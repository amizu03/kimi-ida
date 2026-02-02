// Analysis functions for gathering data references and function information

use serde_json::{Value, json};

use crate::context::{AnalyzedFunction, Context, DataXRef, FunctionCall, PseudocodeLocation, StructFieldXRef};
use crate::ctree_visitor::{cfunc_t, cinsn_t};
use crate::{ctree_visitor, prelude::*};
use crate::{println, dbg};
use std::collections::HashSet;

unsafe extern "system" fn visit_insn(a1: &mut CTreeVisitor, insn: &mut cinsn_t) -> i32 {
    let ea = insn.item.ea;
    let mut s = qstring::default();

    let mut v = Vec::from_raw_parts(a1.extra_context.as_mut_ptr(), a1.extra_context.len(), a1.extra_context.len());

    if ea != BADADDR && insn.print1(&mut s, None).is_some() {
        let s = s.to_string();
        
        let cstr = std::ffi::CString::new(s).unwrap_or_default();
        let mut buf = qstring::default();
        
        // Call IDA's tag_remove function with init_level=0
        // This removes SCOLOR_ON/OFF sequences but may leave SCOLOR_ADDR
        if tag_remove(&mut buf, cstr.as_ptr(), 0) != -1 {
            let ctx = Context::get();

            v.push(PseudocodeLocation { ea, code: buf.to_string() });
        }
    }

    a1.extra_context = Vec::leak(v);

    0
}

/// Collects pseudocode locations for a given function
pub fn collect_pseudocode_locations<'a>(ea: ea_t) -> Option<(&'a mut cfunc_t, Vec<PseudocodeLocation>)> {
    // Get decompiled pseudocode
    let cfunc = decompile(ea, 0)?;

    let mut pseudocode_locations = Vec::<PseudocodeLocation>::new();
        
    let mut visitor = CTreeVisitor::new(CV_FAST as _);
    visitor.vtable.visit_insn = visit_insn;
    visitor.extra_context = Vec::leak(pseudocode_locations);
    visitor.apply_to(&cfunc.body, 0)?;

    let mut v = unsafe { Vec::from_raw_parts(visitor.extra_context.as_mut_ptr(), visitor.extra_context.len(), visitor.extra_context.len()) };

    // remove duplicate entries (there can be multiple occurences
    // of same pseudocode locations due to circular points of function tree
    // prefer the longer blocks of code over short snippets
    v.dedup_by(|a, b| a.ea == b.ea && a.code.len() <= b.code.len());

    Some((cfunc, v))
}

/// Xref type constants from ida.hpp
const FL_CF: u8 = 16;  // Call Far
const FL_CN: u8 = 17;  // Call Near

pub fn count_calls_with_decode(func_ea: ea_t) -> Option<usize> {
    unsafe {
        let func = get_function_at(func_ea)?;
        let mut count = 0;
        let mut ea = func.start_ea();
        let end_ea= func.end_ea();
        
        while ea < end_ea {
            let mut insn = std::mem::zeroed::<cinsn_t>();
            let size = decode_insn(&mut insn, ea);
            if size == 0 { return None; }
            
            match insn.item.op {
                57 => count += 1,
                _ => {}
            }

            ea += size as u64;
        }

        Some(count)
    }
}

/// Get the next head (instruction or data) address
/// 
/// # Safety
/// Uses IDA's next_head API
unsafe fn next_head(ea: ea_t, max_ea: ea_t) -> ea_t {
    // next_head is typically available via callui or as an exported function
    // This is a simplified version - in practice you'd bind to IDA's API
    let item_size = get_item_size(ea);
    ea + item_size as ea_t
}

/// Gather all comments from a function/EA
pub fn get_all_comments(ea: ea_t) -> Option<String> {
    unsafe {
        let mut cmt = qstring::default();
        let mut rcmt = qstring::default();

        if get_cmt(&mut cmt, ea, false) == -1 {
            return None;
        }
        
        if get_cmt(&mut rcmt, ea, true) == -1 {
            return Some(cmt.to_string());
        }

        Some(format!("{} - {}", cmt.as_ref(), rcmt.as_ref()))
    }
}

/// Gather unique data references in a given function
/// Returns a list of unique data reference descriptions or empty list if none found
pub fn collect_data_references(function_ea: ea_t) -> Option<(Vec<StructFieldXRef>, Vec<DataXRef>)> {
    // Get the function object
    let func = get_function_at(function_ea)?;

    let mut struct_field_xrefs: Vec<StructFieldXRef> = Vec::new();
    let mut data_xrefs: Vec<DataXRef> = Vec::new();
    let func_start = func.start_ea();
    let func_end = func.end_ea();
    
    // Iterate through the function
    let mut current_ea = func_start;
    while current_ea < func_end {
        // Get data xrefs from current address
        let xrefs = get_data_xrefs_from(current_ea);
        
        for xref in xrefs {
            let xref_ea = xref.to;
            
            // Get name at target  
            let name = get_name_at(xref_ea).unwrap_or_default();
            let full_flags = get_full_flags(xref_ea);

            // ignore no flag targets - skip addresses to local type/struct
            if full_flags == 0 {
                println!("Skipping 0x{xref_ea:X} due to no flags");
                continue;
            }

            // ignore offsets or invalid xrefs (immediates)
            let op_type = get_operand_type(current_ea, 0);
            if op_type == o_displ || op_type == o_imm {
                println!("Skipping 0x{xref_ea:X} due to operand type");
                continue;
            }

            // Skip default names
            if !is_user_name(&name) && !name.is_empty() {
                println!("Skipping 0x{xref_ea:X} due to default name");
                continue;
            }

            // get regular and repeatable comments at EA
            let comment = get_all_comments(xref_ea).unwrap_or_default();

            // check if a given address is a tail - a part of a larger data object
            // like a struct or array
            if is_tail(full_flags) {
                let head_ea = get_item_head(xref_ea);

                // check if the head is a structure - get info from it
                if is_struct(full_flags) {
                    let instance_name = get_name_at(xref_ea)?;
                    let name: String = get_type(head_ea)?.try_into().ok()?;

                    if let Some(id) = get_struc_id(&name) {
                        let member_offset = xref_ea - head_ea;
                        let member_id = get_member_id(&name, member_offset)?;
                        let member_name = get_member_name(&name, member_offset).unwrap_or(String::from("undefined"));
                        let member_size = get_member_size(&name, member_offset).unwrap_or(0);
                        let member_cmt = get_member_cmt(&name, member_offset, false).map(|s| s.to_string()).unwrap_or_default() + &get_member_cmt(&name, member_offset, true).unwrap_or_default();

                        struct_field_xrefs.push(
                            StructFieldXRef {
                                data: DataXRef {
                                    ea: xref_ea,
                                    name: member_name, comment: if member_cmt.is_empty() { None } else { Some(member_cmt) },
                                    data_offset: 0,
                                },
                                instance_name,
                                type_name: name,
                            }
                        );
                    }
                }
                // not a struct - get head name and comment if it exists
                else {
                    let head_name = get_name_at(head_ea).unwrap_or_default();
                    let head_comment = get_all_comments(head_ea).unwrap_or_default();
                    let data_offset = xref_ea - head_ea;

                    data_xrefs.push(DataXRef {
                        ea: xref_ea,
                        name: head_name,
                        comment: if head_comment.is_empty() { None } else { Some(head_comment) },
                        data_offset: data_offset as _,
                    });
                }
            }
            else {
                data_xrefs.push(DataXRef {
                    ea: xref_ea,
                    name,
                    comment: if comment.is_empty() { None } else { Some(comment) },
                    data_offset: 0,
                });
            }
        }
        
        // Move to next instruction/item (NOT +1 which could land in middle of instruction)
        current_ea = item_end(current_ea);
    }

    // Remove duplicates and return
    Some((struct_field_xrefs, data_xrefs))
}

pub fn analyze(func: &func_t) -> Result<AnalyzedFunction, &'static str> {
    let ea = func.start_ea();

    println!("Reversing {} @ 0x{ea:X}", func.name());

    //println!("Searching data references");

    let Some((struct_field_xrefs, data_xrefs)) = collect_data_references(ea) else {
        return Err("Failed to collect data references");
    };

    //println!("Pinning pseudocode locations");
    
    // NOTE: Pseudocode collection is optional. If Hex-Rays decompilation fails
    // due to struct layout issues, we continue with disassembly-only analysis.
    let Some((cfunc, locs)) = collect_pseudocode_locations(ea) else {
        return Err("Failed to collect pseudocode locations");
    };

    let Some(pseudocode) = get_pseudocode(cfunc) else {
        return Err("Failed to get pseudocode");
    };

    let Some(num_calls) = count_calls_with_decode(ea) else {
        return Err("Failed to count calls");
    };

    //println!("Done initial analysis");

    // in block so we don't hold the mutex too long or while a prompt is being responded to
    let prompt = {
        let mut ctx = Context::get();
        let f = ctx.slot(ea);

        f.name = func.name();
        f.ea = ea;
        f.data_xrefs = data_xrefs;
        f.struct_field_xrefs = struct_field_xrefs;
        f.psedocode_locations = locs;
        f.comment = get_all_comments(ea);
        f.num_calls = num_calls;

        f.called_from = get_code_xrefs_to(ea).iter().flat_map(|call| {
            let mut name = qstring::default();
            if unsafe { get_func_name(&mut name, call.from) } == -1 {
                None
            }
            else {
                let name = name.to_string();
                Some(FunctionCall { ea: call.from, name })
            }
        }).collect();

        f.pseudocode.clear();

        // clean up pseudocode
        for line in pseudocode {
            let mut line = line;
            line.push('\0');

            let mut buf = qstring::default();

            // Call IDA's tag_remove function with init_level=0
            // This removes SCOLOR_ON/OFF sequences but may leave SCOLOR_ADDR
            if unsafe { tag_remove(&mut buf, line.as_ptr() as _, 0) } != -1 {
                f.pseudocode.push_str(&format!("{}\n", buf.as_ref()));
            }
        }

        let Ok(prompt) = serde_json::to_string(f) else {
            return Err("Failed to serialize prompt");
        };

        prompt
    };

    //println!("Doing AI analysis");

    const SYSTEM_PROMPT: &str = r#"You are a reverse engineering assistant.
    Your task is to first analyze what the function does, reverse engineering its behaviour.
    Rename variables in the pseudocode accordingly.
    Write helpful comments that can point out non-obvious information about of the code.
    I will provide the input in JSON format, which contains the original pseudocode, a list of functions that call the target, local variables/fields list, and markers containing parts of the pseudocode which you will write helpful comments about.
    The ONLY outputs should be in the format provided below in JSON, the output values go in the "<>":
    
    { "name": "<FUNCTION_NAME>", "comment": "<COMMENT>", "variables": [ { "original_name": "<ORIGINAL_NAME>", "new_name": "<NEW_NAME>" } ], "comments": [ { "address": <ADDRESS>, "comment": "<COMMENT_ABOUT_CODE>" } ] }"#;

    let messages = json!([{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": prompt}]);
    let Some(response) = Kimi::get().chat(messages, "kimi-for-coding", 0.1, None, true) else {
        return Err("Failed to send prompt");
    };

    if let Some(r) = response.get("choices")
        .and_then(|x| x.as_array())
        .and_then(|x| x.get(0))
        .and_then(|x| x.get("message"))
        .and_then(|x| x.get("content"))
        .and_then(|x| x.as_str()) {
        let mut content = r.trim();

        // check if response was accidentally in markdown format
        if let Some(json_markdown_start) = content.find("```json") {
            content = content[json_markdown_start+"```json".len()..].trim();

            // markdown tags must end somewhere
            if let Some(json_markdown_end) = content.find("```") {
                content = content[..json_markdown_end].trim();
            }
            else {
                return Err("Failed to parse response JSON markdown");
            }
        }

        let analyzed_f = serde_json::from_str::<AnalyzedFunction>(content).or(Err("Failed to parse AnalyzedFunction"))?;
        
        Ok(analyzed_f)
    }
    else {
        return Err("Failed to parse response JSON");
    }
}