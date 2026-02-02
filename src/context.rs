use std::ffi::CString;

use crate::prelude::*;
use crate::{println, dbg};

fn serialize_ea<S>(x: &ea_t, s: S) -> Result<S::Ok, S::Error>
where S: Serializer
{
    s.serialize_str(&format!("0x{x:X}"))
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct StructFieldXRef {
    pub data: DataXRef,
    pub instance_name: String,
    pub type_name: String,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct DataXRef {
    #[serde(rename = "address", serialize_with = "serialize_ea")]
    pub ea: ea_t,
    pub name: String,
    pub comment: Option<String>,
    pub data_offset: usize,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct PseudocodeLocation {
    #[serde(rename = "address")]
    pub ea: ea_t,
    pub code: String,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct FunctionCall {
    // dont serialize this, we don't care about where the call came from
    // we will still retain this data in an effort to gather more information for better prompts
    #[serde(skip)]
    pub ea: ea_t,
    // set this after analysis has more functions
    // this is here just to give more info
    pub name: String,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct AnalyzedVariable {
    pub original_name: String,
    pub new_name: String,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct AnalyzedComment {
    #[serde(rename = "address", serialize_with = "serialize_ea")]
    pub ea: ea_t,
    pub comment: String,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct AnalyzedFunction {
    pub name: String,
    pub comment: String,
    pub variables: Vec<AnalyzedVariable>,
    pub comments: Vec<AnalyzedComment>,
}

impl AnalyzedFunction {
    pub fn apply(&self, ea: ea_t) -> Option<()> {
        let func = get_function_at(ea)?;
        let func_start = func.start_ea();
        let func_end = func.end_ea();

        // set fn name - set_name makes a copy, so CString only needs to live for the call
        let cstr = CString::new(if self.name.starts_with("sub_") {String::from("thunk")} else {self.name.clone()}).ok()?;
    
        if !unsafe { set_name(ea, cstr.as_ptr(), SN_FORCE) } {
            return None;
        }
        
        // set fn header/big comment at top - set_func_cmt makes a copy
        let new_comment = CString::new(textwrap::wrap(&self.comment, 80).join("\n")).ok()?;
        unsafe {
            set_func_cmt(func, new_comment.as_ptr() as _, false);
        }

        // set variable names first (before decompilation)
        for v in &self.variables {
            let _ = rename_lvar(ea, &v.original_name, &v.new_name);
            //println!("{} => {}", v.original_name, v.new_name);
        }
        
        // Apply disassembly comments (these are safe and reliable)
        let mut comment_count = 0;
        for c in &self.comments {
            // Skip comments outside function bounds - they might be bogus from AI
            if c.ea < func_start || c.ea >= func_end {
                println!("Skipping comment at 0x{:X} - outside function bounds (0x{:X} - 0x{:X})", 
                         c.ea, func_start, func_end);
                continue;
            }
            
            // Set disassembly comment (IDA copies the string immediately)
            if let Ok(cmt) = CString::new(c.comment.clone()) {
                unsafe {
                    if set_cmt(c.ea, cmt.as_ptr(), false) {
                        comment_count += 1;
                    }
                }
            }
        }
        
        // NOTE: Hex-Rays decompilation is DISABLED due to struct layout mismatches
        // causing "invalid parameter" errors and crashes.
        // Only disassembly comments are applied for safety.
        // 
        // To re-enable pseudocode comments, the following struct layouts must match
        // the Hex-Rays SDK exactly:
        // - mba_ranges_t (currently has qvector<[ea_t; 2]> which may be wrong)
        // - hexrays_failure_t (currently has code, errea, str)
        // - cfunc_t (partially verified but may have issues)
        if let Some(cfunc) = decompile(ea, 0) {
            for c in &self.comments {
                if c.ea < func_start || c.ea >= func_end {
                    println!("Skipping comment at 0x{:X} - outside function bounds (0x{:X} - 0x{:X})", 
                         c.ea, func_start, func_end);
                    continue;
                }

                let mut tl = TreeLoc::default();

                tl.ea = c.ea;
                tl.itp = ITP_BLOCK1;

                let _ = cfunc.set_user_cmt(&tl, &c.comment);
            }
            
            let _ = cfunc.save_user_cmts();
            let _ = cfunc.refresh_func_ctext();
        }

        println!("Successfully applied analyzed function @ 0x{ea:X}");

        Some(())
    }
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct Function {
    #[serde(rename = "address")]
    pub ea: ea_t,
    pub name: String,
    pub comment: Option<String>,
    pub pseudocode: String,
    pub data_xrefs: Vec<DataXRef>,
    pub struct_field_xrefs: Vec<StructFieldXRef>,
    pub psedocode_locations: Vec<PseudocodeLocation>,
    pub called_from: Vec<FunctionCall>,
    // not that important, more useful for sorting
    #[serde(skip)]
    pub num_calls: usize,
}

pub struct Context {
    pub functions: Vec<Function>,
}

static mut CTX: Option<Mutex<Context>> = None;

impl Context {
    pub fn slot(&mut self, ea: ea_t) -> &mut Function {
        match self.functions.binary_search_by(|x| x.ea.cmp(&ea)) {
            Ok(i) => &mut self.functions[i],
            Err(i) => {
                let f = self.functions.insert_mut(i, Function::default());
                f.ea = ea;
                f
            },
        }
    }

    pub fn init() {
        unsafe {
            core::mem::forget(CTX.take());

            CTX = Some(Mutex::new(Self {
                functions: Vec::new(),
            }));
        }
    }

    pub fn get<'a>() -> MutexGuard<'a, Context> {
        unsafe {
            CTX.as_mut().unwrap_unchecked().lock()
        }
    }
}