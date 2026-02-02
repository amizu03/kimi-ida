use bindgen::EnumVariation;
use std::{env, path::Path};

fn main() {
    let idasdk = env::var("IDASDK").unwrap_or_else(|_| {
        "./ida-sdk".to_string()  // Relative to project root
    });
    
    let include_path = format!("{}/src/include", idasdk);
    println!("cargo:rerun-if-changed={}", include_path);

    let bindings_path = Path::new("./bindgen/bindings.rs");

    if bindings_path.exists() {
        return;
    }
    
    // Check if files exist first
    let pro_h = format!("{}/pro.h", include_path);
    if !std::path::Path::new(&pro_h).exists() {
        panic!("IDA SDK not found at {}. Set IDASDK environment variable.", idasdk);
    }

    let bindings = bindgen::Builder::default()
        .header(format!("{}/pro.h", include_path))
        .header(format!("{}/ida.hpp", include_path))
        .header(format!("{}/idp.hpp", include_path))
        .header(format!("{}/kernwin.hpp", include_path))
        .header(format!("{}/lines.hpp", include_path))
        .header(format!("{}/xref.hpp", include_path))
        .header(format!("{}/funcs.hpp", include_path))
        .header(format!("{}/name.hpp", include_path))
        .header(format!("{}/bytes.hpp", include_path))
        .header(format!("{}/ua.hpp", include_path))
        // Parse as C++17
        .clang_arg("--target=x86_64-pc-windows-msvc")
        .clang_arg("-x")
        .clang_arg("c++")
        .clang_arg("-std=c++17")
        // IDA specific defines
        .clang_arg("-D__IDP__")
        .clang_arg("-D__EA64__")  // For 64-bit EA (IDA 9.0+)
        .clang_arg("-D__NT__")    // Windows
        .clang_arg("-D__X64__")   // x64 architecture
        // Include directories
        .clang_arg(format!("-I{}", include_path))
        // MSVC compatibility
        .clang_arg("-fms-extensions")
        .clang_arg("-fms-compatibility")
        .clang_arg("-fdelayed-template-parsing")
        //.clang_arg("-fkeep-inline-functions")
        // Explicitly enable instruction sets that provide the builtins
        //.clang_arg("-msse")
        //.clang_arg("-msse2")
        //.clang_arg("-mavx")
        //.clang_arg("-mavx2")
        //.clang_arg("-mfma")
        // Block problematic STL types that bindgen can't handle
        .blocklist_type("std::.*")
        .blocklist_type("qlist")
        .blocklist_type(".*iterator.*")
        .blocklist_function("xrefblk_t_next_from1")
        .blocklist_function("xrefblk_t_next_to1")
        // Allowlist only what we need (reduces errors)
        .allowlist_type("plugin_t")
        .allowlist_type("ui_notification_t")
        .allowlist_type("func_t")
        .allowlist_type("ea_t")
        .allowlist_type("qstring")
        .allowlist_type("mbox_kind_t")
        .allowlist_type("xrefblk_t")
        .allowlist_type("cref_t")
        .allowlist_type("dref_t")
        .allowlist_type("action_handler_t")
        .allowlist_type("action_desc_t")
        .allowlist_type("tinfo_t")
        .allowlist_type("udm_t")
        .allowlist_type("hexcall_t")
        .allowlist_type("flags64_t")
        .allowlist_type("optype_t")
        .allowlist_type("uval_t")
        .allowlist_type("mba_ranges_t")
        .allowlist_type("hexrays_failure_t")
        .allowlist_function("get_func")
        .allowlist_function("get_func_qty")
        .allowlist_function("getn_func")
        .allowlist_function("get_next_func")
        .allowlist_function("get_prev_func")
        .allowlist_function("get_func_by_idx")
        .allowlist_function("get_func_name")
        .allowlist_function("get_ea_name")
        .allowlist_function("xrefblk_t_first_from")
        .allowlist_function("xrefblk_t_next_from")
        .allowlist_function("xrefblk_t_first_to")
        .allowlist_function("xrefblk_t_next_to")
        .allowlist_function("set_func_cmt")
        .allowlist_function("calc_func_size")
        .allowlist_function("hook_to_notification_point")
        .allowlist_function("unhook_from_notification_point")
        .allowlist_function("get_func_cmt")
        .allowlist_function("get_cmt")
        .allowlist_function("print_tinfo")
        .allowlist_function("dstr_tinfo")
        .allowlist_function("get_type")
        .allowlist_function("get_tinfo")
        .allowlist_function("is_uname")
        .allowlist_function("get_item_end")
        .allowlist_function("prev_not_tail")
        .allowlist_function("get_named_type_tid")
        .allowlist_function("get_tid_name")
        .allowlist_function("find_tinfo_udt_member")
        .allowlist_function("get_type_by_tid")
        .allowlist_function("get_tinfo_tid")
        .allowlist_function("get_tinfo_size")
        .allowlist_function("get_flags")
        .allowlist_function("get_flags_ex")
        .allowlist_function("get_opinfo")
        .allowlist_function("tag_remove")
        .allowlist_function("decompile")
        .allowlist_function("decompile_func")
        .allowlist_function("decompile_snippet")
        .allowlist_function("get_hexdsp")
        .allowlist_var("o_void")
        .allowlist_var("o_reg")
        .allowlist_var("o_mem")
        .allowlist_var("o_phrase")
        .allowlist_var("o_displ")
        .allowlist_var("o_imm")
        .allowlist_var("o_far")
        .allowlist_var("o_near")
        // Generate
        .use_core()
        .generate_inline_functions(true)
        .default_enum_style(EnumVariation::Rust { non_exhaustive: true })
        .c_naming(false)
        .derive_default(true)
        .derive_debug(true)
        .derive_partialeq(true)
        .generate()
        .expect("Unable to generate bindings");

    let _ = std::fs::create_dir("./bindgen/");

    bindings
        .write_to_file("bindgen/bindings.rs")
        .expect("Couldn't write bindings");
    
    // Link to IDA SDK libs
    println!("cargo:rustc-link-lib=ida");
}