#![allow(non_camel_case_types, dead_code, unused, warnings, static_mut_refs)]
#![feature(c_variadic, str_from_raw_parts, push_mut)]
#![no_main]

mod context;
mod prelude;
mod kimi;
mod ida;
mod actions;
mod analysis;
mod strvec;
mod ctree_visitor;

use std::process::exit;
use std::{panic, ptr::null_mut};
use std::ffi::c_void;
use crate::{context::Context, prelude::*};

// IDA calls this when loading plugin
#[unsafe(no_mangle)]
extern "C" fn ida_init() -> i32 {
    panic::set_hook(Box::new(|info| {
        let panic_msg = if let Some(location) = info.location() {
            format!("Panic occurred at file '{}' line {}", location.file(), location.line())
        } else {
            "Panic occurred but no location info available".to_owned()
        };

        println!("{panic_msg}");
        error_box(&panic_msg);

        exit(1);
    }));

    let result = std::panic::catch_unwind(|| {
        Context::init();
        Kimi::init(std::env::var("KIMI_API_KEY").expect("Failed to find KIMI_API_KEY env var"));
        
        actions::init_actions();
        
        println!("KIMI-IDA plugin loaded successfully");
        println!("Press Ctrl-Shift-K to open the action menu");
    });
    
    2
}

// IDA calls this when user activates plugin (Edit > Plugins > YourName)
// Or when pressing the hotkey (Alt-K by default)
#[unsafe(no_mangle)]
extern "C" fn ida_run(_: i32) {
    let _ = std::panic::catch_unwind(|| {
        
    });
}

// IDA calls this when unloading
#[unsafe(no_mangle)]
extern "C" fn ida_term() {
    let _ = std::panic::catch_unwind(|| {
        actions::cleanup_actions();
        println!("Unloaded");
    });
}

#[repr(C)]
pub struct Plugin {
    pub version: u32,
    pub flags: u32,
    pub init: Option<extern "C" fn() -> i32>,
    pub term: Option<extern "C" fn()>,
    pub run: Option<extern "C" fn(arg: i32)>,
    pub comment: *const i8,
    pub help: *const i8,
    pub wanted_name: *const i8,
    pub wanted_hotkey: *const i8,
}

unsafe impl Send for Plugin {}
unsafe impl Sync for Plugin {}

#[used]
#[unsafe(no_mangle)]
pub static PLUGIN: Plugin = Plugin {
    version: IDA_SDK_VERSION,
    flags: 0x0,
    init: Some(ida_init),
    term: Some(ida_term),
    run: Some(ida_run),
    comment: c"KIMI Agent for IDA Pro".as_ptr(),
    help: c"Press Ctrl-Shift-K for AI-powered analysis menu".as_ptr(),
    wanted_name: c"kimi-ida".as_ptr(),
    wanted_hotkey: null_mut(),
    //wanted_hotkey: c"Ctrl-Shift-K".as_ptr(),
};
