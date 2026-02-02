// Pure Rust action implementation - no C++ wrapper required
// Uses IDA's simpler menu APIs instead of action_handler_t

use crate::{PLUGIN, analysis::{analyze, collect_data_references, collect_pseudocode_locations, count_calls_with_decode, get_all_comments}, context::{AnalyzedFunction, Context, Function}, prelude::*};
use std::{ffi::{CString, VaList, c_char, c_void}, mem::{transmute, transmute_copy}, ptr::null_mut, sync::atomic::{AtomicBool, AtomicUsize, Ordering}, thread::sleep, time::Duration};
use crate::{println, dbg};

// Menu item callback type
pub type MenuCallback = unsafe extern "C" fn(user_data: *mut c_void);

static mut ACTION_HANDLER_VTABLE: [usize; 3] = [0; 3];
static mut ACTION_HANDLER: action_handler_t = unsafe { core::mem::zeroed() };
static mut ACTION_HANDLER_ALL_VTABLE: [usize; 3] = [0; 3];
static mut ACTION_HANDLER_ALL: action_handler_t = unsafe { core::mem::zeroed() };

extern "C" fn action_activate(handler: &mut action_handler_t, ctx: &mut action_activation_ctx_t) -> i32 {
    let ea = get_screen_ea();

    std::thread::spawn(move || {
        if let Some(func) = get_function_at(ea) {
            match analyze(func) {
                Ok(x) => {
                    extern "C" fn execute(req: &mut ExecRequest) -> isize {
                        let mut data = unsafe { Box::<(AnalyzedFunction, ea_t)>::from_raw(req.extra_data as _) };

                        if data.0.apply(data.1).is_none() {
                            println!("Failed to apply analysis at 0x{:X}", data.1);
                        }

                        0
                    }

                    extern "C" fn destructor(req: &mut ExecRequest) {
                        unsafe {
                            qsem_free(req.sem);
                        }

                        req.sem = 0;
                        req.code = 0;
                    }

                    let mut req = ExecRequest {
                        vtable: &ExecRequestVtable { execute, destructor },
                        code: 0,
                        sem: 0,
                        extra_data: Box::leak(Box::new((x, ea))) as *mut _ as usize,
                    };

                    req.execute_sync(MFF_MAGIC | MFF_WRITE);
                },
                Err(e) => println!("Analysis failed with: {e}"),
            }
        }
        else {
            println!("No func at 0x{:X}", ea);
        }
    });

    1
}

extern "C" fn action_update(handler: &mut action_handler_t, ctx: &mut action_update_ctx_t) -> action_state_t {
    // Enable only in pseudocode view
    if ctx.widget_type == BWN_PSEUDOCODE || ctx.widget_type == BWN_DISASM {
        action_state_t::AST_ENABLE_FOR_WIDGET
    }
    else {
        action_state_t::AST_DISABLE_FOR_WIDGET
    }
}

extern "C" fn action_destructor(handler: &mut action_handler_t) {

}

extern "C" fn action_all_activate(handler: &mut action_handler_t, ctx: &mut action_activation_ctx_t) -> i32 {
    println!("FULL Auto-reversal");

    static IN_ALL_REVERSAL: AtomicBool = AtomicBool::new(false);
    static ACTIVE_ANALYSIS_COUNT: AtomicUsize = AtomicUsize::new(0);

    if IN_ALL_REVERSAL.compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed).is_err() {
        println!("Already doing FULL analysis");
        return 1;
    }

    std::thread::spawn(move || {
        // Collect function addresses first (addresses are Send + Sync)
        let mut func_eas: Vec<(ea_t, ea_t)> = FunctionIter::new()
            .map(|f| (f.start_ea(), f.size()))
            .collect();

        // sort functions by size so we start with smaller functions first
        // this way we will have more information in the end when we
        // go for the bigger functions
        // smallest functions are usually thunks/utility functions which may proide extra info
        func_eas.sort_by_key(|f| f.1);

        for (ea, size) in func_eas {
            // maximum number of concurrent requests reached,
            // wait for new slot to open
            while ACTIVE_ANALYSIS_COUNT.load(Ordering::Relaxed) >= 9 {
                sleep(Duration::from_millis(250));
            }

            ACTIVE_ANALYSIS_COUNT.fetch_add(1, Ordering::Relaxed);

            std::thread::spawn(move || {
                if let Some(func) = get_function_at(ea) {
                    if !func.name().starts_with("sub_") {
                        ACTIVE_ANALYSIS_COUNT.fetch_sub(1, Ordering::Relaxed);
                        return;
                    }

                    match analyze(func) {
                        Ok(result) => {
                            extern "C" fn execute(req: &mut ExecRequest) -> isize {
                                let mut data = unsafe { Box::<(AnalyzedFunction, ea_t)>::from_raw(req.extra_data as _) };

                                if data.0.apply(data.1).is_none() {
                                    println!("Failed to apply analysis at 0x{:X}", data.1);
                                }

                                0
                            }

                            extern "C" fn destructor(req: &mut ExecRequest) {
                                unsafe {
                                    qsem_free(req.sem);
                                }

                                req.sem = 0;
                                req.code = 0;
                            }

                            let mut req = ExecRequest {
                                vtable: &ExecRequestVtable { execute, destructor },
                                code: 0,
                                sem: 0,
                                extra_data: Box::leak(Box::new((result, ea))) as *mut _ as usize,
                            };

                            req.execute_sync(MFF_MAGIC | MFF_WRITE);

                            ACTIVE_ANALYSIS_COUNT.fetch_sub(1, Ordering::Relaxed);
                        },
                        Err(e) => {
                            println!("Analysis failed with: {e}");

                            ACTIVE_ANALYSIS_COUNT.fetch_sub(1, Ordering::Relaxed);
                        },
                    }
                }
            });
        }

        IN_ALL_REVERSAL.store(false, Ordering::Relaxed);
    });

    1
}

extern "C" fn action_all_update(handler: &mut action_handler_t, ctx: &mut action_update_ctx_t) -> action_state_t {
    // Enable only in pseudocode view
    if ctx.widget_type == BWN_PSEUDOCODE || ctx.widget_type == BWN_DISASM {
        action_state_t::AST_ENABLE_FOR_WIDGET
    }
    else {
        action_state_t::AST_DISABLE_FOR_WIDGET
    }
}

extern "C" fn action_all_destructor(handler: &mut action_handler_t) {

}

extern "C" fn ui_hook(ctx: usize, code: ui_notification_t, mut va_list: VaList) -> isize {
    match code {
        ui_notification_t::ui_populating_widget_popup => {
            let widget = unsafe { va_list.arg::<*const ()>() };
            let popup_menu = unsafe { va_list.arg::<*const ()>() };

            if widget.is_null() || popup_menu.is_null() {
                return 0;
            }

            let widget_type = get_widget_type(widget);

            if widget_type != BWN_PSEUDOCODE && widget_type != BWN_DISASM {
                return 0;
            }

            if !attach_action_to_popup(widget, popup_menu, c"kimi:analyze".as_ptr(), c"".as_ptr(), SETMENU_INS)
                || !attach_action_to_popup(widget, popup_menu, c"kimi:analyze_all".as_ptr(), c"".as_ptr(), SETMENU_INS) {
                return -1;
            }

            0
        }
        _ => 0,
    }
}

static mut ANALYZE_FN_ACTION: action_desc_t = action_desc_t {
    cb: size_of::<action_desc_t>() as _,
    name: c"kimi:analyze".as_ptr(),
    label: c"KIMI: Analyze function".as_ptr(),
    handler: &raw mut ACTION_HANDLER,
    owner: null_mut(),
    shortcut: c"Ctrl+Shift+K".as_ptr(),
    tooltip: c"Analyze current function".as_ptr(),
    icon: 199,
    flags: 0,
};

static mut ANALYZE_ALL_FN_ACTION: action_desc_t = action_desc_t {
    cb: size_of::<action_desc_t>() as _,
    name: c"kimi:analyze_all".as_ptr(),
    label: c"KIMI: Analyze all functions".as_ptr(),
    handler: &raw mut ACTION_HANDLER_ALL,
    owner: null_mut(),
    shortcut: c"".as_ptr(),
    tooltip: c"Analyze all functions".as_ptr(),
    icon: 199,
    flags: 0,
};

/// Initialize actions - call this in ida_init
pub fn init_actions() {
    unsafe {
        ACTION_HANDLER_VTABLE[0] = action_activate as usize;
        ACTION_HANDLER_VTABLE[1] = action_update as usize;
        ACTION_HANDLER_VTABLE[2] = action_destructor as usize;

        ACTION_HANDLER.flags = 1; // AHF_VERSION
        ACTION_HANDLER.vtable_ = &raw const ACTION_HANDLER_VTABLE as *const _ as _;

        ACTION_HANDLER_ALL_VTABLE[0] = action_all_activate as usize;
        ACTION_HANDLER_ALL_VTABLE[1] = action_all_update as usize;
        ACTION_HANDLER_ALL_VTABLE[2] = action_all_destructor as usize;

        ACTION_HANDLER_ALL.flags = 1; // AHF_VERSION
        ACTION_HANDLER_ALL.vtable_ = &raw const ACTION_HANDLER_ALL_VTABLE as *const _ as _;
    }

    // Register "Analyze Function" action
    unsafe {
        ANALYZE_FN_ACTION.register();
        ANALYZE_ALL_FN_ACTION.register();
    }

    unsafe {
        hook_to_notification_point(hook_type_t::HT_UI, Some(transmute(ui_hook as usize)), null_mut());
    }

    println!("Actions module initialized");
    println!("Tip: Right-click in pseudocode window to see KIMI actions");
}

/// Cleanup actions
pub fn cleanup_actions() {
    unsafe {
        ANALYZE_FN_ACTION.unregister();
        ANALYZE_ALL_FN_ACTION.unregister();
    }

    unsafe {
        unhook_from_notification_point(hook_type_t::HT_UI, Some(transmute(ui_hook as usize)), null_mut());
    }

    println!("Actions cleaned up");
}
