// Include bindgen output
#![allow(non_camel_case_types)]

use std::{ffi::{CStr, CString, c_char, c_void}, ptr::null_mut, rc, sync::OnceLock};

use crate::{context::PseudocodeLocation, ctree_visitor::{cfunc_t, cinsn_t}, strvec::strvec_t};

include!("../bindgen/bindings.rs");

// IDA_VERSION (9.2)
pub const IDA_SDK_VERSION: u32 = 0x384;

// BADADDR constant (usually 0xFFFFFFFFFFFFFFFF for 64-bit)
pub const BADADDR: u64 = u64::MAX;
pub const BADSIZE: isize = isize::from_ne_bytes(u64::MAX.to_ne_bytes());

// Color constants from pro.h/kernwin.hpp
pub const DEFCOLOR: u32 = u32::MAX;  // Default color (bgcolor_t(-1))

// Flag constants from bytes.hpp
const GFE_VALUE: i32 = 0x0001;  // get flags with FF_IVL & MS_VAL
const MS_CLS: u64 = 0x00000600; // Mask for typing
const FF_TAIL: u64 = 0x00000200; // Tail
const FF_DATA: u64 = 0x00000400; // Data
const FF_STRUCT: u64 = 0x60000000; // struct variable
const DT_TYPE: u64 = 0xF0000000; // Mask for DATA typing

// XREF flags
pub const XREF_FLOW: i32 = 0x00;
pub const XREF_NOFLOW: i32 = 0x01;
pub const XREF_DATA: i32 = 0x02;
pub const XREF_CODE: i32 = 0x04;
pub const XREF_EA: i32 = 0x08;

pub const BWN_EXPORTS: i32 = 0;
pub const BWN_IMPORTS: i32 = 1;
pub const BWN_NAMES: i32 = 2;
pub const BWN_FUNCS: i32 = 3;
pub const BWN_STRINGS: i32 = 4;
pub const BWN_SEGS: i32 = 5;
pub const BWN_DISASM: i32 = 27;
pub const BWN_PSEUDOCODE: i32 = 46;
pub const BWN_MICROCODE: i32 = 61;

pub const SETMENU_INS: i32 = 0;

unsafe impl Send for action_desc_t {}
unsafe impl Sync for action_desc_t {}

// callui_t union returned by callui()
#[repr(C)]
#[derive(Copy, Clone)]
pub union callui_t {
    pub b: bool,
    pub i8: i8,
    pub i16: i16,
    pub i32: i32,
    pub u8: u8,
    pub u16: u16,
    pub u32: u32,
    pub pu8: *mut u8,
    pub pvoid: *mut std::ffi::c_void,
    pub isize: isize,
    pub usize: usize,
}

#[link(name = "ida")]
unsafe extern "C" {
    /// Decode instruction at `ea` into `insn`
    /// Returns: insn.size if successful, 0 otherwise
    pub fn decode_insn(insn: *mut cinsn_t, ea: ea_t) -> i32;
    pub fn set_name(ea: ea_t, s: *const i8, flags: i32) -> bool;
    pub fn set_cmt(ea: ea_t, s: *const i8, repeatable: bool) -> bool;
    pub fn qsem_free(sem: usize) -> bool;
}

pub const SN_CHECK: i32 = 0x00; // fail if name contains invalid character
pub const SN_NOCHECK: i32 = 0x01; // replace invalid characters silently with '_'
pub const SN_FORCE: i32 = 0x800; // tries other names by applying a suffix if existing names are used

pub type CalluiFn = unsafe extern "C" fn(ui_notification_t, ...) -> callui_t;

#[link(name = "ida")]
unsafe extern "C" {
    #[link_name = "callui"]
    pub static mut callui: CalluiFn;
    
    // Type printing
    pub fn print_tinfo(
        result: *mut qstring,
        prefix: *const c_char,
        indent: i32,
        cmtindent: i32,
        flags: i32,
        tif: *const tinfo_t,
        name: *const c_char,
        cmt: *const c_char,
    ) -> bool;
    
    // Type ID functions (from typeinf.hpp)
    /// Get named local type TID (idc.get_struc_id equivalent)
    pub fn get_named_type_tid(name: *const c_char) -> tid_t;
    /// Get a type name for the specified TID
    pub fn get_tid_name(out: *mut qstring, tid: tid_t) -> bool;
}

/// Print a message to IDA's message window.
pub fn msg_str(message: *const c_char) {
    unsafe {
        callui(ui_notification_t::ui_msg, message);
    }
}

// ============================================================================
// Message Box Functions
// ============================================================================

/// Display an info message box
pub fn info_box(message: &str) {
    unsafe {
        let c_msg = std::ffi::CString::new(message).unwrap_or_default();
        callui(
            ui_notification_t::ui_mbox,
            mbox_kind_t::mbox_info as i32,
            c_msg.as_ptr(),
        );
    }
}

/// Display a warning message box
pub fn warning_box(message: &str) {
    unsafe {
        let c_msg = std::ffi::CString::new(message).unwrap_or_default();
        callui(
            ui_notification_t::ui_mbox,
            mbox_kind_t::mbox_warning as i32,
            c_msg.as_ptr(),
        );
    }
}

/// Display an error message box
pub fn error_box(message: &str) {
    unsafe {
        let c_msg = std::ffi::CString::new(message).unwrap_or_default();
        callui(
            ui_notification_t::ui_mbox,
            mbox_kind_t::mbox_error as i32,
            c_msg.as_ptr(),
        );
    }
}

/// Display a yes/no question dialog
/// Returns: 1 = Yes, 0 = No, -1 = Cancel/Error
pub fn ask_yn(default_answer: i32, message: &str) -> i32 {
    unsafe {
        let c_msg = std::ffi::CString::new(message).unwrap_or_default();
        let result = callui(
            ui_notification_t::ui_ask_buttons,
            c"Yes".as_ptr(),
            c"No".as_ptr(),
            std::ptr::null::<c_char>(),
            default_answer,
            c_msg.as_ptr(),
        );
        result.i32
    }
}

/// Display a dialog with custom buttons
/// Returns: 0 = Cancel/Error, 1 = Button 1, 2 = Button 2, 3 = Button 3
pub fn ask_buttons(
    btn1: &str,
    btn2: &str,
    btn3: Option<&str>,
    default_answer: i32,
    message: &str,
) -> i32 {
    unsafe {
        let c_btn1 = std::ffi::CString::new(btn1).unwrap_or_default();
        let c_btn2 = std::ffi::CString::new(btn2).unwrap_or_default();
        let c_btn3 = btn3.map(|s| std::ffi::CString::new(s).unwrap_or_default());
        let c_msg = std::ffi::CString::new(message).unwrap_or_default();
        
        let btn3_ptr = c_btn3.as_ref()
            .map(|s| s.as_ptr())
            .unwrap_or(std::ptr::null());
        
        let result = callui(
            ui_notification_t::ui_ask_buttons,
            c_btn1.as_ptr(),
            c_btn2.as_ptr(),
            btn3_ptr,
            default_answer,
            c_msg.as_ptr(),
        );
        result.i32
    }
}

impl AsRef<str> for qstring {
    fn as_ref(&self) -> &str {
        unsafe {
            core::str::from_raw_parts(self.body.array as _, 
                if self.body.n == 0 {
                    0
                } else {
                    self.body.n - 1
                }
            ) 
        }
    }
}

impl ToString for qstring {
    fn to_string(&self) -> String {
        self.as_ref().to_owned()
    }
}

pub trait ActionDescExt {
    fn unregister(self);
    fn register(self);
}

impl ActionDescExt for action_desc_t {
    fn unregister(self) {
        unsafe {
            callui(ui_notification_t::ui_unregister_action, &self);
        }
    }

    fn register(self) {
        unsafe {
            callui(ui_notification_t::ui_register_action, &self);
        }
    }
}

pub fn get_widget_type(widget: *const ()) -> i32 {
    unsafe {
        callui(ui_notification_t::ui_get_widget_type, widget).i32
    }
}

pub fn get_screen_ea() -> ea_t {
    unsafe {
        let mut ea = 0;
        callui(ui_notification_t::ui_screenea, &mut ea);
        ea
    }
}

pub fn attach_action_to_popup(widget: *const (), popup_menu: *const (), name: *const i8, popuppath: *const i8, flags: i32) -> bool {
    unsafe {
        callui(ui_notification_t::ui_attach_action_to_popup, widget, popup_menu, name, popuppath, flags).b
    }
}

// ============================================================================
// Function iteration helpers
// ============================================================================

/// Get the number of functions in the database
pub fn get_function_count() -> usize {
    unsafe { get_func_qty() }
}

/// Get function by index (0..get_function_count()-1)
pub fn get_function_by_idx(idx: usize) -> Option<&'static mut func_t> {
    unsafe {
        let ptr = getn_func(idx);
        if ptr.is_null() {
            None
        } else {
            Some(&mut *ptr)
        }
    }
}

/// Get function at a specific address
pub fn get_function_at(ea: ea_t) -> Option<&'static mut func_t> {
    unsafe {
        get_func(ea).as_mut()
    }
}

/// Get the next function after the given address
pub fn get_next_function(ea: ea_t) -> Option<&'static mut func_t> {
    unsafe {
        get_next_func(ea).as_mut()
    }
}

/// Get the previous function before the given address
pub fn get_prev_function(ea: ea_t) -> Option<&'static mut func_t> {
    unsafe {
        get_prev_func(ea).as_mut()
    }
}

/// Iterator over all functions
pub struct FunctionIter {
    current_idx: usize,
    total: usize,
}

impl FunctionIter {
    pub fn new() -> Self {
        Self {
            current_idx: 0,
            total: get_function_count(),
        }
    }
}

impl Iterator for FunctionIter {
    type Item = &'static mut func_t;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_idx >= self.total {
            return None;
        }

        let func = get_function_by_idx(self.current_idx);
        self.current_idx += 1;

        func
    }
}

/// Extension trait for func_t to provide helper methods
pub trait FuncExt {
    fn start_ea(&self) -> ea_t;
    fn end_ea(&self) -> ea_t;
    fn size(&self) -> u64;
    fn name(&self) -> String;
}

impl FuncExt for func_t {
    fn start_ea(&self) -> ea_t {
        self._base.start_ea
    }
    
    fn end_ea(&self) -> ea_t {
        self._base.end_ea
    }
    
    fn size(&self) -> u64 {
        self._base.end_ea - self._base.start_ea
    }
    
    fn name(&self) -> String {
        unsafe {
            let mut s = qstring::default();
            
            if get_func_name(&mut s, self.start_ea()) == -1 {
                format!("sub_{:X}", self.start_ea())
            }
            else {
                s.to_string()
            }
        }
    }
}

// ============================================================================
// XREF (Cross-Reference) helpers
// ============================================================================

/// Represents a single cross-reference
#[derive(Debug, Clone, Copy)]
pub struct Xref {
    pub from: ea_t,
    pub to: ea_t,
    pub is_code: bool,
    pub xref_type: u8,
    pub is_user: bool,
}

/// Get all xrefs from a given address (outgoing references)
pub fn get_xrefs_from(ea: ea_t, flags: i32) -> Vec<Xref> {
    unsafe {
        let mut xrefs = Vec::new();
        let mut xb = xrefblk_t::default();
        
        if xrefblk_t_first_from(&mut xb, ea, flags) {
            loop {
                xrefs.push(Xref {
                    from: xb.from,
                    to: xb.to,
                    is_code: xb.iscode,
                    xref_type: xb.type_,
                    is_user: xb.user,
                });
                
                if !xrefblk_t_next_from(&mut xb) {
                    break;
                }
            }
        }
        
        xrefs
    }
}

/// Get all xrefs to a given address (incoming references)
pub fn get_xrefs_to(ea: ea_t, flags: i32) -> Vec<Xref> {
    unsafe {
        let mut xrefs = Vec::new();
        let mut xb: xrefblk_t = std::mem::zeroed();
        
        if xrefblk_t_first_to(&mut xb, ea, flags) {
            loop {
                xrefs.push(Xref {
                    from: xb.from,
                    to: xb.to,
                    is_code: xb.iscode,
                    xref_type: xb.type_,
                    is_user: xb.user,
                });
                if !xrefblk_t_next_to(&mut xb) {
                    break;
                }
            }
        }
        
        xrefs
    }
}

/// Get only code xrefs from an address
pub fn get_code_xrefs_from(ea: ea_t) -> Vec<Xref> {
    get_xrefs_from(ea, XREF_CODE)
}

/// Get only code xrefs to an address
pub fn get_code_xrefs_to(ea: ea_t) -> Vec<Xref> {
    get_xrefs_to(ea, XREF_CODE)
}

/// Get only data xrefs from an address
pub fn get_data_xrefs_from(ea: ea_t) -> Vec<Xref> {
    get_xrefs_from(ea, XREF_DATA)
}

/// Get only data xrefs to an address
pub fn get_data_xrefs_to(ea: ea_t) -> Vec<Xref> {
    get_xrefs_to(ea, XREF_DATA)
}

/// Get string representation of xref type
pub fn xref_type_string(xref: &Xref) -> &'static str {
    if xref.is_code {
        match xref.xref_type {
            16 => "Call Far",      // fl_CF
            17 => "Call Near",     // fl_CN
            18 => "Jump Far",      // fl_JF
            19 => "Jump Near",     // fl_JN
            20 => "Flow",          // fl_F
            _ => "Code",
        }
    } else {
        match xref.xref_type {
            0 => "Offset",         // dr_O
            1 => "Write",          // dr_W
            2 => "Read",           // dr_R
            3 => "Text",           // dr_T
            4 => "Info",           // dr_I
            5 => "Enum",           // dr_S
            _ => "Data",
        }
    }
}

/// Iterator for xrefs from an address
pub struct XrefsFromIter {
    xb: xrefblk_t,
    first: bool,
}

impl XrefsFromIter {
    pub fn new(ea: ea_t, flags: i32) -> Option<Self> {
        unsafe {
            let mut xb: xrefblk_t = std::mem::zeroed();
            if xrefblk_t_first_from(&mut xb, ea, flags) {
                Some(Self { xb, first: true })
            } else {
                None
            }
        }
    }
}

impl Iterator for XrefsFromIter {
    type Item = Xref;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.first {
            unsafe {
                if !xrefblk_t_next_from(&mut self.xb) {
                    return None;
                }
            }
        }
        self.first = false;
        
        Some(Xref {
            from: self.xb.from,
            to: self.xb.to,
            is_code: self.xb.iscode,
            xref_type: self.xb.type_,
            is_user: self.xb.user,
        })
    }
}

/// Iterator for xrefs to an address
pub struct XrefsToIter {
    xb: xrefblk_t,
    first: bool,
}

impl XrefsToIter {
    pub fn new(ea: ea_t, flags: i32) -> Option<Self> {
        unsafe {
            let mut xb: xrefblk_t = std::mem::zeroed();
            if xrefblk_t_first_to(&mut xb, ea, flags) {
                Some(Self { xb, first: true })
            } else {
                None
            }
        }
    }
}

impl Iterator for XrefsToIter {
    type Item = Xref;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.first {
            unsafe {
                if !xrefblk_t_next_to(&mut self.xb) {
                    return None;
                }
            }
        }
        self.first = false;
        
        Some(Xref {
            from: self.xb.from,
            to: self.xb.to,
            is_code: self.xb.iscode,
            xref_type: self.xb.type_,
            is_user: self.xb.user,
        })
    }
}

/// Get name at address (wrapper using get_ea_name)
pub fn get_name_at(ea: ea_t) -> Option<String> {
    unsafe {
        let mut s = qstring::default();
        
        // GN_VISIBLE = 0x0001
        let len = get_ea_name(&mut s, ea, 0x0001, std::ptr::null_mut());
        
        if len > 0 {
            Some(s.to_string())
        } else {
            None
        }
    }
}

pub fn get_type(ea: ea_t) -> Option<tinfo_t> {
    unsafe {
        let mut tif = std::mem::MaybeUninit::<tinfo_t>::zeroed();
        if !get_tinfo(tif.as_mut_ptr(), ea) {
            return None;
        }
        Some(tif.assume_init())
    }
}

// PRTYPE flags for print_tinfo
pub const PRTYPE_1LINE: i32 = 0x00001;     ///< print in one line
pub const PRTYPE_PRAGMA: i32 = 0x00004;    ///< print pragmas for alignment
pub const PRTYPE_SEMI: i32 = 0x00008;      ///< append ; to the end
pub const PRTYPE_CPP: i32 = 0x00010;       ///< use c++ name
pub const PRTYPE_DEF: i32 = 0x00020;       ///< print definition, if available
pub const PRTYPE_NOARGS: i32 = 0x00040;    ///< do not print function argument names
pub const PRTYPE_NOARRS: i32 = 0x00080;    ///< print arguments with FAI_ARRAY as pointers
pub const PRTYPE_NORES: i32 = 0x00100;     ///< never resolve types
pub const PRTYPE_RESTORE: i32 = 0x00200;   ///< print restored types
pub const PRTYPE_NOREGEX: i32 = 0x00400;   ///< do not apply regular expressions
pub const PRTYPE_COLORED: i32 = 0x00800;   ///< add color tags
pub const PRTYPE_METHODS: i32 = 0x01000;   ///< print udt methods
pub const PRTYPE_1LINCMT: i32 = 0x02000;   ///< print comments even in one line mode
pub const PRTYPE_HEADER: i32 = 0x04000;    ///< print only type header
pub const PRTYPE_OFFSETS: i32 = 0x08000;   ///< print udt member offsets
pub const PRTYPE_MAXSTR: i32 = 0x10000;    ///< limit output length
pub const PRTYPE_TAIL: i32 = 0x20000;      ///< print only definition tail
pub const PRTYPE_ARGLOCS: i32 = 0x40000;   ///< print function arglocs

/// Print type info to string
/// 
/// # Arguments
/// * `tif` - pointer to tinfo_t
/// * `name` - variable name (can be null)
/// * `flags` - PRTYPE_ flags
/// 
/// # Returns
/// Type string or None on error
pub fn print_tinfo_wrapper(tif: *const tinfo_t, name: Option<&str>, flags: i32) -> Option<String> {
    unsafe {
        let mut s = qstring::default();
        
        let name_ptr = name.map(|s| {
            let cstr = std::ffi::CString::new(s).unwrap_or_default();
            cstr.as_ptr()
        }).unwrap_or(std::ptr::null());
        
        let success = print_tinfo(
            &mut s,
            std::ptr::null(), // prefix
            0,                // indent
            0,                // cmtindent
            flags,
            tif,
            name_ptr,
            std::ptr::null(), // cmt
        );
        
        if !success {
            None
        } else {
            Some(s.to_string())
        }
    }
}

impl TryInto<String> for tinfo_t {
    type Error = ();
    
    fn try_into(self) -> Result<String, Self::Error> {
        print_tinfo_wrapper(&self, None, PRTYPE_1LINE).ok_or(())
    }
}

///// Simple wrapper to print type info (one line format)
//pub fn tinfo_to_string(tif: *const tinfo_t) -> Option<String> {
//    print_tinfo_wrapper(tif, None, PRTYPE_1LINE)
//}
//
///// Print type info with variable name
//pub fn tinfo_with_name(tif: *const tinfo_t, name: &str) -> Option<String> {
//    print_tinfo_wrapper(tif, Some(name), PRTYPE_1LINE | PRTYPE_SEMI)
//}

// ============================================================================
// Operand Type Functions (IDC get_operand_type equivalent)
// ============================================================================

// Operand type constants from ua.hpp
pub const O_VOID: u8 = 0;     // No Operand
pub const O_REG: u8 = 1;      // General Register
pub const O_MEM: u8 = 2;      // Direct memory reference
pub const O_PHRASE: u8 = 3;   // Memory reference using register [reg]
pub const O_DISPL: u8 = 4;    // Memory reference using register + displacement
pub const O_IMM: u8 = 5;      // Immediate value
pub const O_FAR: u8 = 6;      // Far code reference
pub const O_NEAR: u8 = 7;     // Near code reference

/// Get operand type at the specified address (IDC get_operand_type equivalent)
/// 
/// # Arguments
/// * `ea` - address
/// * `n` - operand number (0 = first operand, 1 = second operand)
/// 
/// # Returns
/// Operand type (O_VOID, O_REG, O_MEM, etc.) or O_VOID on error
pub fn get_operand_type(ea: ea_t, n: i32) -> u8 {
    if n < 0 || n >= 8 {
        return O_VOID;
    }
    
    unsafe {
        let flags = get_full_flags(ea);

        // Operand type is stored in flags at specific bit positions
        // Each operand gets 4 bits starting at offset 20
        let shift = if n > 1 {
            20 + 4 * (n + 1)
        } else {
            20 + 4 * n
        };
        
        let optype = ((flags >> shift) & 0xF) as u8;
        optype
    }
}

/// Check if an operand is a register (O_REG)
pub fn is_operand_reg(ea: ea_t, n: i32) -> bool {
    get_operand_type(ea, n) == O_REG
}

/// Check if an operand is memory (O_MEM)
pub fn is_operand_mem(ea: ea_t, n: i32) -> bool {
    get_operand_type(ea, n) == O_MEM
}

/// Check if an operand is immediate (O_IMM)
pub fn is_operand_imm(ea: ea_t, n: i32) -> bool {
    get_operand_type(ea, n) == O_IMM
}

// ============================================================================
// Name Functions
// ============================================================================

/// Check if a name is a user-specified name (not auto-generated)
/// 
/// # Arguments
/// * `name` - name to check
/// 
/// # Returns
/// true if the name is a valid user-specified name
pub fn is_user_name(name: &str) -> bool {
    let cname = std::ffi::CString::new(name).unwrap_or_default();
    unsafe { is_uname(cname.as_ptr()) }
}

// ============================================================================
// Item Functions (get_item_head is already in bindings)
// ============================================================================

/// Get the start address of the item at the given address
/// 
/// This handles "tail" bytes that are part of a larger item (e.g., struct members)
/// 
/// # Arguments
/// * `ea` - address within the item
/// 
/// # Returns
/// Start address of the item
pub fn get_item_start(ea: ea_t) -> ea_t {
    get_item_head(ea)
}

/// Get the end address of the item at the given address
/// 
/// Returns the address immediately after the current instruction/data item
/// 
/// # Arguments
/// * `ea` - address within the item
/// 
/// # Returns
/// End address of the item (start of next item)
pub fn item_end(ea: ea_t) -> ea_t {
    unsafe { get_item_end(ea) }
}

/// Get the size of the item at the given address
/// 
/// # Arguments
/// * `ea` - address of the item
/// 
/// # Returns
/// Size of the item in bytes
pub fn get_item_size(ea: ea_t) -> u64 {
    item_end(ea) - ea
}

// ============================================================================
// Inline flag functions (from bytes.hpp)
// ============================================================================

/// Get full flags for an address (inline implementation)
/// 
/// This is equivalent to the C++ inline function get_full_flags()
/// which calls get_flags_ex(ea, GFE_VALUE)
pub fn get_full_flags(ea: ea_t) -> flags64_t {
    unsafe { get_flags_ex(ea, GFE_VALUE) }
}

/// Check if flags indicate a tail byte (inline implementation)
/// 
/// Tail bytes are parts of multi-byte data items or instructions
pub fn is_tail(flags: flags64_t) -> bool {
    (flags & MS_CLS) == FF_TAIL
}

/// Check if flags indicate data (inline implementation)
pub fn is_data(flags: flags64_t) -> bool {
    (flags & MS_CLS) == FF_DATA
}

/// Check if flags indicate a struct (inline implementation)
pub fn is_struct(flags: flags64_t) -> bool {
    is_data(flags) && (flags & DT_TYPE) == FF_STRUCT
}

/// Get the head of an item at the given address (inline implementation)
/// 
/// If the address is in a tail byte, returns the address of the item head.
/// Otherwise returns the same address.
pub fn get_item_head(ea: ea_t) -> ea_t {
    unsafe {
        // Get 32-bit flags - for most purposes this is enough
        let flags = get_flags_ex(ea, 0); // GFE_NOVALUE = 0
        if is_tail(flags) {
            prev_not_tail(ea)
        } else {
            ea
        }
    }
}

// ============================================================================
// Struct Member Functions (Pure Rust via IDA API)
// ============================================================================

/// STRMEM_ flags for find_tinfo_udt_member
const STRMEM_OFFSET: i32 = 0x0000;  // get member by offset
const STRMEM_INDEX: i32 = 0x0001;   // get member by number
const STRMEM_NAME: i32 = 0x0003;    // get member by name

// Link the find_tinfo_udt_member function from IDA
#[link(name = "ida")]
unsafe extern "C" {
    /// Find a UDT (struct/union) member by offset/index/name
    /// 
    /// # Arguments
    /// * `udm` - pointer to udm_t struct (input/output)
    /// * `typid` - type ID of the struct/union
    /// * `strmem_flags` - STRMEM_* flags
    /// 
    /// # Returns
    /// Member index (>=0) on success, -1 on failure
    fn find_tinfo_udt_member(udm: *mut udm_t_raw, typid: u64, strmem_flags: i32) -> i32;
    
    /// Get tinfo_t by TID
    fn get_type_by_tid(tif: *mut tinfo_t, tid: u64) -> bool;
    
    /// Get TID for a member
    fn get_tinfo_tid(tif: *mut tinfo_t, force: bool) -> u64;
    
    /// Get size of a type
    fn get_tinfo_size(align: *mut u32, typid: u64, gts_code: i32) -> u64;
}

/// Raw udm_t struct layout matching IDA SDK
/// 
/// This is the memory layout of udm_t - we access fields directly
#[repr(C)]
#[derive(Clone, Copy)]
struct udm_t_raw {
    // qstring name: qvector<char> 
    // qvector layout: array, n, alloc
    name_array: *mut u8,
    name_n: usize,
    name_alloc: usize,
    
    // qstring cmt
    cmt_array: *mut u8,
    cmt_n: usize,
    cmt_alloc: usize,
    
    // tinfo_t type (opaque, we don't access directly)
    type_data: [u8; 24],  // Size of tinfo_t (3 pointers)
    
    // value_repr_t repr (we can skip for basic usage)
    repr_data: [u8; 64],  // value_repr_t is larger
    
    offset: u64,  // member offset in bits
    size: u64,    // member size in bits
    effalign: i32,
    tafld_bits: u32,
    fda: u8,
    _pad: [u8; 7],
}

impl Default for udm_t_raw {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

/// Extract string from qstring fields
unsafe fn qstring_to_str(ptr: *mut u8, len: usize) -> String {
    if ptr.is_null() || len == 0 {
        return String::new();
    }
    let slice = std::slice::from_raw_parts(ptr, len);
    String::from_utf8_lossy(slice).into_owned()
}

/// Get struct member name by offset
/// 
/// # Arguments
/// * `struct_name` - name of the struct
/// * `offset` - byte offset into the struct
/// 
/// # Returns
/// Member name or None if not found
pub fn get_member_name(struct_name: &str, offset: u64) -> Option<String> {
    let sid = get_struc_id(struct_name)?;
    
    unsafe {
        // Create zeroed udm_t with offset set
        let mut udm = udm_t_raw::default();
        udm.offset = offset * 8;  // Convert bytes to bits
        
        // Find member by offset
        let idx = find_tinfo_udt_member(&mut udm, sid, STRMEM_OFFSET);
        if idx < 0 {
            return None;
        }
        
        // Extract name from qstring
        let name = qstring_to_str(udm.name_array, udm.name_n);
        
        // Cleanup qstring memory (call destructor logic)
        // In IDA, qstring destructor frees memory - we should too
        if !udm.name_array.is_null() {
            // Note: We're leaking memory here since we can't easily call qstring destructor
            // For a plugin that's short-lived, this is acceptable
        }
        if !udm.cmt_array.is_null() {
            // Same for cmt
        }
        
        if name.is_empty() {
            None
        } else {
            Some(name)
        }
    }
}

/// Get struct member size by offset
/// 
/// # Arguments
/// * `struct_name` - name of the struct
/// * `offset` - byte offset into the struct
/// 
/// # Returns
/// Member size in bytes or None
pub fn get_member_size(struct_name: &str, offset: u64) -> Option<u64> {
    let sid = get_struc_id(struct_name)?;
    
    unsafe {
        let mut udm = udm_t_raw::default();
        udm.offset = offset * 8;  // Convert bytes to bits
        
        let idx = find_tinfo_udt_member(&mut udm, sid, STRMEM_OFFSET);
        if idx < 0 {
            return None;
        }
        
        Some(udm.size / 8)  // Convert bits to bytes
    }
}

/// Get struct member comment by offset
/// 
/// # Arguments
/// * `struct_name` - name of the struct
/// * `offset` - byte offset into the struct
/// * `_repeatable` - get repeatable comment (unused, kept for API compatibility)
/// 
/// # Returns
/// Member comment or None
pub fn get_member_cmt(struct_name: &str, offset: u64, _repeatable: bool) -> Option<String> {
    let sid = get_struc_id(struct_name)?;
    
    unsafe {
        let mut udm = udm_t_raw::default();
        udm.offset = offset * 8;  // Convert bytes to bits
        
        let idx = find_tinfo_udt_member(&mut udm, sid, STRMEM_OFFSET);
        if idx < 0 {
            return None;
        }
        
        let cmt = qstring_to_str(udm.cmt_array, udm.cmt_n);
        
        if cmt.is_empty() {
            None
        } else {
            Some(cmt)
        }
    }
}

/// Get struct member ID (TID) by offset
/// 
/// # Arguments
/// * `struct_name` - name of the struct
/// * `offset` - byte offset into the struct
/// 
/// # Returns
/// Member TID or None
/// 
/// # Note
/// Returns the struct's TID combined with the member index,
/// since member TIDs in IDA 9.x are derived from the parent struct.
pub fn get_member_id(struct_name: &str, offset: u64) -> Option<u64> {
    let sid = get_struc_id(struct_name)?;
    
    unsafe {
        let mut udm = udm_t_raw::default();
        udm.offset = offset * 8;  // Convert bytes to bits
        
        let idx = find_tinfo_udt_member(&mut udm, sid, STRMEM_OFFSET);
        if idx < 0 {
            return None;
        }
        
        // In IDA 9.x, member TIDs are derived from the struct TID and member index
        // We return a synthetic ID: (struct_tid << 32) | member_index
        // This matches how IDA internally represents member TIDs
        Some((sid << 32) | (idx as u64))
    }
}

/// Get struct size in bytes
/// 
/// # Arguments
/// * `struct_name` - name of the struct
/// 
/// # Returns
/// Size in bytes or None
/// 
/// # Note
/// Uses the fact that for struct TIDs, the TID itself can often be used
/// as the typid in get_tinfo_size (this is how IDA's API works internally)
pub fn get_struct_size(struct_name: &str) -> Option<u64> {
    let sid = get_struc_id(struct_name)?;
    
    unsafe {
        // For struct TIDs, the TID is often the typid
        let size = get_tinfo_size(std::ptr::null_mut(), sid, 0);
        
        if size == 0 {
            None
        } else {
            Some(size)
        }
    }
}

/// Get named type ID (TID) by name (idc.get_struc_id equivalent)
/// 
/// In IDA 9.x, get_struc_id() was replaced by get_named_type_tid()
/// 
/// # Arguments
/// * `name` - type name (e.g., "struct_name")
/// 
/// # Returns
/// Type ID (tid_t) or None
/// 
/// # Example
/// ```rust
/// // Get struct ID by name
/// if let Some(sid) = get_struc_id("my_struct") {
///     println!("Struct ID: 0x{:X}", sid);
/// }
/// ```
pub fn get_struc_id(name: &str) -> Option<u64> {
    unsafe {
        let cname = std::ffi::CString::new(name).ok()?;
        let tid = get_named_type_tid(cname.as_ptr());

        if tid == BADADDR || tid == 0 {
            None
        } else {
            Some(tid)
        }
    }
}

/// Get type name by TID (inverse of get_struc_id)
/// 
/// # Arguments
/// * `tid` - type ID
/// 
/// # Returns
/// Type name or None
pub fn get_struc_name(tid: u64) -> Option<String> {
    unsafe {
        if tid == BADADDR || tid == 0 {
            return None;
        }

        let mut s = qstring::default();
        
        if get_tid_name(&mut s, tid) {
            Some(s.to_string())
        } else {
            None
        }
    }
}



// ============================================================================
// Decompiler Functions (Hex-Rays) - Dynamic Loading
// ============================================================================

/// Hex-Rays decompiler function pointer type
/// 
/// The decompiler exports a dispatcher function HEXDSP that takes:
/// - hx_code: operation code (from hexrays.hpp)
/// - va: variadic arguments
/// 
/// Returns: result depends on the operation
type HexDspFn = unsafe extern "C" fn(hx_code: HexCall, ...) -> *mut std::ffi::c_void;

/// API call numbers for Hex-Rays decompiler SDK
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HexCall {
    ModifyUserLVarInfo = 193,
    LocateLVar = 194,
    CTreeVisitorTApplyTo = 455,
    CInsnPrint1 = 497,
    SaveUserCmts = 525,
    CFuncTSetUserCmt = 544,
    CFuncTGetPseudocode = 560,
    CFuncTRefreshFuncCText = 561,
    Decompile = 566,
}

/// mba_ranges_t - Ranges to decompile (function or snippet)
/// 
/// This struct matches the layout in hexrays.hpp
#[repr(C)]
pub struct mba_ranges_t {
    /// Function to decompile. If not null, function mode.
    pub pfn: *mut func_t,
    /// Range vector for snippet mode (not used directly here)
    /// In the SDK this is rangevec_t, but we use a pointer for FFI
    pub ranges: qvector<[ea_t; 2]>,
}

impl Default for mba_ranges_t {
    fn default() -> Self {
        Self {
            pfn: std::ptr::null_mut(),
            ranges: qvector::default(),
        }
    }
}

impl mba_ranges_t {
    /// Create mba_ranges_t for a function
    pub fn new_function(func: *mut func_t) -> Self {
        Self {
            pfn: func,
            ranges: qvector::default(),
        }
    }
}

#[repr(C)]
pub struct HexRaysFailure {
    pub code: i32,
    pub errea: ea_t,
    pub str: qstring,
}

impl Default for HexRaysFailure {
    fn default() -> Self {
        Self { code: 0, errea: BADADDR, str: qstring::default() }
    }
}

pub const ITP_BLOCK1: i32 = 74; ///< opening block comment. this comment is printed before the item
                            ///< (other comments are indented and printed after the item)
pub const ITP_BLOCK2: i32 = 75; ///< closing block comment.

#[repr(C)]
#[derive(Debug, Default)]
pub struct TreeLoc {
    pub ea: ea_t,
    pub itp: i32,
}

#[repr(C)]
#[derive(Debug)]
pub struct LVarSavedInfo {
    pub ll: LVarLocator,
    pub name: qstring,
    pub vtype: tinfo_t,
    pub cmt: qstring,
    pub size: isize,
    pub flags: i32,
}

impl Default for LVarSavedInfo {
    fn default() -> Self {
        Self {
            ll: LVarLocator::default(),
            name: qstring::default(),
            vtype: unsafe { std::mem::zeroed() },  // tinfo_t is opaque
            cmt: qstring::default(),
            size: BADSIZE,
            flags: 0,
        }
    }
}

// argloc_t/vdloc_t layout: type (int) + union (8 bytes on 64-bit) = 16 bytes with padding
// lvar_locator_t adds defea (8 bytes) after that
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LVarLocator {
    // vdloc_t (inherits from argloc_t)
    // argloc_t layout:
    pub atype: i32,           // argloc_type_t
    pub _pad: i32,            // padding to align union
    pub bigval: u64,          // biggest_t (union storage)
    // lvar_locator_t field
    pub defea: ea_t,
}

impl Default for LVarLocator {
    fn default() -> Self {
        Self { 
            atype: 0,  // ALOC_NONE
            _pad: 0,
            bigval: 0,
            defea: BADADDR 
        }
    }
}

pub const MLI_NAME: u32 = 0x01;
pub const MLI_TYPE: u32 = 0x02;
pub const MLI_CMT: u32 = 0x04;

pub fn locate_lvar(func_ea: ea_t, var_name: &str) -> Option<LVarLocator> {
    let mut loc = LVarLocator::default();
    let hexrays = unsafe { get_hexdsp()? };
    let var_name = CString::new(var_name.to_owned()).ok()?; 
    let retval = unsafe {hexrays(HexCall::LocateLVar as _, &mut loc, func_ea, var_name.as_ptr())};
    
    if retval as usize as u8 == 0 {
        return None;
    }   

    Some(loc)
}

pub fn modify_user_lvar_info(func_ea: ea_t, mli_flags: u32, info: &LVarSavedInfo) -> Option<()> {
    let hexrays = unsafe { get_hexdsp()? };
    let retval = unsafe {hexrays(HexCall::ModifyUserLVarInfo as _, func_ea, mli_flags, info)};
    
    if retval as usize as u8 == 0 {
        return None;
    }   

    None
}

pub fn rename_lvar(func_ea: ea_t, old_var_name: &str, new_var_name: &str) -> Option<()> {
    let loc = locate_lvar(func_ea, old_var_name)?;
    
    // Keep the CString alive until after the call
    let new_var_name = CString::new(new_var_name.to_owned()).ok()?;
    let mut info = LVarSavedInfo::default();
    info.ll = loc;
    let cb = new_var_name.count_bytes() + 1;
    // NOTE: The qstring points to CString data - this is still problematic
    // but keeping CString alive through the call
    info.name = qstring { 
        _phantom_0: std::marker::PhantomData, 
        body: qvector { 
            _phantom_0: std::marker::PhantomData, 
            array: new_var_name.as_ptr() as _, 
            n: cb, 
            alloc: cb 
        } 
    };
    
    let result = modify_user_lvar_info(func_ea, MLI_NAME, &info);
    
    // Keep CString alive until here
    drop(new_var_name);
    result
}

pub fn get_pseudocode(cfunc: &cfunc_t) -> Option<Vec<String>> {
   unsafe {
        let hexrays = get_hexdsp()?;
        let pseudocode = hexrays(HexCall::CFuncTGetPseudocode as _, cfunc) as *mut strvec_t;        
        
        if pseudocode.is_null() {
            println!("Getting pseudocode failed at 0x{:X}", cfunc.entry_ea);
            return None;
        }     
          
        Some((*pseudocode).to_vec())
   }
}

/// Decompile a function and return its pseudocode as a string
/// 
/// # Arguments
/// * `func_ea` - Address of the function to decompile
/// * `decomp_flags` - Decompilation flags (0 for default)
/// 
/// # Returns
/// String containing the decompiled pseudocode, or None if decompilation failed
pub fn decompile<'a>(func_ea: ea_t, decomp_flags: u32) -> Option<&'a mut cfunc_t> {
    unsafe {
        let pfn = get_function_at(func_ea)?;

        let hexrays = get_hexdsp()?;

        let mbr = mba_ranges_t::new_function(pfn);
        let mut hf = HexRaysFailure::default();
        
        (hexrays(HexCall::Decompile as _, &mbr, &mut hf, decomp_flags) as *mut cfunc_t).as_mut()
    }
}

#[repr(C)]
pub struct CBlockPos {
    pub blk: usize,
    pub p: usize,
}

pub const CV_FAST: u32 = 0x0000;
pub const CV_PRUNE: u32 = 0x0001;
pub const CV_PARENTS: u32 = 0x0002;
pub const CV_POST: u32 = 0x0004;
pub const CV_RESTART: u32 = 0x0008;
pub const CV_INSNS: u32 = 0x0010;

#[repr(C)]
pub struct CTreeVisitorVTable {
    pub destructor: unsafe extern "system" fn(&mut CTreeVisitor),
    pub visit_insn: unsafe extern "system" fn(&mut CTreeVisitor, &mut cinsn_t) -> i32,
    pub visit_expr: unsafe extern "system" fn(&mut CTreeVisitor, &mut cinsn_t) -> i32,
    pub leave_insn: unsafe extern "system" fn(&mut CTreeVisitor, &mut cinsn_t) -> i32,
    pub leave_expr: unsafe extern "system" fn(&mut CTreeVisitor, &mut cinsn_t) -> i32,
}

static mut CTREE_VISITOR_VTABLE: CTreeVisitorVTable = CTreeVisitorVTable {
    destructor: ctree_visitor_destructor,
    visit_insn: ctree_visitor_default_fn,
    visit_expr: ctree_visitor_default_fn,
    leave_insn: ctree_visitor_default_fn,
    leave_expr: ctree_visitor_default_fn,
};

unsafe extern "system" fn ctree_visitor_destructor(a1: &mut CTreeVisitor) {
    
}

unsafe extern "system" fn ctree_visitor_default_fn(a1: &mut CTreeVisitor, a2: &mut cinsn_t) -> i32 {
    0
}

#[repr(C)]
pub struct CTreeVisitor<'a> {
    pub vtable: &'a mut CTreeVisitorVTable,
    pub cv_flags: i32,
    pub parents: qvector<usize>,
    pub bposvec: qvector<CBlockPos>,
    pub extra_context: &'a mut [PseudocodeLocation],
}

impl CTreeVisitor<'_> {
    pub fn new(cv_flags: i32) -> Self {
        Self {
            vtable: unsafe { &mut CTREE_VISITOR_VTABLE },
            cv_flags,
            parents: qvector::default(),
            bposvec: qvector::default(),
            // this field doesn't acctually exist, im just expanding the struct
            // past the maximum size so i can store some context
            extra_context: &mut [PseudocodeLocation::default(); 0],
        }
    }

    pub fn apply_to(&mut self, item: &cinsn_t, parent: usize) -> Option<i32> {
        unsafe {
            let hexrays = get_hexdsp()?;
            Some(hexrays(HexCall::CTreeVisitorTApplyTo as _, self, item, parent) as usize as i32)
        }
    }
}


// ============================================================================
// tinfo_t - Type Information Extensions
// ============================================================================

/// Type identifier (handle to internal type representation)
pub type typid_t = u64;

/// Type sign
pub type type_sign_t = i32;
pub const TYPE_SIGN_UNSIGNED: type_sign_t = 0;
pub const TYPE_SIGN_SIGNED: type_sign_t = 1;
pub const TYPE_SIGN_UNKNOWN: type_sign_t = 2;

/// tinfo_t property enums
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GtaProp {
    DeclAlign = 0,      // GTA_DECLALIGN
    Resolve = 1,        // GTA_RESOLVE
    RealType = 2,       // GTA_REALTYPE
    TypeSign = 3,       // GTA_TYPE_SIGN
    FromSubtil = 4,     // GTA_FROM_SUBTIL
    IsForward = 5,      // GTA_IS_FORWARD
    IsFuncPtr = 6,      // GTA_IS_FUNCPTR
    Ordinal = 7,        // GTA_ORDINAL
    FinalOrdinal = 8,   // GTA_FINAL_ORDINAL
    PtrObj = 9,         // GTA_PTR_OBJ
    SafePtrObj = 10,    // GTA_SAFE_PTR_OBJ
    ArrayElem = 11,     // GTA_ARRAY_ELEM
    ArrayNElems = 12,   // GTA_ARRAY_NELEMS
    PtrArrSubtif = 13,  // GTA_PTRARR_SUBTIF
    PtrArrSize = 14,    // GTA_PTRARR_SIZE
    UnpaddedSize = 15,  // GTA_UNPADDED_SIZE
    UdtNMembers = 16,   // GTA_UDT_NMEMBERS
    IsSmallUdt = 17,    // GTA_IS_SMALL_UDT
    OneMemType = 18,    // GTA_ONEMEM_TYPE
    EnumBaseType = 19,  // GTA_ENUM_BASE_TYPE
    FuncCc = 20,        // GTA_FUNC_CC
    PurgedBytes = 21,   // GTA_PURGED_BYTES
    IsHighType = 22,    // GTA_IS_HIGH_TYPE
    FuncNArgs = 23,     // GTA_FUNC_NARGS
    FuncRet = 24,       // GTA_FUNC_RET
    FuncArg = 25,       // GTA_FUNC_ARG (base, add index)
}

/// tinfo_t comparison flags
pub const TCMP_EQUAL: i32 = 0x0000;
pub const TCMP_IGNMODS: i32 = 0x0001;
pub const TCMP_AUTOCAST: i32 = 0x0002;
pub const TCMP_MANCAST: i32 = 0x0004;
pub const TCMP_CALL: i32 = 0x0008;
pub const TCMP_DELPTR: i32 = 0x0010;
pub const TCMP_DECL: i32 = 0x0020;
pub const TCMP_ANYBASE: i32 = 0x0040;
pub const TCMP_SKIPTHIS: i32 = 0x0080;
pub const TCMP_DEEP_UDT: i32 = 0x0100;

// Type constants
pub const BT_UNK: uchar = 0x00;
pub const BT_VOID: uchar = 0x01;
pub const BT_INT8: uchar = 0x02;
pub const BT_INT16: uchar = 0x03;
pub const BT_INT32: uchar = 0x04;
pub const BT_INT64: uchar = 0x05;
pub const BT_INT128: uchar = 0x06;
pub const BT_INT: uchar = 0x07;
pub const BT_FLOAT: uchar = 0x08;
pub const BT_DOUBLE: uchar = 0x09;
pub const BT_LDOUBLE: uchar = 0x0A;
pub const BT_PTR: uchar = 0x0B;
pub const BT_FUNC: uchar = 0x0C;
pub const BT_ARRAY: uchar = 0x0D;
pub const BT_COMPLEX: uchar = 0x0E;
pub const BT_BITFIELD: uchar = 0x0F;

// Type modifiers
pub const BTM_CONST: uchar = 0x40;
pub const BTM_VOLATILE: uchar = 0x80;
pub const TYPE_MODIF_MASK: uchar = 0xC0;

// Complex type subtypes
pub const BTF_STRUCT: uchar = 0x10 | BT_COMPLEX;
pub const BTF_UNION: uchar = 0x20 | BT_COMPLEX;
pub const BTF_ENUM: uchar = 0x30 | BT_COMPLEX;
pub const BTF_TYPEDEF: uchar = 0x40 | BT_COMPLEX;

// Type reference flag
pub const TYPID_ISREF: u64 = 0x8000000000000000;
pub const FIRST_NONTRIVIAL_TYPID: u64 = 0x10;

// Type masks
pub const TYPE_BASE_MASK: uchar = 0x0F;
pub const TYPE_FLAGS_MASK: uchar = 0x30;
pub const TYPE_FULL_MASK: uchar = TYPE_BASE_MASK | TYPE_FLAGS_MASK;

/// Calling convention type
pub type callcnv_t = uchar;

/// tinfo_t error codes
pub type tinfo_code_t = i32;
pub const TERR_OK: tinfo_code_t = 0;
pub const TERR_INVALID_TYPE: tinfo_code_t = -1;
pub const TERR_INVALID_SIZE: tinfo_code_t = -2;
pub const TERR_INVALID_DETAIL: tinfo_code_t = -3;

// NTF flags
pub const NTF_TYPE: i32 = 0x0001;
pub const NTF_SYMM: i32 = 0x0002;
pub const NTF_SYMU: i32 = 0x0004;
pub const NTF_NOBASE: i32 = 0x0008;
pub const NTF_REPLACE: i32 = 0x0010;
pub const NTF_COPY: i32 = 0x0020;

// ETF flags
pub const ETF_NO_SAVE: i32 = 0x0001;
pub const ETF_FORCENAME: i32 = 0x0002;

// GTD flags
pub const GTD_CALC_LAYOUT: u32 = 0;
pub const GTD_CALC_ARGLOCS: u32 = 0;

// SUDT flags
pub const SUDT_FAST: i32 = 0x0001;
pub const SUDT_TRUNC: i32 = 0x0002;
pub const SUDT_GAPS: i32 = 0x0004;

// PT flags
pub const PT_SILENT: i32 = 0x0001;
pub const PT_SEMICOLON: i32 = 0x0002;
pub const PT_PPACKED: i32 = 0x0004;
pub const PT_PDEBPACK: i32 = 0x0008;
pub const PT_PCCHAR: i32 = 0x0010;
pub const PT_TYPDEF: i32 = 0x0020;
pub const PT_IGNOREVOIDARG: i32 = 0x0040;
pub const PT_QUAL: i32 = 0x0080;

// GTS flags
pub const GTS_VALUE: i32 = 0x0001;
pub const GTS_READONLY: i32 = 0x0002;
pub const GTS_NESTED: i32 = 0x0004;

// TAUDT bits
pub const TAUDT_UNALIGNED: u32 = 0x0001;
pub const TAUDT_MSSTRUCT: u32 = 0x0002;
pub const TAUDT_CPPOBJ: u32 = 0x0004;
pub const TAUDT_VFTABLE: u32 = 0x0008;
pub const TAUDT_FIXED: u32 = 0x0010;
pub const TAUDT_TUPLE: u32 = 0x0020;

// STRMEM flags
pub const STRMEM_MASK: i32 = 0x000F;
// STRMEM_OFFSET = 0x0000, STRMEM_INDEX = 0x0001, etc already defined above
pub const STRMEM_TYPE: i32 = 0x0004;
pub const STRMEM_SIZE: i32 = 0x0005;
pub const STRMEM_MINS: i32 = 0x0006;
pub const STRMEM_MAXS: i32 = 0x0007;
pub const STRMEM_LOWBND: i32 = 0x0008;
pub const STRMEM_NEXT: i32 = 0x0009;
pub const STRMEM_VFTABLE: i32 = 0x10000000;
pub const STRMEM_SKIP_EMPTY: i32 = 0x20000000;
pub const STRMEM_CASTABLE_TO: i32 = 0x40000000;
pub const STRMEM_ANON: i32 = 0x80000000u32 as i32;
pub const STRMEM_SKIP_GAPS: i32 = 0x01000000;

// FAI flags
pub const FAI_HIDDEN: u32 = 0x0001;
pub const FAI_RETPTR: u32 = 0x0002;
pub const FAI_STRUCT: u32 = 0x0004;
pub const FAI_ARRAY: u32 = 0x0008;
pub const FAI_UNUSED: u32 = 0x0010;

/// Stock type IDs
pub type stock_type_id_t = i32;
pub const STI_PVOID: stock_type_id_t = 0;
pub const STI_PBYTE: stock_type_id_t = 1;
pub const STI_PWORD: stock_type_id_t = 2;
pub const STI_PDWORD: stock_type_id_t = 3;
pub const STI_PQWORD: stock_type_id_t = 4;
pub const STI_PFLOAT: stock_type_id_t = 5;
pub const STI_PDOUBLE: stock_type_id_t = 6;
pub const STI_PUCHAR: stock_type_id_t = 7;
pub const STI_PUINT: stock_type_id_t = 8;
pub const STI_SIZE_T: stock_type_id_t = 9;
pub const STI_SSIZE_T: stock_type_id_t = 10;
pub const STI_COMPLEX64: stock_type_id_t = 11;
pub const STI_COMPLEX128: stock_type_id_t = 12;

// Additional GTA properties
const GTA_IS_SHIFTED_PTR: u32 = 44;
const GTA_IS_VARSTRUCT: u32 = 45;
const GTA_IS_VARMEMBER: u32 = 46;
const GTA_IS_TYPEDEF: u32 = 47;
const GTA_IS_ANON_UDT: u32 = 50;
const GTA_HAS_VFTABLE: u32 = 49;
const GTA_HAS_UNION: u32 = 52;
const GTA_UDM_TID: u32 = 54;
const GTA_UDM_IS_BYTIL: u32 = 56;
const GTA_EDT_NMEMBERS: u32 = 58;
const GTA_ENUM_WIDTH: u32 = 59;
const GTA_ENUM_REPR: u32 = 60;
const GTA_UDT_BITS: u32 = 61;
const GTA_FRAME_FUNC: u32 = 63;
const GTA_FINAL_ELEM: u32 = 51;
const GTA_EDM_BYNAME: u32 = 55;
const GTA_EDM_BYVAL: u32 = 56;
const GTA_EDM_TID: u32 = 57;
const GTA_BITMASK: u32 = 48;
const GTA_ENUM_RADIX: u32 = 49;
const GTA_EDM: u32 = 53;
const GTA_ALIAS: u32 = 53;

// GTP constants
const GTP_NAME: u32 = 0;
const GTP_NEXT_NAME: u32 = 1;
const GTP_FINAL_NAME: u32 = 2;
const GTP_TIL: u32 = 3;
const GTP_UDT_METHODS: u32 = 4;
const GTP_COMMENT: u32 = 5;
const GTP_RPTCMT: u32 = 6;
const GTP_BIT_BUCKETS: u32 = 7;
const GTP_NICE_NAME: u32 = 8;

// STA constants
const STA_DECLALIGN: u32 = 0;
const STA_TYPE_SIGN: u32 = 1;
const STA_UDT_ALIGN: u32 = 2;
const STA_UDT_METHODS: u32 = 3;
const STA_RENAME: u32 = 4;
const STA_COMMENT: u32 = 5;
const STA_CLR_MODIFS: u32 = 6;
const STA_SET_SDA: u32 = 7;
const STA_SET_PACK: u32 = 8;
const STA_ADD_UDM: u32 = 9;
const STA_DEL_UDMS: u32 = 10;
const STA_UDM_NAME: u32 = 11;
const STA_UDM_TYPE: u32 = 12;
const STA_UDM_CMT: u32 = 13;
const STA_UDM_REPR: u32 = 14;
const STA_EXPAND_UDT: u32 = 15;
const STA_ENUM_WIDTH: u32 = 16;
const STA_ENUM_SIGN: u32 = 17;
const STA_BITMASK: u32 = 18;
const STA_ENUM_REPR: u32 = 19;
const STA_ADD_EDM: u32 = 20;
const STA_DEL_EDMS: u32 = 21;
const STA_EDM_NAME: u32 = 22;
const STA_EDM_CMT: u32 = 23;
const STA_EDIT_EDM: u32 = 24;
const STA_ALIAS: u32 = 25;
const STA_ALIGNMENT: u32 = 26;
const STA_UDM_SET_BYTIL: u32 = 27;
const STA_FIXED_STRUCT: u32 = 28;
const STA_STRUCT_SIZE: u32 = 29;
const STA_FUNCARG_NAME: u32 = 30;
const STA_FUNCARG_TYPE: u32 = 31;
const STA_FUNC_RETTYPE: u32 = 32;
const STA_DEL_FUNCARGS: u32 = 33;
const STA_ADD_FUNCARG: u32 = 34;
const STA_FUNC_CC: u32 = 35;
const STA_ENUM_RADIX: u32 = 36;
const STA_FUNCARG_LOC: u32 = 37;
const STA_FUNC_RETLOC: u32 = 38;
const STA_TUPLE: u32 = 39;

/// Type library handle (opaque)
#[repr(C)]
#[derive(Debug)]
pub struct til_t {
    _unused: [u8; 0],
}

// Forward declarations for helper types
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct value_repr_t {
    pub _unused: [u8; 0],
}

// External FFI functions for tinfo_t
#[link(name = "ida")]
unsafe extern "C" {
    // Core tinfo_t functions
    fn create_tinfo_t(tif: *mut tinfo_t, decl_type: uchar, bt2: uchar, details: *mut std::ffi::c_void) -> bool;
    fn clear_tinfo_t(tif: *mut tinfo_t);
    fn copy_tinfo_t(dst: *mut tinfo_t, src: *const tinfo_t);
    fn get_tinfo_details(typid: u64, bt2: uchar, buf: *mut c_void) -> bool;
    fn get_tinfo_property(typid: u64, prop: u32) -> u64;
    fn get_tinfo_property4(typid: u64, prop: u32, arg1: usize, arg2: usize, arg3: usize, arg4: usize) -> u64;
    fn set_tinfo_property(tif: *mut tinfo_t, prop: u32, value: u64) -> u64;
    fn set_tinfo_property4(tif: *mut tinfo_t, prop: u32, arg1: usize, arg2: usize, arg3: usize, arg4: usize) -> u64;
    fn get_tinfo_pdata(out: *mut c_void, typid: u64, prop: u32) -> bool;
    fn verify_tinfo(typid: u64) -> i32;
    fn compare_tinfo(t1: u64, t2: u64, tcflags: i32) -> bool;
    fn lexcompare_tinfo(t1: u64, t2: u64, arg: u64) -> i32;
    fn detach_tinfo_t(tif: *mut tinfo_t) -> bool;
    fn serialize_tinfo(type_: *mut qvector<uchar>, fields: *mut qvector<uchar>, fldcmts: *mut qvector<uchar>, tif: *const tinfo_t, sudt_flags: i32) -> bool;
    fn deserialize_tinfo(tif: *mut tinfo_t, til: *const til_t, ptype: *mut *const uchar, pfields: *mut *const uchar, pfldcmts: *mut *const uchar, cmt: *const c_char) -> bool;
    fn score_tinfo(tif: *const tinfo_t) -> u32;
    fn dstr_tinfo(tif: *const tinfo_t) -> *const c_char;
    fn get_stock_tinfo(tif: *mut tinfo_t, id: i32);
    fn get_named_type(til: *const til_t, name: *const c_char, decl_type: uchar, resolve: bool, try_ordinal: bool, tif: *mut tinfo_t) -> bool;
    fn get_numbered_type(til: *const til_t, ordinal: u32, decl_type: uchar, resolve: bool, tif: *mut tinfo_t) -> bool;
    fn save_tinfo(tif: *mut tinfo_t, til: *mut til_t, ordinal: u32, name: *const c_char, ntf_flags: i32) -> tinfo_code_t;
    fn parse_decl(tif: *mut tinfo_t, name: *mut qstring, til: *mut til_t, decl: *const c_char, pt_flags: i32) -> bool;
    fn tinfo_get_innermost_udm(out: *mut tinfo_t, tif: *const tinfo_t, bitoffset: u64, out_index: *mut usize, out_bitoffset: *mut u64, get_type_only: bool);
    fn read_tinfo_bitfield_value(typid: u64, v: u64, bitoff: i32) -> u64;
    fn write_tinfo_bitfield_value(typid: u64, dst: u64, v: u64, bitoff: i32) -> u64;
    fn get_udm_by_tid(tif: *mut tinfo_t, udm: *mut udm_t, tid: u64) -> isize;
    // edm_t is same as udm_t in bindgen
    fn get_edm_by_tid(tif: *mut tinfo_t, edm: *mut udm_t, tid: u64) -> isize;
    // get_type_by_tid already defined above
    // get_tinfo_by_edm_name would go here
}

// Helper functions for calling conventions
fn is_user_cc(cc: callcnv_t) -> bool {
    cc >= 0x20 && cc <= 0x2F
}

fn is_vararg_cc(cc: callcnv_t) -> bool {
    cc == 0x05 || cc == 0x15
}

fn is_purging_cc(cc: callcnv_t) -> bool {
    cc == 0x02 || cc == 0x12
}

/// Extension trait for tinfo_t to provide safe Rust API
pub trait TinfoExt {
    fn new() -> Self;
    fn from_type(t: uchar) -> Self;
    fn is_empty(&self) -> bool;
    fn present(&self) -> bool;
    fn get_decltype(&self) -> uchar;
    fn get_realtype(&self) -> uchar;
    fn get_size(&self) -> Option<usize>;
    fn get_unpadded_size(&self) -> u64;
    fn is_const(&self) -> bool;
    fn is_volatile(&self) -> bool;
    fn is_void(&self) -> bool;
    fn is_ptr(&self) -> bool;
    fn is_array(&self) -> bool;
    fn is_func(&self) -> bool;
    fn is_struct(&self) -> bool;
    fn is_union(&self) -> bool;
    fn is_udt(&self) -> bool;
    fn is_enum(&self) -> bool;
    fn is_integral(&self) -> bool;
    fn is_floating(&self) -> bool;
    fn get_pointed_object(&self) -> Self;
    fn get_array_element(&self) -> Self;
    fn get_rettype(&self) -> Self;
    fn get_nth_arg(&self, n: i32) -> Self;
    fn get_type_name(&self) -> Option<String>;
    fn to_type_string(&self) -> String;
    fn dstr(&self) -> &str;
    fn equals_to(&self, other: &Self) -> bool;
    fn is_castable_to(&self, target: &Self) -> bool;
}

impl TinfoExt for tinfo_t {
    fn new() -> Self {
        Self { _unused: [] }
    }

    fn from_type(t: uchar) -> Self {
        let mut r = Self::new();
        unsafe { create_tinfo_t(&mut r, t, BT_INT, std::ptr::null_mut()) };
        r
    }

    fn is_empty(&self) -> bool {
        self.get_decltype() == BT_UNK
    }

    fn present(&self) -> bool {
        self.get_realtype() != BT_UNK
    }

    fn get_decltype(&self) -> uchar {
        // Access the internal typid field - we need to treat tinfo_t as having a u64 field
        unsafe { *(self as *const _ as *const u64) as uchar }
    }

    fn get_realtype(&self) -> uchar {
        unsafe { get_tinfo_property(self.get_typid(), GtaProp::RealType as u32) as uchar }
    }

    fn get_size(&self) -> Option<usize> {
        const BADSIZE: u64 = u64::MAX;
        let typid = self.get_typid();
        let size = unsafe { get_tinfo_size(std::ptr::null_mut(), typid, 0) };
        if size == BADSIZE { None } else { Some(size as usize) }
    }

    fn get_unpadded_size(&self) -> u64 {
        unsafe { get_tinfo_property(self.get_typid(), GtaProp::UnpaddedSize as u32) }
    }

    fn is_const(&self) -> bool {
        self.get_realtype() & BTM_CONST != 0
    }

    fn is_volatile(&self) -> bool {
        self.get_realtype() & BTM_VOLATILE != 0
    }

    fn is_void(&self) -> bool {
        self.get_realtype() == BT_VOID
    }

    fn is_ptr(&self) -> bool {
        self.get_realtype() == BT_PTR
    }

    fn is_array(&self) -> bool {
        self.get_realtype() == BT_ARRAY
    }

    fn is_func(&self) -> bool {
        self.get_realtype() == BT_FUNC
    }

    fn is_struct(&self) -> bool {
        self.get_realtype() == BTF_STRUCT
    }

    fn is_union(&self) -> bool {
        self.get_realtype() == BTF_UNION
    }

    fn is_udt(&self) -> bool {
        let rt = self.get_realtype();
        rt == BTF_STRUCT || rt == BTF_UNION
    }

    fn is_enum(&self) -> bool {
        self.get_realtype() == BTF_ENUM
    }

    fn is_integral(&self) -> bool {
        let rt = self.get_realtype() & TYPE_FULL_MASK;
        rt >= BT_INT8 && rt <= BT_INT
    }

    fn is_floating(&self) -> bool {
        let rt = self.get_realtype();
        rt >= BT_FLOAT && rt <= BT_LDOUBLE
    }

    fn get_pointed_object(&self) -> Self {
        let mut r = Self::new();
        let typid = unsafe { get_tinfo_property(self.get_typid(), GtaProp::PtrObj as u32) };
        unsafe { *(std::ptr::addr_of_mut!(r) as *mut u64) = typid };
        r
    }

    fn get_array_element(&self) -> Self {
        let mut r = Self::new();
        let typid = unsafe { get_tinfo_property(self.get_typid(), GtaProp::ArrayElem as u32) };
        unsafe { *(std::ptr::addr_of_mut!(r) as *mut u64) = typid };
        r
    }

    fn get_rettype(&self) -> Self {
        self.get_nth_arg(-1)
    }

    fn get_nth_arg(&self, n: i32) -> Self {
        let mut r = Self::new();
        if n >= -1 && n < 256 {
            let typid = unsafe { get_tinfo_property(self.get_typid(), (GtaProp::FuncArg as u32).wrapping_add(n as u32)) };
            unsafe { *(std::ptr::addr_of_mut!(r) as *mut u64) = typid };
        }
        r
    }

    fn get_type_name(&self) -> Option<String> {
        if !self.is_typeref() {
            return None;
        }
        let mut out = qstring::default();
        let ok = unsafe { get_tinfo_pdata(&mut out as *mut _ as *mut _, self.get_typid(), GTP_NAME) };
        if ok {
            Some(out.to_string())
        } else {
            None
        }
    }

    fn to_type_string(&self) -> String {
        self.print(None, PRTYPE_1LINE | PRTYPE_SEMI, 0, 0, None, None)
            .unwrap_or_default()
    }

    fn dstr(&self) -> &str {
        unsafe {
            let ptr = dstr_tinfo(self);
            if ptr.is_null() {
                ""
            } else {
                CStr::from_ptr(ptr).to_str().unwrap_or("")
            }
        }
    }

    fn equals_to(&self, other: &Self) -> bool {
        unsafe { compare_tinfo(self.get_typid(), other.get_typid(), TCMP_EQUAL) }
    }

    fn is_castable_to(&self, target: &Self) -> bool {
        unsafe { compare_tinfo(self.get_typid(), target.get_typid(), TCMP_AUTOCAST) }
    }
}

// Helper methods for tinfo_t
impl tinfo_t {
    /// Get the internal typid value
    fn get_typid(&self) -> u64 {
        unsafe { *(self as *const _ as *const u64) }
    }

    /// Check if this is a type reference
    fn is_typeref(&self) -> bool {
        (self.get_typid() & TYPID_ISREF) != 0
    }

    /// Print type to string
    pub fn print(&self, name: Option<&str>, prtype_flags: i32, indent: i32, cmtindent: i32, prefix: Option<&str>, cmt: Option<&str>) -> Option<String> {
        let mut out = qstring::default();
        let c_name = name.map(|n| CString::new(n).unwrap_or_default());
        let c_prefix = prefix.map(|p| CString::new(p).unwrap_or_default());
        let c_cmt = cmt.map(|c| CString::new(c).unwrap_or_default());
        
        let ok = unsafe {
            print_tinfo(
                &mut out,
                c_prefix.as_ref().map(|c| c.as_ptr()).unwrap_or(std::ptr::null()),
                indent,
                cmtindent,
                prtype_flags,
                self,
                c_name.as_ref().map(|c| c.as_ptr()).unwrap_or(std::ptr::null()),
                c_cmt.as_ref().map(|c| c.as_ptr()).unwrap_or(std::ptr::null()),
            )
        };
        
        if ok {
            Some(out.to_string())
        } else {
            None
        }
    }
}

// Helper to create qstring from &str
impl qstring {
    pub fn from_str(s: &str) -> Self {
        let mut qs = Self::default();
        for c in s.bytes() {
            unsafe {
                let vec = &mut qs.body;

                if vec.n < vec.alloc || (vec.alloc == 0 && vec.n == 0) {
                    if vec.alloc == 0 {
                        // Need to allocate - this is simplified
                        vec.alloc = 16;
                        vec.array = std::alloc::alloc(std::alloc::Layout::array::<i8>(16).unwrap()) as *mut i8;
                    }

                    *vec.array.add(vec.n) = c as i8;
                    vec.n += 1;
                }
            }
        }

        // Add null terminator
        unsafe {
            let vec = &mut qs.body;

            if vec.n > 0 {
                *vec.array.add(vec.n) = 0;
            }
        }

        qs
    }
}

pub const MFF_MAGIC: u32 = 0x12345678;
pub const MFF_WRITE: u32 = 0x0002;
pub const MFF_NOWAIT: u32 = 0x0004;

#[repr(C)]
pub struct ExecRequestVtable {
    pub execute: extern "C" fn (&mut ExecRequest) -> isize,
    pub destructor: extern "C" fn (&mut ExecRequest),
}

#[repr(C)]
pub struct ExecRequest {
    pub vtable: &'static ExecRequestVtable,
    pub code: isize, //< temporary location, used internally
    pub sem: usize,  //< semaphore to communicate with the main thread. If nullptr, will be initialized by execute_sync()
                     //< If nullptr, will be initialized by execute_sync().
    pub extra_data: usize,
}

impl ExecRequest {
    pub fn execute_sync(&mut self, flags: u32) -> isize {
        unsafe {
            callui(
                ui_notification_t::ui_execute_sync,
                self,
                flags,
            ).isize
        }
    }
}