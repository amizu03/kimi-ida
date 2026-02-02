// Hex-Rays ctree visitor implementation for collecting instruction addresses
// Based on IDA SDK hexrays.hpp

use crate::ida::{BADADDR, HexCall, decompile, ea_t, get_hexdsp, get_pseudocode, qstring, qvector};
use crate::strvec::{strvec_t, simpleline_t};
use std::collections::HashSet;

/// intvec_t - vector of integers (from IDA SDK)
pub type intvec_t = qvector<i32>;

/// ctree instruction opcodes (cit_)
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CInsnOpcode {
    CitEmpty = 0,
    CitBlock = 1,
    CitExpr = 2,
    CitIf = 3,
    CitFor = 4,
    CitWhile = 5,
    CitDo = 6,
    CitSwitch = 7,
    CitBreak = 8,
    CitContinue = 9,
    CitReturn = 10,
    CitGoto = 11,
    CitAsm = 12,
}

/// cinsn_t - ctree instruction
/// Opaque struct - we only need its address field
#[repr(C)]
pub struct cinsn_t {
    pub item: citem_t,
    pub details: *mut (),
}

impl cinsn_t {
    pub fn print1(&self, s: &mut qstring, func: Option<&cfunc_t>) -> Option<()> {
        unsafe {
            let hexrays = get_hexdsp()?;
            hexrays(HexCall::CInsnPrint1 as _, self, s, func);
            Some(())
        }
    }
}

/// ctree expression opcodes (cop_)
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CExprOpcode {
    CopAdd = 0,
    CopSub = 1,
    CopMul = 2,
    CopDiv = 3,
    CopMod = 4,
    CopNeg = 5,
    CopAnd = 6,
    CopOr = 7,
    CopXor = 8,
    CopShl = 9,
    CopShr = 10,
    CopCall = 15,
}

/// cexpr_t - ctree expression
#[repr(C)]
pub struct cexpr_t {
    _opaque: [u8; 96], // Size estimate
}

impl cexpr_t {
    /// Get the opcode of this expression
    /// 
    /// # Safety
    /// Must be a valid cexpr_t pointer
    pub unsafe fn opcode(&self) -> CExprOpcode {
        let opcode_val = *(self._opaque.as_ptr() as *const u32);
        match opcode_val {
            0 => CExprOpcode::CopAdd,
            1 => CExprOpcode::CopSub,
            2 => CExprOpcode::CopMul,
            3 => CExprOpcode::CopDiv,
            4 => CExprOpcode::CopMod,
            5 => CExprOpcode::CopNeg,
            6 => CExprOpcode::CopAnd,
            7 => CExprOpcode::CopOr,
            8 => CExprOpcode::CopXor,
            9 => CExprOpcode::CopShl,
            10 => CExprOpcode::CopShr,
            15 => CExprOpcode::CopCall,
            _ => CExprOpcode::CopAdd,
        }
    }
}

#[repr(C)]
pub struct citem_t {
    pub ea: ea_t,
    pub op: i32,
    pub label_num: i32,
    pub index: i32,
}

/// cfunc_t - decompiled function
/// Represents the decompilation result
/// 
/// # Note
/// This struct must match the Hex-Rays SDK layout exactly.
/// The argidx field is intvec_t (qvector<int>, 24 bytes), not a simple pointer.
#[repr(C)]
pub struct cfunc_t {
    pub entry_ea: ea_t,        // Function entry point
    pub mba: usize,            // Pointer to mba_t (microcode)
    pub body: cinsn_t,         // Function body (ctree)
    pub argidx: intvec_t,      // Argument indexes (qvector<int>, 24 bytes!)
    pub maturity: i32,         // Decompilation maturity level
    // Padding to align next fields to 8 bytes (maturity is 4 bytes, need 4 more)
    // The C++ compiler adds padding here, so we need to account for it
    _padding: [u8; 4],
    pub user_labels: usize,    // Pointer to user_labels_t
    pub user_cmts: usize,      // Pointer to usercmts_t
}

impl cfunc_t {    
    /// Set a user comment in the decompiled function
    /// 
    /// # Arguments
    /// * `tl` - Tree location (address + itp)
    /// * `comment` - The comment text
    /// 
    /// # Safety
    /// The Hex-Rays decompiler makes a copy of the comment string, so the
    /// CString is only needed for the duration of this call.
    /// 
    /// # Note  
    /// This function is best-effort. If the struct layout doesn't match
    /// the Hex-Rays SDK, this may fail silently.
    pub fn set_user_cmt(&self, tl: &crate::ida::TreeLoc, comment: &str) -> Option<()> {
        // Validate inputs
        if comment.is_empty() || tl.ea == 0 || tl.ea == BADADDR {
            return None;
        }
        
        let hexrays = unsafe { get_hexdsp()? };
        let comment = std::ffi::CString::new(comment.to_owned()).ok()?;
        
        // Call Hex-Rays API - ignore the return value as we don't know
        // what the actual return type should be
        unsafe { 
            hexrays(crate::ida::HexCall::CFuncTSetUserCmt as _, self, tl, comment.as_ptr()); 
        }
        Some(())
    }
    
    /// Save user comments for this function
    /// 
    /// # Note
    /// This is a potentially dangerous operation if the struct layout
    /// doesn't match the Hex-Rays SDK. We make it as defensive as possible.
    pub fn save_user_cmts(&self) -> Option<()> {
        // Defensive checks - if user_cmts is null, nothing to save
        if self.user_cmts == 0 {
            return Some(());
        }
        
        // Also check if entry_ea is valid
        if self.entry_ea == 0 || self.entry_ea == u64::MAX {
            return None;
        }
        
        let hexrays = unsafe { crate::ida::get_hexdsp()? };
        
        // Pass the cfunc_t pointer and let Hex-Rays figure out the rest
        // The SDK function might have different signatures across versions
        unsafe { 
            hexrays(crate::ida::HexCall::SaveUserCmts as _, self, self.user_cmts); 
        }
        Some(())
    }

    pub fn refresh_func_ctext(&self) -> Option<()> {
        let hexrays = unsafe { get_hexdsp()? };
        unsafe { hexrays(HexCall::CFuncTRefreshFuncCText as _, self) };        
        Some(())
    }
}