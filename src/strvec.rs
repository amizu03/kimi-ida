// strvec_t and simpleline_t definitions for Hex-Rays decompiler output
// Based on IDA SDK kernwin.hpp

use crate::ida::qstring;

/// Default color constant (from pro.h)
pub const DEFCOLOR: u32 = u32::MAX;  // bgcolor_t(-1)

/// Color type for line prefix (uchar in C++)
pub type color_t = u8;

/// Background color type (uint32 in C++)
pub type bgcolor_t = u32;

/// Maintain basic information for a line in a custom view
/// 
/// This struct matches the layout of `simpleline_t` in kernwin.hpp
#[repr(C)]
#[derive(Debug)]
pub struct simpleline_t {
    /// Line text (qstring)
    pub line: qstring,
    /// Line prefix color (defaults to 1)
    pub color: color_t,
    /// Line background color (defaults to DEFCOLOR)
    pub bgcolor: bgcolor_t,
}

impl Default for simpleline_t {
    fn default() -> Self {
        Self {
            line: qstring::default(),
            color: 1,
            bgcolor: DEFCOLOR,
        }
    }
}

impl simpleline_t {
    /// Create a new empty simpleline
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Get the line text as a Rust String
    pub fn text(&self) -> String {
        self.line.to_string()
    }
}

/// A collection of simple lines to populate a custom view
/// 
/// This is `strvec_t` in the IDA SDK, defined as `qvector<simpleline_t>`
/// It represents the decompilation output (pseudocode) from Hex-Rays
#[repr(C)]
pub struct strvec_t {
    /// Internal qvector storage
    /// qvector layout: array, n, alloc
    array: *mut simpleline_t,
    n: usize,
    alloc: usize,
}

impl Default for strvec_t {
    fn default() -> Self {
        Self {
            array: std::ptr::null_mut(),
            n: 0,
            alloc: 0,
        }
    }
}

impl strvec_t {
    /// Create an empty strvec_t
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Get the number of lines
    pub fn len(&self) -> usize {
        self.n
    }
    
    /// Check if the vector is empty
    pub fn is_empty(&self) -> bool {
        self.n == 0
    }
    
    /// Get a line at the specified index
    /// 
    /// # Safety
    /// This is unsafe because we dereference a raw pointer
    pub unsafe fn get(&self, idx: usize) -> Option<&simpleline_t> {
        if idx >= self.n || self.array.is_null() {
            return None;
        }
        Some(&*self.array.add(idx))
    }
    
    /// Get a line at the specified index (mutable)
    /// 
    /// # Safety
    /// This is unsafe because we dereference a raw pointer
    pub unsafe fn get_mut(&mut self, idx: usize) -> Option<&mut simpleline_t> {
        if idx >= self.n || self.array.is_null() {
            return None;
        }
        Some(&mut *self.array.add(idx))
    }
    
    /// Iterate over all lines
    /// 
    /// # Safety
    /// The caller must ensure the strvec_t is valid
    pub unsafe fn iter(&self) -> StrvecIter {
        StrvecIter {
            vec: self,
            idx: 0,
        }
    }
    
    /// Convert to a Vec<String> for easier handling
    /// 
    /// # Safety
    /// The caller must ensure the strvec_t is valid
    pub unsafe fn to_vec(&self) -> Vec<String> {
        let mut result = Vec::with_capacity(self.n);

        for i in 0..self.n {
            if let Some(line) = self.get(i) {
                result.push(line.text());
            }
        }
        
        result
    }
}

/// Iterator over strvec_t lines
pub struct StrvecIter<'a> {
    vec: &'a strvec_t,
    idx: usize,
}

impl<'a> Iterator for StrvecIter<'a> {
    type Item = &'a simpleline_t;
    
    fn next(&mut self) -> Option<Self::Item> {
        if self.idx >= self.vec.n {
            return None;
        }
        let item = unsafe { self.vec.get(self.idx) };
        self.idx += 1;
        item
    }
}

// Link to IDA's strvec_t/qvector methods
#[link(name = "ida")]
unsafe extern "C" {
    // qvector methods for strvec_t
    fn strvec_t_push_back(vec: *mut strvec_t, item: *const simpleline_t);
    fn strvec_t_clear(vec: *mut strvec_t);
    fn strvec_t_resize(vec: *mut strvec_t, new_size: usize);
}
