use alloc::{string::{String, ToString}, vec::Vec};
use core::{fmt::{self, Write}, ptr};
use crate::{
    data::WriteConsoleA, 
    dinvoke, GetModuleHandle, 
    GetStdHandle, 
};

/// `ConsoleWriter` is a custom implementation of `core::fmt::Write`
/// that writes formatted strings directly to the Windows console.
///
/// This is particularly useful in `#[no_std]` environments where
/// standard printing functions are unavailable.
pub struct ConsoleWriter;

impl Write for ConsoleWriter {
    /// Writes a string to the Windows console using `WriteConsoleA`.
    ///
    /// # Argument
    /// 
    /// * `s` - The string to be written to the console.
    ///
    /// # Returns
    /// 
    /// * Indicates whether the write operation was successful.
    fn write_str(&mut self, s: &str) -> fmt::Result {       
        // Convert the string into a byte buffer
        let buffer = Vec::from(s.as_bytes());
        
        // Retrieve the handle for `KERNEL32.DLL`
        let kernel32 = GetModuleHandle(obfstr::obfstr!("KERNEL32.DLL"), None);

        // Dynamically invoke `WriteConsoleA`
        _ = dinvoke!(
            kernel32,
            obfstr::obfstr!("WriteConsoleA"),
            WriteConsoleA,
            GetStdHandle((-11i32) as u32),
            buffer.as_ptr() as *const u8,
            buffer.len() as u32,
            ptr::null_mut(),
            ptr::null_mut()
        );

        Ok(())
    }
}

/// Normalizes a module (DLL) name for consistent comparison with loaded module names.
///
/// This function:
/// - Strips any path, keeping only the filename.
/// - Converts the name to uppercase for case-insensitive comparison.
/// - Removes the `.DLL` extension if present (case-insensitive).
///
/// Useful for matching variations like `"kernel32.dll"`, `"KERNEL32"`, or
/// `"C:\\Windows\\System32\\kernel32.DlL"` to a consistent `"KERNEL32"`.
///
/// # Example
/// 
/// ```rs
/// assert_eq!(canonicalize_module("kernel32.dll"), "KERNEL32");
/// assert_eq!(canonicalize_module("C:\\Windows\\System32\\KERNEL32"), "KERNEL32");
/// assert_eq!(canonicalize_module("KERNEL32.DlL"), "KERNEL32");
/// ```
pub(crate) fn canonicalize_module(name: &str) -> String {
    let file = name.rsplit(['\\', '/']).next().unwrap_or(name);
    let upper = file.to_ascii_uppercase();
    upper.trim_end_matches(".DLL").to_string()
}
