use alloc::vec::Vec;
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
