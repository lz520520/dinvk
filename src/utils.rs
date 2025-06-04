use alloc::{string::{String, ToString}, vec::Vec};
use core::{fmt::{self, Write}, ptr};
use crate::{
    data::WriteConsoleA, 
    dinvoke, GetModuleHandle, 
    GetStdHandle, 
};

/// `ConsoleWriter` is a custom implementation of `core::fmt::Write`
/// that writes formatted strings directly to the Windows console.
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
            buffer.as_ptr(),
            buffer.len() as u32,
            ptr::null_mut(),
            ptr::null_mut()
        );

        Ok(())
    }
}

pub(crate) fn canonicalize_module(name: &str) -> String {
    let file = name.rsplit(['\\', '/']).next().unwrap_or(name);
    let upper = file.to_ascii_uppercase();
    upper.trim_end_matches(".DLL").to_string()
}

/// Randomly shuffles the elements of a mutable slice in-place using a pseudo-random
/// number generator seeded by the CPU's timestamp counter (`rdtsc`).
///
/// The shuffling algorithm is a variant of the Fisher-Yates shuffle.
///
/// # Arguments
/// 
/// * `list` — A mutable slice of elements to be shuffled.
pub fn shuffle<T>(list: &mut [T]) {
    let mut seed = unsafe { core::arch::x86_64::_rdtsc() };
    for i in (1..list.len()).rev() {
        seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
        let j = seed as usize % (i + 1);
        list.swap(i, j);
    }
}
