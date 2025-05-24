use alloc::vec::Vec;
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

/// Canonicalizes a UTF-16 path slice by removing `.dll` suffix and returning just the file name.
pub fn canon(s: &[u16]) -> &[u16] {
    let mut end = s.len();
    if end >= 4
        && eq_nocase(
            &s[end - 4..],
            &[b'.' as u16, b'd' as u16, b'l' as u16, b'l' as u16],
        )
    {
        end -= 4;
    }

    s[..end]
        .rsplit(|&c| c == '\\' as u16 || c == '/' as u16)
        .next()
        .unwrap_or(&s[..end])
}

/// Compares two UTF-16 slices for case-insensitive ASCII equality.
pub fn eq_nocase(a: &[u16], b: &[u16]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    a.iter().zip(b).all(|(&x, &y)| {
        let x = x as u8;
        let y = y as u8;
        x.is_ascii() && y.is_ascii() && x.eq_ignore_ascii_case(&y)
    })
}

/// Converts a UTF-16 slice into uppercase ASCII bytes and stores in a destination buffer.
pub fn upper(src: &[u16], dst: &mut [u8]) -> usize {
    let mut i = 0;
    for &c in src {
        if i >= dst.len() {
            break;
        }
        let b = c as u8;
        if b.is_ascii() {
            dst[i] = b.to_ascii_uppercase();
            i += 1;
        }
    }
    
    i
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
