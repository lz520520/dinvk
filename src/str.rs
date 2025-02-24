/// A helper trait to convert Rust strings into null-terminated C strings.
///
/// This trait is implemented for `&str` to simplify the creation of `CStr` values
/// for use with Windows APIs.
pub trait CStr {
    /// Converts a Rust string slice into a null-terminated C string.
    ///
    /// # Returns
    /// 
    /// * A vector of bytes containing the C-style string (null-terminated).
    fn to_vec(&self) -> alloc::vec::Vec<u8>;
}

impl CStr for &str {
    fn to_vec(&self) -> alloc::vec::Vec<u8> {
        let mut c_string = self.as_bytes().to_vec();
        c_string.push(0);
        c_string
    }
}
