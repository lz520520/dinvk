#![cfg(any(target_arch = "x86_64", target_arch = "x86"))]

use core::sync::atomic::{Ordering, AtomicUsize};

/// The global variable that stores the currently selected DLL for system calls.
///
/// # Default
///
/// By default, this is set to `Dll::Ntdll`, meaning that system calls will be
/// resolved from `ntdll.dll` unless explicitly changed using [`Dll::use_dll`].
static DEFAULT_DLL: AtomicUsize = AtomicUsize::new(Dll::Ntdll as usize);

/// Represents different dynamic link libraries (DLLs) that contain system call functions.
#[derive(Clone, Copy, PartialEq)]
pub enum Dll {
    #[cfg(target_arch = "x86_64")]
    /// `iumdll.dll`
    Iumdll,

    #[cfg(target_arch = "x86_64")]
    /// `vertdll.dll`
    Vertdll,

    /// `win32u.dll`
    Win32u,

    /// `ntdll.dll`
    Ntdll,
}

impl Dll {
    /// Sets the default DLL to be used for system calls.
    ///
    /// # Arguments
    ///
    /// * `dll` - The [`Dll`] variant to use as the new default.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use dinvk::Dll;
    ///
    /// // Switch to win32u.dll for GUI-related syscalls
    /// Dll::use_dll(Dll::Win32u);
    /// ```
    pub fn use_dll(dll: Dll) {
        DEFAULT_DLL.store(dll as usize, Ordering::Relaxed);
    }

    /// Retrieves the currently selected DLL for system calls.
    ///
    /// # Returns
    ///
    /// * The currently set DLL as a [`Dll`] enum variant.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use dinvk::Dll;
    ///
    /// // Retrieve the currently selected DLL
    /// let dll = Dll::current();
    ///
    /// println!("Current DLL: {}", dll);
    /// ```
    pub fn current() -> Dll {
        match DEFAULT_DLL.load(Ordering::Relaxed) {
            #[cfg(target_arch = "x86_64")]
            x if x == Dll::Iumdll as usize => Dll::Iumdll,
            #[cfg(target_arch = "x86_64")]
            x if x == Dll::Vertdll as usize => Dll::Vertdll,
            x if x == Dll::Win32u as usize => Dll::Win32u,
            _ => Dll::Ntdll,
        }
    }

    /// Returns the function name associated with the selected DLL, if applicable.
    ///
    /// # Returns
    ///
    /// * A static string slice (`&str`) containing the function name or an empty string.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use dinvk::Dll;
    ///
    /// let dll = Dll::Win32u;
    /// println!("Function: {}", dll.function_hash());
    /// ```
    pub fn function_hash(&self) -> u32 {
        match self {
            Dll::Ntdll => 0,
            Dll::Win32u => 2604093150u32,
            #[cfg(target_arch = "x86_64")]
            Dll::Iumdll => 75139374u32,
            #[cfg(target_arch = "x86_64")]
            Dll::Vertdll => 2237456582u32,
        }
    }
}

impl core::fmt::Display for Dll {
    /// Formats the `Dll` variant as its corresponding DLL file name.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use dinvk::Dll;
    ///
    /// let dll = Dll::Win32u;
    /// println!("DLL: {}", dll);
    /// ```
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name: &[u8] = match self {
            Dll::Ntdll => &[0x4E, 0x54, 0x44, 0x4C, 0x4C, 0x0E, 0x44, 0x4C, 0x4C],
            Dll::Win32u => &[0x57, 0x49, 0x4E, 0x13, 0x12, 0x55, 0x0E, 0x44, 0x4C, 0x4C],
            #[cfg(target_arch = "x86_64")]
            Dll::Iumdll => &[0x49, 0x55, 0x4D, 0x44, 0x4C, 0x4C, 0x0E, 0x44, 0x4C, 0x4C],
            #[cfg(target_arch = "x86_64")]
            Dll::Vertdll => &[0x56, 0x45, 0x52, 0x54, 0x44, 0x4C, 0x4C, 0x0E, 0x44, 0x4C, 0x4C],
        };
        write!(f, "{}", name.iter().map(|&c| (c ^ 0x20) as char).collect::<alloc::string::String>())
    }
}