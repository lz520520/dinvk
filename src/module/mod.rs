use core::{
    ffi::{c_void, CStr}, 
    ptr::null_mut, 
    slice::from_raw_parts
};
use crate::{
    functions::LoadLibraryA, 
    hash::crc32ba,
    utils::*,
    data::{
        HMODULE, IMAGE_DIRECTORY_ENTRY_EXPORT, 
        IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, 
        IMAGE_NT_HEADERS, IMAGE_NT_SIGNATURE, 
        LDR_DATA_TABLE_ENTRY, PEB, TEB 
    },  
};

/// Module containing dynamic module loader proxy.
pub mod ldr;

/// Stores the NTDLL address
static NTDLL: spin::Once<u64> = spin::Once::new();

/// Resolves the base address of a module loaded in memory by name or hash.
///
/// # Arguments
///
/// * `module` - Can be a DLL name (as `&str`) or a hash (`u32`).  
///             The function will auto-detect and match accordingly.
/// * `hash` - Optional hash function (e.g., `crc32`, `murmur3`). Used for hash matching.
///
/// # Returns
///
/// - If found: Returns the module's base address (`HMODULE`)
/// - If not found: Returns null.
///
/// # Examples
///
/// ```rust,ignore
/// let base = GetModuleHandle("ntdll.dll", None);
/// let base = GetModuleHandle(2788516083u32, Some(murmur3));
/// ```
pub fn GetModuleHandle<'a>(
    module: impl Into<Symbol<'a>>,
    hash: Option<fn(&str) -> u32>,
) -> HMODULE {
    let module = module.into();
    unsafe {
        let hash = hash.unwrap_or(crc32ba);
        let peb = NtCurrentPeb();
        let ldr_data = (*peb).Ldr;
        let mut data_table_entry = (*ldr_data).InMemoryOrderModuleList.Flink as *const LDR_DATA_TABLE_ENTRY;
        let mut list_node = (*ldr_data).InMemoryOrderModuleList.Flink;

        if module.is_empty() {
            return (*peb).ImageBaseAddress;
        }

        // Save a reference to the head nod for the list
        let head_node = list_node;
        while !(*data_table_entry).FullDllName.Buffer.is_null() {
            if (*data_table_entry).FullDllName.Length != 0 {
                // Converts the buffer from UTF-16 to a `String`
                let buffer = from_raw_parts(
                    (*data_table_entry).FullDllName.Buffer,
                    ((*data_table_entry).FullDllName.Length / 2) as usize,
                );

                // We're handling string interpretations this way to avoid heap allocations, 
                // which could potentially trigger a loop in the allocator under certain conditions.
                match &module {
                    Symbol::Hash(dll_hash) => {
                        // Try interpreting `module` as a numeric hash (u32)
                        let mut buf = [0u8; 256];
                        let n = upper(buffer, &mut buf);
                        let name = core::str::from_utf8(&buf[..n]).unwrap_or("");
                        if *dll_hash == hash(name) {
                            return (*data_table_entry).Reserved2[0];
                        }
                    },
                    Symbol::Name(name) => {
                        // If it is not an `u32`, it is treated as a string
                        let dll_file_name = canon(buffer);
                        let mut tmp = [0u16; 256];
                        let len = name.encode_utf16()
                            .take(256)
                            .enumerate()
                            .map(|(i, c)| {
                                tmp[i] = c;
                                i
                            })
                            .last()
                            .unwrap_or(0) + 1;

                        let canon_name = canon(&tmp[..len]);
                        if eq_nocase(canon_name, dll_file_name) {
                            return (*data_table_entry).Reserved2[0];
                        }
                    }
                }
            }

            // Moves to the next node in the list of modules
            list_node = (*list_node).Flink;

            // Break out of loop if all of the nodes have been checked
            if list_node == head_node {
                break;
            }

            data_table_entry = list_node as *const LDR_DATA_TABLE_ENTRY
        }
    }

    null_mut()
}

/// Retrieves the address of a function exported by a given module.
///
/// Supports lookup by name (`&str`), hash (`u32`), or ordinal (`u16`).
///
/// # Arguments
///
/// * `h_module` - Handle of the module (base address)
/// * `function` - Can be a name, hash or ordinal
/// * `hash` - Optional function to hash export names for hash-based matching
///
/// # Returns
///
/// * Pointer to the resolved function
///
/// # Examples
///
/// ```rust,ignore
/// let base = GetModuleHandle("ntdll.dll", None);
/// let func = GetProcAddress(base, "NtProtectVirtualMemory", None);
/// ```
///
/// ```rust,ignore
/// let func = GetProcAddress(base, 2193297120u32, Some(murmur3));
/// ```
///
/// ```rust,ignore
/// let func = GetProcAddress(base, 473u32, None);
/// ```
pub fn GetProcAddress<'a>(
    h_module: HMODULE, 
    function: impl Into<Symbol<'a>>, 
    hash: Option<fn(&str) -> u32>
) -> *mut c_void {
    if h_module.is_null() {
        return null_mut();
    }

    let function = function.into();
    let h_module = h_module as usize;
    unsafe {
        let nt_header = (h_module + (*(h_module as *const IMAGE_DOS_HEADER)).e_lfanew as usize) as *const IMAGE_NT_HEADERS;
        if (*nt_header).Signature != IMAGE_NT_SIGNATURE {
            return null_mut();
        }

        // Retrieves the export table
        let export_dir = (h_module + (*nt_header).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].VirtualAddress as usize) 
            as *const IMAGE_EXPORT_DIRECTORY;
        
        // Retrieves the size of the export table
        let export_size = (*nt_header).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].Size as usize;

        // Retrieving information from module names
        let names = from_raw_parts((
            h_module + (*export_dir).AddressOfNames as usize) as *const u32, 
            (*export_dir).NumberOfNames as usize
        );

        // Retrieving information from functions
        let functions = from_raw_parts(
            (h_module + (*export_dir).AddressOfFunctions as usize) as *const u32, 
            (*export_dir).NumberOfFunctions as usize
        );

        // Retrieving information from ordinals
        let ordinals = from_raw_parts(
            (h_module + (*export_dir).AddressOfNameOrdinals as usize) as *const u16, 
            (*export_dir).NumberOfNames as usize
        );

        // Import By Ordinal
        let hash = hash.unwrap_or(crc32ba);
        if let Symbol::Hash(ordinal) = &function {
            if *ordinal <= 0xFFFF {
                let ordinal = ordinal & 0xFFFF;
                if ordinal >= (*export_dir).Base
                    && ordinal < (*export_dir).Base + (*export_dir).NumberOfFunctions
                {
                    let addr = (h_module + functions[ordinal as usize - (*export_dir).Base as usize] as usize) as *mut c_void;
                    return get_forwarded_address(addr, export_dir, export_size, hash);
                }
            }
        }

        // Import By Name or Hash
        for i in 0..(*export_dir).NumberOfNames as usize {
            let offset = (h_module + names[i] as usize) as *const i8;
            let name = CStr::from_ptr(offset).to_str().unwrap_or("");
            let ordinal = ordinals[i] as usize;
            let addr = (h_module + functions[ordinal] as usize) as *mut c_void;

            match &function {
                Symbol::Hash(h) => {
                    if hash(name) == *h {
                        return get_forwarded_address(addr, export_dir, export_size, hash);
                    }
                }
                Symbol::Name(s) => {
                    if name.eq_ignore_ascii_case(s) {
                        return get_forwarded_address(addr, export_dir, export_size, hash);
                    }
                }
            }
        }
    }

    null_mut()
}

/// Retrieves the base address of the `ntdll.dll` module.
#[inline(always)]
pub fn get_ntdll_address() -> *mut c_void {
    *NTDLL.call_once(|| GetModuleHandle(2788516083u32, Some(crate::hash::murmur3)) as u64) as *mut c_void
}

/// Resolves a forwarded export address from a module's export table.
///
/// # Arguments
/// 
/// * `address` - The address to check, typically obtained from the export table.
/// * `export_dir` - A pointer to the `IMAGE_EXPORT_DIRECTORY` of the module.
/// * `export_size` - The size of the export directory.
/// * `hash` - A function to hash strings, used to resolve forwarded functions by name.
///
/// # Returns
/// 
/// * A pointer (`*mut c_void`) to the resolved function, either from the forwarded module or the original address.
unsafe fn get_forwarded_address(
    address: *mut c_void,
    export_dir: *const IMAGE_EXPORT_DIRECTORY,
    export_size: usize,
    hash: fn(&str) -> u32,
) -> *mut c_void  {
    // Checks forwarder functions
    if address as usize >= export_dir as usize && (address as usize) < (export_dir as usize + export_size) {
        let cstr = unsafe { CStr::from_ptr(address as *const i8) };
        let forwarder_name = cstr.to_str().unwrap_or("");

        let mut parts = forwarder_name.splitn(2, '.');
        let module_name = parts.next().unwrap_or("");
        let function_name = parts.next().unwrap_or("");
        return GetProcAddress(LoadLibraryA(module_name), hash(function_name), Some(hash));
    }

    address
}

/// Retrieves a pointer to the Process Environment Block (PEB) of the current process.
/// 
/// # Returns
/// 
/// * Pointer to the PEB structure.
#[inline(always)]
pub fn NtCurrentPeb() -> *const PEB {
    #[cfg(target_arch = "x86_64")]
    return __readgsqword(0x60) as *const PEB;

    #[cfg(target_arch = "x86")]
    return __readfsdword(0x30) as *const PEB;

    #[cfg(target_arch = "aarch64")]
    return *(__readx18(0x60) as *const *const PEB);
}

/// Retrieves a pointer to the Thread Environment Block (TEB) of the current thread.
/// 
/// # Returns
/// 
/// * Pointer to the TEB structure.
#[inline(always)]
pub fn NtCurrentTeb() -> *const TEB {
    #[cfg(target_arch = "x86_64")]
    return __readgsqword(0x30) as *const TEB;

    #[cfg(target_arch = "x86")]
    return __readfsdword(0x18) as *const TEB;

    #[cfg(target_arch = "aarch64")]
    return *(__readx18(0x30) as *const *const TEB);
}

/// Reads a `u64` value from the GS segment at the specified offset.
/// 
/// # Arguments
/// 
/// * `offset` - The offset from the GS base where the value is located.
/// 
/// # Returns
/// 
/// * The value read from the GS segment.
#[inline(always)]
#[cfg(target_arch = "x86_64")]
pub fn __readgsqword(offset: u64) -> u64 {
    let out: u64;
    unsafe {
        core::arch::asm!(
            "mov {}, gs:[{:e}]",
            lateout(reg) out,
            in(reg) offset,
            options(nostack, pure, readonly),
        );
    }
    out
}

/// Reads a `u32` value from the FS segment at the specified offset.
/// 
/// # Arguments
/// 
/// * `offset` - The offset from the FS base where the value is located.
/// 
/// # Returns
/// 
/// * The value read from the FS segment.
#[inline(always)]
#[cfg(target_arch = "x86")]
pub unsafe fn __readfsdword(offset: u32) -> u32 {
    let out: u32;
    unsafe {
        core::arch::asm!(
            "mov {:e}, fs:[{:e}]",
            lateout(reg) out,
            in(reg) offset,
            options(nostack, pure, readonly),
        );
    }

    out
}

/// Reads a `u64` value from the x18 register at the specified offset.
///
/// # Arguments
///
/// * `offset` - The offset added to the value stored in x18.
///
/// # Returns
///
/// * The value read from x18 plus the given offset.
#[inline(always)]
#[cfg(target_arch = "aarch64")]
pub unsafe fn __readx18(offset: u64) -> u64 {
    let out: u64;
    unsafe {
        core::arch::asm!(
            "mov {}, x18",
            lateout(reg) out,
            options(nostack, pure, readonly),
        );
    }

    out + offset
}

/// Represents a symbol reference by name or hash.
///
/// Used as a generic input type to resolve loaded symbol and their exports.
pub enum Symbol<'a> {
    /// Module specified by name.
    Name(&'a str),

    /// Module specified by 32-bit hash.
    Hash(u32),
}

impl Symbol<'_> {
    /// Returns `true` if the module reference is empty.
    pub fn is_empty(&self) -> bool {
        match self {
            Symbol::Name(s) => s.is_empty(),
            Symbol::Hash(_) => false,
        }
    }
}

impl<'a> From<&'a str> for Symbol<'a> {
    fn from(s: &'a str) -> Self {
        Symbol::Name(s)
    }
}

impl From<u32> for Symbol<'_> {
    fn from(h: u32) -> Self {
        Symbol::Hash(h)
    }
}