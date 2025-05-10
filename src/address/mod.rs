use alloc::string::{ToString, String};
use core::{
    ffi::{c_void, CStr},
    mem::transmute, 
    ptr::null_mut, 
    slice::from_raw_parts
};
use crate::{
    utils::canonicalize_module,
    hash::crc32ba, 
    wrappers::LoadLibraryA,
    data::{
        IMAGE_NT_SIGNATURE, IMAGE_DOS_HEADER,
        IMAGE_DIRECTORY_ENTRY_EXPORT, HMODULE, PEB,
        IMAGE_EXPORT_DIRECTORY, IMAGE_NT_HEADERS,
        LDR_DATA_TABLE_ENTRY
    }, 
};

/// Retrieves the handle of a module loaded into memory based on the module name or a numeric hash.
///
/// # Arguments
/// 
/// * `module` - It can be a DLL name (`&str` or `String`) or a numeric hash (`u32`). The function detects
/// automatically the type and performs the appropriate comparison.
/// * `hash` - An optional function that converts a `&str` into a `u32`,  
///   used when searching by numeric hash.
/// 
/// # Returns
/// 
/// * The address of the module if found.
pub fn GetModuleHandle<T>(module: T, hash: Option<fn(&str) -> u32>) -> HMODULE
where 
    T: ToString
{
    unsafe {
        let hash = hash.unwrap_or(crc32ba);
        let peb = NtCurrentPeb();
        let ldr_data = (*peb).Ldr;
        let mut data_table_entry = (*ldr_data).InMemoryOrderModuleList.Flink as *const LDR_DATA_TABLE_ENTRY;
        let mut list_node = (*ldr_data).InMemoryOrderModuleList.Flink;

        if module.to_string().is_empty() {
            return (*peb).ImageBaseAddress;
        }

        // Save a reference to the head nod for the list
        let head_node = list_node;
        while !(*data_table_entry).FullDllName.Buffer.is_null() {
            if (*data_table_entry).FullDllName.Length != 0 {
                // Converts the buffer from UTF-16 to a `String`
                let buffer = from_raw_parts(
                    (*data_table_entry).FullDllName.Buffer, 
                    ((*data_table_entry).FullDllName.Length / 2) as usize
                );
            
                // Try interpreting `module` as a numeric hash (u32)
                let mut dll_file_name = String::from_utf16_lossy(buffer).to_uppercase();
                if let Ok(dll_hash) = module.to_string().parse::<u32>() {
                    if dll_hash == hash(&dll_file_name) {
                        return (*data_table_entry).Reserved2[0];
                    }
                } else {
                    // If it is not an `u32`, it is treated as a string
                    let module = canonicalize_module(&module.to_string());
                    dll_file_name = canonicalize_module(&dll_file_name);
                    if dll_file_name == module {
                        return (*data_table_entry).Reserved2[0];
                    }
                }
            }

            // Moves to the next node in the list of modules
            list_node = (*list_node).Flink;

            // Break out of loop if all of the nodes have been checked
            if list_node == head_node {
                break
            }

            data_table_entry = list_node as *const LDR_DATA_TABLE_ENTRY
        }
    }

    null_mut()
}

/// Retrieves the base address of the `ntdll.dll` module.
///
/// This function accesses the Process Environment Block (PEB) and traverses
/// the loader data structures to locate the base address of `ntdll.dll`.
/// 
/// # Returns
///
/// * A pointer to the base address of the `ntdll.dll` module.
pub fn get_ntdll_address() -> *mut c_void {
    unsafe {
        let peb = NtCurrentPeb();
        let ldr_data = ((*(*(*peb).Ldr).InMemoryOrderModuleList.Flink).Flink as *const u8)
            .offset(if cfg!(any(target_arch = "x86_64", target_arch = "aarch64")) { -0x10 } else { -0x08 }) 
            as *const LDR_DATA_TABLE_ENTRY;
        
        (*ldr_data).DllBase.cast::<c_void>()
    }
}

/// Retrieves the address of an exported function or variable from the specified module.
/// 
/// # Arguments
/// 
/// * `h_module` - Handle to the module that contains the desired function or variable.
/// * `function` - The function name hash, its ordinal, or a string representing the function name.
/// * `hash` - An optional function that computes a `u32` hash from a `&str`, used for name-based resolution.
/// 
/// # Returns
/// 
/// * The address of the exported function if found.
/// 
/// # Notes
/// 
/// - Supports resolving functions by both **name**, **ordinal** and **hash**.
/// - Handles forwarded exports by recursively resolving the function in the forwarding module.
/// 
/// # Examples
/// 
/// * Import By Name
/// ```rust,ignore
/// use dinvk::{GetModuleHandle, GetProcAddress};
/// 
/// let h_module = GetModuleHandle("NTDLL.DLL", None);
/// let address = GetProcAddress(h_module, "NtProtectVirtualMemory", None);
/// ```
///
/// * Import By Hash
/// ```rust,ignore
/// use dinvk::hash::jenkins;
/// use dinvk::{GetModuleHandle, GetProcAddress};
/// 
/// let h_module = GetModuleHandle(3547223233u32, Some(jenkins));
/// let address = GetProcAddress(h_module, 2193297120u32, Some(jenkins));
/// ```
/// 
/// * Import By Ordinal
/// ```rust,ignore
/// use dinvk::{GetModuleHandle, GetProcAddress};
/// 
/// let h_module = GetModuleHandle("NTDLL.DLL", None);
/// let address = GetProcAddress(h_module, 473, None);
/// ```
pub fn GetProcAddress<T>(h_module: HMODULE, function: T, hash: Option<fn(&str) -> u32>) -> *mut c_void
where 
    T: ToString,
{
    if h_module.is_null() {
        return null_mut();
    }

    unsafe {
        let h_module = h_module as usize;
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

        // Convert Api name to String
        let api_name = function.to_string();

        // Import By Ordinal
        if let Ok(ordinal) = api_name.parse::<u32>() {
            if ordinal <= 0xFFFF {
                let ordinal = ordinal & 0xFFFF;
                if ordinal < (*export_dir).Base || (ordinal >= (*export_dir).Base + (*export_dir).NumberOfFunctions) {
                    return null_mut();
                }

                return transmute(h_module + functions[ordinal as usize - (*export_dir).Base as usize] as usize);
            }
        }

        // Import By Name or Hash
        let hash = hash.unwrap_or(crc32ba);
        for i in 0..(*export_dir).NumberOfNames as usize {
            let name = CStr::from_ptr((h_module + names[i] as usize) as *const i8)
                .to_str()
                .unwrap_or("");
            
            let ordinal = ordinals[i] as usize;
            let address = (h_module + functions[ordinal] as usize) as *mut c_void;
            if let Ok(api_hash) = api_name.parse::<u32>() {
                // Comparison by hash
                if hash(name) == api_hash {
                    return get_forwarded_address(address, export_dir, export_size, hash);
                }
            } else {
                // Comparison by String
                if name == api_name {
                    return get_forwarded_address(address, export_dir, export_size, hash);
                }
            }
        }
    }

    null_mut()
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
) -> *mut c_void 
{
    // Checks forwarder functions
    if address as usize >= export_dir as usize && (address as usize) < (export_dir as usize + export_size) {
        let cstr = CStr::from_ptr(address as *const i8);
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
    unsafe {
        #[cfg(target_arch = "x86_64")]
        return __readgsqword(0x60) as *const PEB;

        #[cfg(target_arch = "x86")]
        return __readfsdword(0x30) as *const PEB;

        #[cfg(target_arch = "aarch64")]
        return *(__readx18(0x60) as *const *const PEB);
    }
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
pub unsafe fn __readgsqword(offset: u64) -> u64 {
    let out: u64;
    core::arch::asm!(
        "mov {}, gs:[{:e}]",
        lateout(reg) out,
        in(reg) offset,
        options(nostack, pure, readonly),
    );
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
    core::arch::asm!(
        "mov {:e}, fs:[{:e}]",
        lateout(reg) out,
        in(reg) offset,
        options(nostack, pure, readonly),
    );
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
    core::arch::asm!(
        "mov {}, x18",
        lateout(reg) out,
        options(nostack, pure, readonly),
    );
    out + offset
}