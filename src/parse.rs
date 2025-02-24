use core::{ffi::{c_void, CStr}, slice::from_raw_parts};
use alloc::collections::btree_map::BTreeMap;
use crate::data::{
    IMAGE_DOS_HEADER, 
    IMAGE_EXPORT_DIRECTORY, 
    IMAGE_NT_HEADERS, 
    IMAGE_NT_SIGNATURE
};

/// Maps exported function addresses to their respective names.
type Functions<'a> = BTreeMap<usize, &'a str>;

/// Retrieves the export directory from a loaded module.
///
/// # Arguments
///
/// * `module` - A pointer to the module base address.
///
/// # Returns
///
/// * `Some(*const IMAGE_EXPORT_DIRECTORY)` if the export directory is found.
/// * `None` if the module is invalid or does not contain an export directory.
pub fn get_export_directory(module: *mut c_void) -> Option<*const IMAGE_EXPORT_DIRECTORY> {
    unsafe {
        let nt_header = (module as usize + (*(module as *const IMAGE_DOS_HEADER)).e_lfanew as usize) 
            as *const IMAGE_NT_HEADERS;

        if (*nt_header).Signature != IMAGE_NT_SIGNATURE {
            return None;
        }

        let data_directory = (*nt_header).OptionalHeader.DataDirectory[0];
        Some((module as usize + data_directory.VirtualAddress as usize) as *const IMAGE_EXPORT_DIRECTORY)
    }
}

/// Retrieves the NT header from a loaded module.
///
/// # Arguments
///
/// * `module` - A pointer to the module base address.
///
/// # Returns
///
/// * `Some(*const IMAGE_NT_HEADERS)` if the NT header is valid.
/// * `None` if the module is invalid.
pub fn get_nt_header(module: *mut c_void) -> Option<*const IMAGE_NT_HEADERS> {
    unsafe {
        let nt_header = (module as usize + (*(module as *const IMAGE_DOS_HEADER)).e_lfanew as usize) 
            as *const IMAGE_NT_HEADERS;

        if (*nt_header).Signature != IMAGE_NT_SIGNATURE {
            return None;
        }

        Some(nt_header)
    }
}

/// Retrieves the function export address table (EAT) from a module.
///
/// # Arguments
///
/// * `module` - A pointer to the module base address.
///
/// # Returns
///
/// * `Some(Functions<'static>)` if function exports are found.
/// * `None` if the module does not export any functions.
pub fn get_functions_eat(module: *mut c_void) -> Option<Functions<'static>> {
    unsafe {
        // Get the export directory and hash the module
        let export_dir = get_export_directory(module)?;
        let module = module as usize;
        
        // Retrieve function names
        let names = from_raw_parts(
            (module + (*export_dir).AddressOfNames as usize) as *const u32, 
            (*export_dir).NumberOfNames as usize
        );

        // Retrieve function addresses
        let functions = from_raw_parts(
            (module + (*export_dir).AddressOfFunctions as usize) as *const u32, 
            (*export_dir).NumberOfFunctions as usize
        );

        // Retrieve function ordinals
        let ordinals = from_raw_parts(
            (module + (*export_dir).AddressOfNameOrdinals as usize) as *const u16, 
            (*export_dir).NumberOfNames as usize
        );

        let mut apis = Functions::new(); 
        for i in 0..(*export_dir).NumberOfNames as isize {
            let ordinal = ordinals[i as usize] as usize;
            let address = (module + functions[ordinal] as usize) as usize;
            let name = CStr::from_ptr((module + names[i as usize] as usize) as *const i8)
                .to_str()
                .unwrap_or("");

            apis.insert(address, name);
        }
    
        Some(apis)
    }
}
