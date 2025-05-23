use dinvk::{GetModuleHandle, GetProcAddress};

#[test]
fn test_modules() {
    println!("Module: {:?}", GetModuleHandle("kernel32.dll", None));
    println!("Module: {:?}", GetModuleHandle("kernel32.DLL", None));
    println!("Module: {:?}", GetModuleHandle("kernel32", None));
    println!("Module: {:?}", GetModuleHandle("KERNEL32.dll", None));
    println!("Module: {:?}", GetModuleHandle("KERNEL32", None));
}

#[test]
fn test_function() {
    let module = GetModuleHandle("KERNEL32.dll", None);
    println!("Function: {:?}", GetProcAddress(module, "VirtualAlloc", None));
}