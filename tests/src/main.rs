use dinvk::GetModuleHandle;

#[test]
fn test_modules() {
    println!("{:?}", GetModuleHandle("kernel32.dll", None));
    println!("{:?}", GetModuleHandle("kernel32.DLL", None));
    println!("{:?}", GetModuleHandle("kernel32", None));
    println!("{:?}", GetModuleHandle("KERNEL32.dll", None));
    println!("{:?}", GetModuleHandle("KERNEL32", None));
}