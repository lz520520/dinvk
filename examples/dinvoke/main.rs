use dinvk::{
    data::HeapAllocFn, 
    dinvoke, GetModuleHandle,
    GetProcessHeap
};

const HEAP_ZERO_MEMORY: u32 = 8u32;

fn main() {
    let kernel32 = GetModuleHandle("KERNEL32.DLL", None);
    let addr = dinvoke!(
        kernel32,
        "HeapAlloc",
        HeapAllocFn,
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        0x200
    );
    
    println!("[+] Address: {:?}", addr);
}