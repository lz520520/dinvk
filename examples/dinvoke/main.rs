#![allow(unused)]

use dinvk::{data::HeapAlloc, dinvoke, get_peb, GetModuleHandle};

const HEAP_ZERO_MEMORY: u32 = 8u32;

fn main() {
    let peb = get_peb();
    let kernel32 = GetModuleHandle("KERNEL32.DLL", None);
    let addr = dinvoke!(
        kernel32,
        "HeapAlloc",
        HeapAlloc,
        (*peb).ProcessHeap,
        HEAP_ZERO_MEMORY,
        0x200
    );
    
    println!("@ Address: {:?}", addr);
}