use crate::{data::HANDLE, link};
use core::{
    ptr, ffi::c_void,
    alloc::{GlobalAlloc, Layout},
    sync::atomic::{AtomicUsize, Ordering},
};

/// A thread-safe wrapper for managing a Windows Heap.
pub struct WinHeap {
    // Store the HANDLE as a usize for atomic operations
    heap: AtomicUsize,
}

impl WinHeap {
    /// Creates a new, uninitialized `WinHeap` instance.
    ///
    /// The heap is not created until the first memory allocation is attempted.
    ///
    /// # Returns
    ///
    /// * A new instance of `WinHeap`.
    pub const fn new() -> Self {
        WinHeap {
            heap: AtomicUsize::new(0),
        }
    }

    /// Lazily initializes the heap and retrieves its handle.
    ///
    /// Uses double-checked locking to ensure only one thread creates the heap,
    /// while subsequent threads safely access the same heap handle.
    ///
    /// # Returns
    ///
    /// * A `HANDLE` to the initialized heap.
    fn heap(&self) -> HANDLE {
        let heap_ptr = self.heap.load(Ordering::Acquire);
        if heap_ptr == 0 {
            // Double-checked locking to ensure only one thread initializes
            let new_heap = unsafe { HeapCreate(0, 0, 0) };

            // Try to store the new heap; another thread might beat us to it
            let old = self
                .heap
                .compare_exchange(0, new_heap as usize, Ordering::Release, Ordering::Acquire);

            if old.is_err() {
                // Another thread initialized the heap, free our local one
                unsafe { HeapFree(new_heap, 0, ptr::null_mut()) };
            }
        }

        self.heap.load(Ordering::Acquire) as HANDLE
    }
}

unsafe impl GlobalAlloc for WinHeap {
    /// Allocates memory using the custom heap.
    ///
    /// # Arguments
    ///
    /// * `layout` - The memory layout to allocate.
    ///
    /// # Returns
    ///
    /// * A pointer to the allocated memory, or `ptr::null_mut()` if allocation fails.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let heap = self.heap();
        let size = layout.size();
        if size == 0 {
            return ptr::null_mut();
        }

        HeapAlloc(heap, 8u32, size).cast()
    }

    /// Deallocates memory using the custom heap.
    ///
    /// # Arguments
    ///
    /// * `ptr` - A pointer to the memory to deallocate.
    /// * `_` - The memory layout (ignored during deallocation).
    /// 
    /// # Notes
    /// 
    /// * If `ptr` is null, this function does nothing.
    unsafe fn dealloc(&self, ptr: *mut u8, _: Layout) {
        if ptr.is_null() {
            return;
        }
        
        let heap = self.heap();
        HeapFree(heap, 0, ptr.cast());
    }
}

/// Allows `WinHeap` to be safely shared across threads.
unsafe impl Sync for WinHeap {}

impl Drop for WinHeap {
    /// Cleans up the heap on drop.
    ///
    /// If the heap was initialized, it will be destroyed, releasing all
    /// associated memory. This ensures proper resource cleanup.
    fn drop(&mut self) {
        let heap = self.heap.load(Ordering::Acquire);
        if heap != 0 {
            unsafe { HeapDestroy(heap as HANDLE) };
        }
    }
}

// Resolution of external apis for Heap manipulation
//
// @TODO: Use NTAPI?
link!("kernel32.dll" "system" fn HeapAlloc(hheap: HANDLE, dwflags: u32, dwbytes: usize) -> *mut c_void);
link!("kernel32.dll" "system" fn HeapCreate(floptions: u32, dwinitialsize : usize, dwmaximumsize: usize) -> *mut c_void);
link!("kernel32.dll" "system" fn HeapDestroy(hheap: HANDLE) -> i32);
link!("kernel32.dll" "system" fn HeapFree(hheap: HANDLE, dwflags: u32, lpmem: *const c_void) -> i32);