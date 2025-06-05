use crate::{data::*, link};
use core::{
    ptr::null_mut, ffi::c_void,
    alloc::{GlobalAlloc, Layout},
    sync::atomic::{AtomicUsize, Ordering},
};

/// A thread-safe wrapper for managing a Windows Heap.
pub struct WinHeap {
    // Store the HANDLE as a usize for atomic operations
    heap: AtomicUsize,
}

/// Allows `WinHeap` to be safely shared across threads.
unsafe impl Sync for WinHeap {}

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
        let current = self.heap.load(Ordering::Acquire);
        if current != 0 {
            return current as HANDLE;
        }

        // Double-checked locking to ensure only one thread initializes
        let new_heap = unsafe {
            RtlCreateHeap(
                0,
                null_mut(),
                0,
                0,
                null_mut(),
                null_mut()
            )
        };

        // Try to store the new heap; another thread might beat us to it
        _ = self.heap.compare_exchange(0, new_heap as usize, Ordering::Release, Ordering::Acquire);
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
            return null_mut();
        }

        // Another thread initialized the heap, free our local one
        unsafe {
            RtlAllocateHeap(
                heap,
                0,
                size
            ) as *mut u8
        }
    }

    /// Deallocates memory using the custom heap.
    ///
    /// # Arguments
    ///
    /// * `ptr` - A pointer to the memory to deallocate.
    /// * `layout` - The memory layout.
    /// 
    /// # Notes
    /// 
    /// * If `ptr` is null, this function does nothing.
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() {
            return;
        }
    
        unsafe { core::ptr::write_bytes(ptr, 0, layout.size()) };
        unsafe { RtlFreeHeap(self.heap(), 0, ptr.cast()); }
    }
}

link!("ntdll.dll" "system" fn RtlFreeHeap(heap: HANDLE, flags: u32, ptr: *mut c_void) -> i8);
link!("ntdll.dll" "system" fn RtlAllocateHeap(heap: HANDLE, flags: u32, size: usize) -> *mut c_void);
link!("ntdll.dll" "system" fn RtlCreateHeap(flags: u32, base: *mut c_void, reserve: usize, commit: usize, lock: *mut c_void, param: *mut c_void) -> HANDLE);