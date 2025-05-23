use obfstr::obfstr as s;
use crate::{
    data::*, dinvoke, 
    get_ntdll_address
};
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
        let new_heap = dinvoke!(
            get_ntdll_address(),
            s!("RtlCreateHeap"),
            RtlCreateHeap,
            0,
            null_mut(),
            0,
            0,
            null_mut(),
            null_mut()
        )
        .unwrap_or(null_mut());

        // Try to store the new heap; another thread might beat us to it
        let old = self.heap
            .compare_exchange(0, new_heap as usize, Ordering::Release, Ordering::Acquire);

        if old.is_ok() {
            new_heap
        } else {
            self.heap.load(Ordering::Acquire) as HANDLE
        }
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
        dinvoke!(
            get_ntdll_address(),
            s!("RtlAllocateHeap"),
            RtlAllocateHeap,
            heap,
            0,
            layout.size()
        )
        .unwrap_or(null_mut()) as *mut u8
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
        
        dinvoke!(
            get_ntdll_address(),
            s!("RtlFreeHeap"),
            RtlFreeHeap,
            self.heap(),
            0,
            ptr as *mut c_void
        );
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
            let _ = dinvoke!(
                get_ntdll_address(),
                s!("RtlDestroyHeap"),
                RtlDestroyHeap,
                heap as *mut c_void
            );
        }
    }
}
