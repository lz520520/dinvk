use obfstr::obfstr as s;
use core::{ffi::c_void, ptr::null_mut};
use crate::{
    data::*, dinvoke, get_ntdll_address, 
    GetModuleHandle, GetProcAddress 
};

/// A helper struct to interact with dynamic module loading with Windows APIs via Proxy.
///
/// The `LdrProxy` struct provides methods to queue work items and manage operations
/// involving dynamic libraries using Windows APIs.
pub struct LdrProxy<'a> {
    /// The name of the module to be loaded or operated on.
    pub module: &'a str
}

impl<'a> LdrProxy<'a> {
    /// Creates a new `Loader` instance for a given module.
    ///
    /// # Arguments
    /// 
    /// * `module` - The name of the module (e.g., `"kernel32.dll"`) to be handled by this loader.
    ///
    /// # Return
    /// 
    /// * A new instance of the `LdrProxy` struct.
    pub fn new(module: &'a str) -> Self {
        Self { module }
    }

    /// Queues a work item to load the specified module asynchronously.
    ///
    /// This method wraps the `RtlQueueWorkItem` Windows API, dynamically resolving
    /// the function and scheduling the specified module to be loaded.
    ///
    /// # Returns
    /// 
    /// * `Some(NTSTATUS)` - Status code returned by the `RtlQueueWorkItem` API if successful.
    /// * `None` - If the function or module cannot be resolved.
    pub fn work(&self) -> Option<NTSTATUS> {
        let ntdll = get_ntdll_address();
        let kernel32 = GetModuleHandle(s!("KERNEL32.DLL"), None);
        let load_library = GetProcAddress(kernel32, s!("LoadLibraryA"), None);
        let mut module_bytes = self.module.as_bytes().to_vec();
        module_bytes.push(0);

        let module = unsafe { core::ffi::CStr::from_bytes_with_nul_unchecked(&module_bytes) };
        Some(dinvoke!(
            ntdll,
            s!("RtlQueueWorkItem"),
            RtlQueueWorkItem,
            core::mem::transmute(load_library),
            module.as_ptr() as *mut c_void,
            0x00000000
        )?)
    }

    /// Schedules a timer to execute the loading of the specified module.
    ///
    /// This method uses the `RtlCreateTimer` API to create a timer queue
    /// and schedule the execution of the `LoadLibraryA` function.
    ///
    /// # Returns
    /// 
    /// * `Some(NTSTATUS)` - Status code returned by the `RtlCreateTimer` API if successful.
    /// * `None` - If the function or module cannot be resolved.
    pub fn timer(&self) -> Option<NTSTATUS> {
        let ntdll = get_ntdll_address();
        let kernel32 = GetModuleHandle(s!("KERNEL32.DLL"), None);
        let load_library = GetProcAddress(kernel32, s!("LoadLibraryA"), None);
        
        // Create a timer queue
        let mut queue = null_mut();
        let status = dinvoke!(ntdll, s!("RtlCreateTimerQueue"), RtlCreateTimerQueue, &mut queue)?;
        if !NT_SUCCESS(status) {
            return None;
        }

        // Create a timer and associate it with the module loading function
        let mut h_timer = null_mut();
        let mut module_bytes = self.module.as_bytes().to_vec();
        module_bytes.push(0);

        let module = unsafe { core::ffi::CStr::from_bytes_with_nul_unchecked(&module_bytes) };
        Some(dinvoke!(
            ntdll,
            s!("RtlCreateTimer"),
            RtlCreateTimer,
            queue,
            &mut h_timer,
            core::mem::transmute(load_library),
            module.as_ptr() as *mut c_void,
            0,
            0,
            WT_EXECUTEINTIMERTHREAD
        )?)
    }

    /// Registers a wait event to execute the loading of the specified module.
    ///
    /// This method uses the `RtlRegisterWait` API to register an event-based
    /// callback that triggers the execution of the `LoadLibraryA` function.
    /// 
    /// * `Some(NTSTATUS)` - Status code returned by the `RtlRegisterWait` API if successful.
    /// * `None` - If the function or module cannot be resolved.
    pub fn register_wait(&self) -> Option<NTSTATUS> {
        let ntdll = get_ntdll_address();
        let kernel32 = GetModuleHandle(s!("KERNEL32.DLL"), None);
        let load_library = GetProcAddress(kernel32, s!("LoadLibraryA"), None);
    
        // Create an event handle
        let mut h_event = null_mut();
        let status = dinvoke!(ntdll, s!("NtCreateEvent"), NtCreateEvent, &mut h_event, EVENT_ALL_ACCESS, null_mut(), EVENT_TYPE::SynchronizationEvent, 0)?;
        if !NT_SUCCESS(status) {
            return None;
        }

        // Register a wait event associated with the module loading function
        let mut h_timer = null_mut();
        let mut module_bytes = self.module.as_bytes().to_vec();
        module_bytes.push(0);

        let module = unsafe { core::ffi::CStr::from_bytes_with_nul_unchecked(&module_bytes) };
        Some(dinvoke!(
            ntdll,
            s!("RtlRegisterWait"),
            RtlRegisterWait,
            &mut h_timer,
            h_event,
            load_library,
            module.as_ptr() as *mut c_void,
            0,
            WT_EXECUTEONLYONCE | WT_EXECUTEINWAITTHREAD
        )?)
    }
}

