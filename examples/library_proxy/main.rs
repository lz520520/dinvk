use dinvk::{GetModuleHandle, LdrProxy};
use std::{thread, time::Duration};

fn main() {
    // RtlQueueWorkItem
    LdrProxy::new("xpsservices.dll").work();

    // RtlCreateTimer
    LdrProxy::new("xpsservices.dll").timer();

    // RtlRegisterWait
    LdrProxy::new("xpsservices.dll").register_wait();

    thread::sleep(Duration::from_secs(2));

    println!("@ xpsservices.dll: {:?}", GetModuleHandle("XPSSERVICES.DLL", None));
}