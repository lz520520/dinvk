use dinvk::{GetModuleHandle, LdrProxy};

fn main() {
    // RtlQueueWorkItem
    LdrProxy::new("xpsservices.dll").work();

    // RtlCreateTimer
    LdrProxy::new("xpsservices.dll").timer();

    // RtlRegisterWait
    LdrProxy::new("xpsservices.dll").register_wait();

    println!("@ xpsservices.dll: {:?}", GetModuleHandle("XPSSERVICES.DLL", None));
}