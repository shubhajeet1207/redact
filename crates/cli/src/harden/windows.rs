#![allow(unsafe_code)]

use std::sync::atomic::{AtomicBool, Ordering};

use windows_sys::Win32::System::Diagnostics::Debug::{
    SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, SEM_NOOPENFILEERRORBOX, SetErrorMode,
};
use windows_sys::Win32::System::SystemServices::{
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY, PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY,
    PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY,
};
use windows_sys::Win32::System::Threading::{
    ProcessDynamicCodePolicy, ProcessExtensionPointDisablePolicy, ProcessStrictHandleCheckPolicy,
    SetProcessMitigationPolicy,
};

static APPLIED: AtomicBool = AtomicBool::new(false);

/// Suppresses error dialogs and applies the mitigation policies the OS supports. Policies the
/// OS refuses are skipped; the report records whether all of them applied.
pub fn mitigate() {
    // SAFETY: SetErrorMode takes a flag set and has no memory preconditions.
    unsafe {
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    }
    // Bit 0 of each policy's flags: ProhibitDynamicCode, DisableExtensionPoints, and
    // RaiseExceptionOnInvalidHandleReference (bit 1: HandleExceptionsPermanentlyEnabled).
    // SAFETY: each buffer is an initialized policy struct of the size passed.
    let all = unsafe {
        let mut dynamic: PROCESS_MITIGATION_DYNAMIC_CODE_POLICY = std::mem::zeroed();
        dynamic.Anonymous.Flags = 1;
        let mut extension: PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY = std::mem::zeroed();
        extension.Anonymous.Flags = 1;
        let mut handles: PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY = std::mem::zeroed();
        handles.Anonymous.Flags = 0b11;
        let a = SetProcessMitigationPolicy(
            ProcessDynamicCodePolicy,
            (&raw const dynamic).cast(),
            size_of_val(&dynamic),
        );
        let b = SetProcessMitigationPolicy(
            ProcessExtensionPointDisablePolicy,
            (&raw const extension).cast(),
            size_of_val(&extension),
        );
        let c = SetProcessMitigationPolicy(
            ProcessStrictHandleCheckPolicy,
            (&raw const handles).cast(),
            size_of_val(&handles),
        );
        a != 0 && b != 0 && c != 0
    };
    APPLIED.store(all, Ordering::Relaxed);
}

pub fn mitigations_applied() -> bool {
    APPLIED.load(Ordering::Relaxed)
}
