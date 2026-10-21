//! Process hardening (TRD §9.8), applied before any input is read.
//!
//! - `early`: core dumps off (Unix), not dumpable (Linux), error dialogs suppressed and process
//!   mitigation policies applied (Windows), and a panic hook that prints a fixed message, removes
//!   temporary files, and exits 1 without printing the payload.
//! - `sandbox`: after every handle is open, a seccomp filter on Linux denies network and
//!   process-creation syscalls.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

pub fn early() {
    std::panic::set_hook(Box::new(|_info| {
        // The payload may contain data, so it is never printed.
        crate::atomic::remove_all_temps();
        eprintln!("spymonk-redact: internal error (INTERNAL_ERROR)");
        std::process::exit(1);
    }));
    #[cfg(unix)]
    unix::no_core_dumps();
    #[cfg(target_os = "linux")]
    linux::not_dumpable();
    #[cfg(windows)]
    windows::mitigate();
}

/// Applies the syscall filter where the platform has one. Returns the report's `sandbox` value.
pub fn sandbox() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        if linux::seccomp() { "seccomp" } else { "none" }
    }
    #[cfg(windows)]
    {
        if windows::mitigations_applied() {
            "process-mitigations"
        } else {
            "none"
        }
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        "none"
    }
}

/// `--probe-sandbox` (feature `sandbox-probe`): reports the hardening state the tests assert.
#[cfg(feature = "sandbox-probe")]
pub fn probe() -> String {
    #[cfg(target_os = "linux")]
    {
        linux::probe()
    }
    #[cfg(not(target_os = "linux"))]
    {
        String::from("probe unsupported\n")
    }
}
