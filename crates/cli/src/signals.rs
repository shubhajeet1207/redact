//! Interruption (TRD §9.4). SIGINT, SIGTERM, and Ctrl+C only record which signal arrived; the
//! main loop checks between chunks, removes temporary files, and exits with 130 or 143. Handlers
//! do nothing but an atomic store, which is async-signal-safe.
#![allow(unsafe_code)]

use std::sync::atomic::{AtomicI32, Ordering};

static PENDING: AtomicI32 = AtomicI32::new(0);

/// The signal that interrupted the run, if any: 2 (SIGINT, Ctrl+C) or 15 (SIGTERM).
pub fn pending() -> Option<i32> {
    match PENDING.load(Ordering::Relaxed) {
        0 => None,
        s => Some(s),
    }
}

#[cfg(unix)]
extern "C" fn on_signal(signal: libc::c_int) {
    PENDING.store(signal, Ordering::Relaxed);
}

#[cfg(unix)]
pub fn install() {
    for signal in [libc::SIGINT, libc::SIGTERM] {
        // SAFETY: `action` is fully initialized before use: zeroed, then the handler and an
        // empty mask are set. No SA_RESTART, so a blocking read returns EINTR and the main loop
        // can notice the flag. The handler only performs an atomic store.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as usize;
            libc::sigemptyset(&mut action.sa_mask);
            action.sa_flags = 0;
            libc::sigaction(signal, &action, std::ptr::null_mut());
        }
    }
}

#[cfg(windows)]
unsafe extern "system" fn on_console(ctrl: u32) -> windows_sys::core::BOOL {
    use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, CTRL_C_EVENT};
    let signal = if ctrl == CTRL_C_EVENT || ctrl == CTRL_BREAK_EVENT {
        crate::error::SIGINT
    } else {
        crate::error::SIGTERM
    };
    PENDING.store(signal, Ordering::Relaxed);
    1
}

#[cfg(windows)]
pub fn install() {
    // SAFETY: `on_console` matches PHANDLER_ROUTINE and stays valid for the process lifetime.
    unsafe {
        windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(on_console), 1);
    }
}

#[cfg(not(any(unix, windows)))]
pub fn install() {}
