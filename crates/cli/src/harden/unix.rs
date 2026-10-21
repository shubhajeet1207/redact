#![allow(unsafe_code)]

/// `setrlimit(RLIMIT_CORE, 0)`: a crash leaves no core file containing input.
pub fn no_core_dumps() {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid, initialized rlimit; the call has no other preconditions.
    unsafe {
        libc::setrlimit(libc::RLIMIT_CORE, &limit);
    }
}
