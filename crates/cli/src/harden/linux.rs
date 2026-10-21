#![allow(unsafe_code)]

use std::collections::BTreeMap;

use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule, TargetArch};

/// `prctl(PR_SET_DUMPABLE, 0)`: no core dumps and no same-user ptrace attachment.
pub fn not_dumpable() {
    // SAFETY: PR_SET_DUMPABLE takes one integer argument; the extra arguments are ignored.
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
}

/// Network and process-creation syscalls, answered with EPERM once the filter is installed.
const DENIED: &[libc::c_long] = &[
    libc::SYS_socket,
    libc::SYS_socketpair,
    libc::SYS_connect,
    libc::SYS_bind,
    libc::SYS_listen,
    libc::SYS_accept,
    libc::SYS_accept4,
    libc::SYS_sendto,
    libc::SYS_sendmsg,
    libc::SYS_sendmmsg,
    libc::SYS_execve,
    libc::SYS_execveat,
    libc::SYS_ptrace,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
];

/// Installs the deny filter. Returns false when the architecture or kernel refuses it; the run
/// then continues and the report says `"sandbox": "none"`.
pub fn seccomp() -> bool {
    let Ok(arch) = TargetArch::try_from(std::env::consts::ARCH) else {
        return false;
    };
    // `c_long` is 32 bits on some targets, so the conversion is not always a no-op.
    #[allow(clippy::useless_conversion)]
    let rules: BTreeMap<i64, Vec<SeccompRule>> = DENIED
        .iter()
        .map(|&nr| (i64::from(nr), Vec::new()))
        .collect();
    let Ok(filter) = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        arch,
    ) else {
        return false;
    };
    let Ok(program) = BpfProgram::try_from(filter) else {
        return false;
    };
    seccompiler::apply_filter(&program).is_ok()
}

/// The hardening state, for the Linux hardening test only.
#[cfg(feature = "sandbox-probe")]
pub fn probe() -> String {
    // SAFETY: plain syscalls with valid arguments; the socket, if one were created, is closed.
    let (dumpable, socket_errno, core) = unsafe {
        let dumpable = libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0);
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        let errno = if fd < 0 {
            *libc::__errno_location()
        } else {
            libc::close(fd);
            0
        };
        let mut limit = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        libc::getrlimit(libc::RLIMIT_CORE, &mut limit);
        (dumpable, errno, limit.rlim_cur)
    };
    format!(
        "dumpable={dumpable} core={core} socket={}\n",
        if socket_errno == libc::EPERM {
            "EPERM"
        } else {
            "ALLOWED"
        }
    )
}
