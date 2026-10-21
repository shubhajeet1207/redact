//! The operating system's random source, used only to name temporary files (TRD §9.3). It never
//! affects content.

use std::io;

/// 128 random bits as 32 lower-case hex digits.
pub fn hex128() -> io::Result<String> {
    let bytes = bytes16()?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(unix)]
fn bytes16() -> io::Result<[u8; 16]> {
    use std::io::Read;
    let mut buf = [0u8; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut buf)?;
    Ok(buf)
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn bytes16() -> io::Result<[u8; 16]> {
    use windows_sys::Win32::Security::Cryptography::{
        BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
    };
    let mut buf = [0u8; 16];
    // SAFETY: `buf` is a valid writable buffer of exactly the length passed; a null algorithm
    // handle is permitted together with BCRYPT_USE_SYSTEM_PREFERRED_RNG.
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            buf.as_mut_ptr(),
            16,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status == 0 {
        Ok(buf)
    } else {
        Err(io::Error::other("system random source unavailable"))
    }
}

#[cfg(not(any(unix, windows)))]
fn bytes16() -> io::Result<[u8; 16]> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}
