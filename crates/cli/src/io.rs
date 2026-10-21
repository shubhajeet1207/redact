//! Input handling (TRD §9.2) and file identity. A file operand is opened read-only and its type
//! is checked through the open handle, so the check and the open refer to the same file.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use crate::error::{Code, Failure};

/// A file's identity: device and inode on Unix; volume serial number and file index on Windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileId(u64, u64);

pub enum Input {
    File(File),
    Stdin(io::Stdin),
}

impl std::fmt::Debug for Input {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Input::File(_) => "Input::File",
            Input::Stdin(_) => "Input::Stdin",
        })
    }
}

impl Read for Input {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Input::File(f) => f.read(buf),
            Input::Stdin(s) => s.read(buf),
        }
    }
}

/// Opens the input. Returns the reader and, when the input is a regular file, its identity.
pub fn open_input(path: Option<&Path>) -> Result<(Input, Option<FileId>), Failure> {
    let failed = Failure::new(Code::InputReadFailed);
    match path {
        Some(path) => {
            let file = open_no_block(path).map_err(|_| failed)?;
            let meta = file.metadata().map_err(|_| failed)?;
            if !meta.is_file() {
                return Err(failed);
            }
            let id = file_id(&file).ok();
            Ok((Input::File(file), id))
        }
        None => Ok((Input::Stdin(io::stdin()), stdin_id())),
    }
}

/// Opens read-only without blocking on FIFOs (Unix), so the type check can reject them.
fn open_no_block(path: &Path) -> io::Result<File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    options.open(path)
}

/// Opens an existing path only to learn its identity. Links are followed, so a link to the
/// input is recognized as the input.
pub fn path_id(path: &Path) -> io::Result<FileId> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Identity only: no read access is needed, and directories need backup semantics.
        options.access_mode(0);
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS);
    }
    let file = options.open(path)?;
    file_id(&file)
}

fn stdin_id() -> Option<FileId> {
    #[cfg(unix)]
    {
        use std::os::fd::AsFd;
        let fd = io::stdin().as_fd().try_clone_to_owned().ok()?;
        let file = File::from(fd);
        let meta = file.metadata().ok()?;
        meta.is_file().then(|| file_id(&file).ok()).flatten()
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsHandle;
        let handle = io::stdin().as_handle().try_clone_to_owned().ok()?;
        let file = File::from(handle);
        let meta = file.metadata().ok()?;
        meta.is_file().then(|| file_id(&file).ok()).flatten()
    }
    #[cfg(not(any(unix, windows)))]
    {
        None
    }
}

#[cfg(unix)]
pub fn file_id(file: &File) -> io::Result<FileId> {
    use std::os::unix::fs::MetadataExt;
    let meta = file.metadata()?;
    Ok(FileId(meta.dev(), meta.ino()))
}

#[cfg(windows)]
#[allow(unsafe_code)]
pub fn file_id(file: &File) -> io::Result<FileId> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    // SAFETY: an all-zero BY_HANDLE_FILE_INFORMATION is a valid value of this plain C struct.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: the handle is owned by `file` and open for the duration of the call; `info` is a
    // valid, writable buffer of the type the function expects.
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let index = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
    Ok(FileId(u64::from(info.dwVolumeSerialNumber), index))
}

#[cfg(not(any(unix, windows)))]
pub fn file_id(_file: &File) -> io::Result<FileId> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}
