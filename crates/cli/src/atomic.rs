//! Atomic output (TRD §9.3): checks before any input is read, a private create-new temporary
//! file in the target's directory, and flush, sync, rename, and directory sync on success. The
//! temporary file is removed on every failure path, including panics.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::error::{Code, Failure};
use crate::io::{FileId, path_id};
use crate::osrand;

/// Temporary files that exist right now, for the panic hook and signal paths.
static TEMPS: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

/// Removes every registered temporary file. Safe to call from the panic hook.
pub fn remove_all_temps() {
    if let Ok(mut temps) = TEMPS.try_lock() {
        for path in temps.drain(..) {
            let _ = fs::remove_file(path);
        }
    }
}

fn register(path: &Path) {
    if let Ok(mut temps) = TEMPS.lock() {
        temps.push(path.to_path_buf());
    }
}

fn unregister(path: &Path) {
    if let Ok(mut temps) = TEMPS.lock() {
        temps.retain(|p| p != path);
    }
}

/// An output under construction: a temporary file that becomes `target` on `commit`.
#[derive(Debug)]
pub struct Pending {
    target: PathBuf,
    temp: PathBuf,
    file: Option<File>,
}

/// Checks `target` and creates its temporary file. `input` is the input's identity, if known.
pub fn prepare(target: &Path, input: Option<FileId>) -> Result<Pending, Failure> {
    check_target(target, input)?;
    let write_failed = Failure::new(Code::OutputWriteFailed);
    let name = target
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or(write_failed)?;
    let dir = match target.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let temp = dir.join(format!(
        ".{name}.{}.tmp",
        osrand::hex128().map_err(|_| write_failed)?
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(&temp).map_err(|_| write_failed)?;
    register(&temp);
    Ok(Pending {
        target: target.to_path_buf(),
        temp,
        file: Some(file),
    })
}

/// Same-file refusal first (identity, so hard links and other spellings are caught), then the
/// regular-file requirement (a symbolic link is never a valid target).
fn check_target(target: &Path, input: Option<FileId>) -> Result<(), Failure> {
    let meta = match fs::symlink_metadata(target) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(Failure::new(Code::OutputWriteFailed)),
    };
    if let Some(input) = input
        && path_id(target).ok() == Some(input)
    {
        return Err(Failure::new(Code::OutputIsInput));
    }
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(Failure::new(Code::OutputNotRegular));
    }
    Ok(())
}

impl Pending {
    pub fn writer(&mut self) -> Option<&mut File> {
        self.file.as_mut()
    }

    /// Flushes, syncs, renames over the target, and (Unix) syncs the directory.
    pub fn commit(mut self) -> Result<(), Failure> {
        let failed = Failure::new(Code::OutputWriteFailed);
        let mut file = self.file.take().ok_or(failed)?;
        file.flush().map_err(|_| failed)?;
        file.sync_all().map_err(|_| failed)?;
        drop(file);
        fs::rename(&self.temp, &self.target).map_err(|_| failed)?;
        unregister(&self.temp);
        #[cfg(unix)]
        {
            let dir = match self.target.parent() {
                Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
                _ => PathBuf::from("."),
            };
            if let Ok(d) = File::open(dir) {
                let _ = d.sync_all();
            }
        }
        // Mark as committed so Drop leaves the (now renamed) path alone.
        self.temp = PathBuf::new();
        Ok(())
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        drop(self.file.take());
        if !self.temp.as_os_str().is_empty() {
            let _ = fs::remove_file(&self.temp);
            unregister(&self.temp);
        }
    }
}
