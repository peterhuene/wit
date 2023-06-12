use crate::{
    config::DEFAULT_REGISTRY_NAME,
    resolver::{DependencyResolution, DependencyResolutionMap},
};
use anyhow::{anyhow, bail, Context, Result};
use colored::Colorize;
use semver::Version;
use serde::{de::IntoDeserializer, Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use toml_edit::{Document, Item, Value};
use warg_crypto::hash::AnyHash;
use warg_protocol::registry::PackageId;

/// The name of the lock file.
const LOCK_FILE_NAME: &str = "wit.lock";
/// The file format version of the lock file.
const LOCK_FILE_VERSION: i64 = 1;

/// Represents a locked package in a lock file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub struct LockedPackage {
    /// The id of the locked package.
    pub id: PackageId,
    /// The registry the package was resolved from.
    ///
    /// Defaults to the default registry if not specified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry: Option<String>,
    /// The locked versions of a package.
    ///
    /// A package may have multiple locked versions if more than one
    /// version requirement was specified for the package in `wit.toml`.
    #[serde(rename = "version", default, skip_serializing_if = "Vec::is_empty")]
    pub versions: Vec<LockedPackageVersion>,
}

impl LockedPackage {
    /// The key used in sorting and searching the package list.
    pub(crate) fn key(&self) -> (&PackageId, &str) {
        (
            &self.id,
            self.registry.as_deref().unwrap_or(DEFAULT_REGISTRY_NAME),
        )
    }
}

/// Represents version information for a locked package.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LockedPackageVersion {
    /// The version requirement used to resolve this version.
    pub requirement: String,
    /// The version the package is locked to.
    pub version: Version,
    /// The digest of the package contents.
    pub digest: AnyHash,
}

impl LockedPackageVersion {
    pub(crate) fn key(&self) -> &str {
        &self.requirement
    }
}

/// Represents a resolved dependency lock file.
///
/// This is a TOML file that contains the resolved dependency information from
/// a previous build.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct LockFile {
    /// The version of the lock file.
    ///
    /// Currently this is always `1`.
    pub version: i64,
    /// The locked dependencies in the lock file.
    ///
    /// This list is sorted by the key of the locked package.
    #[serde(rename = "package", default, skip_serializing_if = "Vec::is_empty")]
    pub packages: Vec<LockedPackage>,
}

impl LockFile {
    /// Constructs a `LockFile` from a `DependencyResolutionMap`.
    pub fn from_resolution(map: &DependencyResolutionMap) -> Self {
        type PackageKey = (PackageId, Option<String>);
        type VersionsMap = HashMap<String, (Version, AnyHash)>;
        let mut packages: HashMap<PackageKey, VersionsMap> = HashMap::new();

        for resolution in map.values() {
            match resolution.key() {
                Some((id, registry)) => {
                    let pkg = match resolution {
                        DependencyResolution::Registry(pkg) => pkg,
                        DependencyResolution::Local(_) => unreachable!(),
                    };

                    let prev = packages
                        .entry((id.clone(), registry.map(str::to_string)))
                        .or_default()
                        .insert(
                            pkg.requirement.to_string(),
                            (pkg.version.clone(), pkg.digest.clone()),
                        );

                    if let Some((prev, _)) = prev {
                        // The same requirements should resolve to the same version
                        assert!(prev == pkg.version)
                    }
                }
                None => continue,
            }
        }

        let mut packages: Vec<_> = packages
            .into_iter()
            .map(|((id, registry), versions)| {
                let mut versions: Vec<LockedPackageVersion> = versions
                    .into_iter()
                    .map(|(requirement, (version, digest))| LockedPackageVersion {
                        requirement,
                        version,
                        digest,
                    })
                    .collect();

                versions.sort_by(|a, b| a.key().cmp(b.key()));

                LockedPackage {
                    id,
                    registry,
                    versions,
                }
            })
            .collect();

        packages.sort_by(|a, b| a.key().cmp(&b.key()));

        Self {
            version: LOCK_FILE_VERSION,
            packages,
        }
    }

    /// Opens the lock file for the given configuration file path.
    pub fn open(config_path: &Path) -> Result<Option<Self>> {
        let path = config_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(LOCK_FILE_NAME);

        if !path.exists() {
            return Ok(None);
        }

        tracing::info!("opening lock file `{path}`", path = path.display());
        let mut lock = Self::acquire_ro(&path)
            .with_context(|| format!("failed to open `{path}`", path = path.display()))?;

        let mut contents = String::new();
        lock.read_to_string(&mut contents)
            .with_context(|| format!("failed to read `{path}`", path = path.display()))?;

        let document: Document = contents
            .parse()
            .with_context(|| format!("failed to parse `{path}`", path = path.display()))?;

        match document.as_table().get("version") {
            Some(Item::Value(Value::Integer(v))) => {
                if *v.value() != LOCK_FILE_VERSION {
                    bail!(
                        "failed to parse `{path}`: unsupported file format version {version}",
                        path = path.display(),
                        version = v.value()
                    );
                }

                // In the future, we should convert between supported versions here.
            }
            Some(_) => bail!(
                "failed to parse `{path}`: file format version is not an integer",
                path = path.display()
            ),
            None => bail!(
                "failed to parse `{path}`: missing file format version",
                path = path.display()
            ),
        }

        Ok(Some(
            Self::deserialize(document.into_deserializer()).with_context(|| {
                format!(
                    "failed to parse `{path}`: invalid file format",
                    path = path.display()
                )
            })?,
        ))
    }

    /// Updates the lock file on disk given the old lock file to compare against.
    pub fn update(&self, config_path: &Path, old: &Self) -> Result<()> {
        // If the set of packages are the same, we don't need to update the lock file.
        let path = config_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(LOCK_FILE_NAME);
        if path.is_file() && old == self {
            return Ok(());
        }

        tracing::info!("updating lock file `{path}`", path = path.display());

        let updated = toml_edit::ser::to_string_pretty(&self)
            .with_context(|| format!("failed to serialize `{path}`", path = path.display()))?;

        let mut lock = Self::acquire(&path)
            .with_context(|| format!("failed to open `{path}`", path = path.display()))?;

        lock.file().set_len(0)?;
        lock.write_all(b"# This file is automatically generated by wit.\n# It is not intended for manual editing.\n")
            .and_then(|_| lock.write_all(updated.as_bytes()))
            .with_context(|| format!("failed to write `{path}`", path = path.display()))?;

        Ok(())
    }

    fn acquire_ro(path: &Path) -> Result<FileLock> {
        match FileLock::try_open_ro(path)? {
            Some(lock) => Ok(lock),
            None => {
                println!(
                    "{blocking} on access to lock file `{path}`",
                    blocking = "blocking".cyan(),
                    path = path.display()
                );

                FileLock::open_ro(path)
            }
        }
    }

    fn acquire(path: &Path) -> Result<FileLock> {
        match FileLock::try_open_rw(path)? {
            Some(lock) => Ok(lock),
            None => {
                println!(
                    "{blocking} on access to lock file `{path}`",
                    blocking = "blocking".cyan(),
                    path = path.display()
                );

                FileLock::open_rw(path)
            }
        }
    }
}

impl Default for LockFile {
    fn default() -> Self {
        Self {
            version: LOCK_FILE_VERSION,
            packages: Vec::new(),
        }
    }
}

#[derive(Debug)]
struct FileLock {
    file: File,
    path: PathBuf,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum Access {
    Shared,
    Exclusive,
}

impl FileLock {
    /// Attempts to acquire exclusive access to a file, returning the locked
    /// version of a file.
    ///
    /// This function will create a file at `path` if it doesn't already exist
    /// (including intermediate directories), and then it will try to acquire an
    /// exclusive lock on `path`.
    ///
    /// If the lock cannot be immediately acquired, `Ok(None)` is returned.
    ///
    /// The returned file can be accessed to look at the path and also has
    /// read/write access to the underlying file.
    pub fn try_open_rw(path: impl Into<PathBuf>) -> Result<Option<Self>> {
        Self::open(
            path.into(),
            OpenOptions::new().read(true).write(true).create(true),
            Access::Exclusive,
            true,
        )
    }

    /// Opens exclusive access to a file, returning the locked version of a
    /// file.
    ///
    /// This function will create a file at `path` if it doesn't already exist
    /// (including intermediate directories), and then it will acquire an
    /// exclusive lock on `path`.
    ///
    /// If the lock cannot be acquired, this function will block until it is
    /// acquired.
    ///
    /// The returned file can be accessed to look at the path and also has
    /// read/write access to the underlying file.
    pub fn open_rw(path: impl Into<PathBuf>) -> Result<Self> {
        Ok(Self::open(
            path.into(),
            OpenOptions::new().read(true).write(true).create(true),
            Access::Exclusive,
            false,
        )?
        .unwrap())
    }

    /// Attempts to acquire shared access to a file, returning the locked version
    /// of a file.
    ///
    /// This function will fail if `path` doesn't already exist, but if it does
    /// then it will acquire a shared lock on `path`.
    ///
    /// If the lock cannot be immediately acquired, `Ok(None)` is returned.
    ///
    /// The returned file can be accessed to look at the path and also has read
    /// access to the underlying file. Any writes to the file will return an
    /// error.
    pub fn try_open_ro(path: impl Into<PathBuf>) -> Result<Option<Self>> {
        Self::open(
            path.into(),
            OpenOptions::new().read(true),
            Access::Shared,
            true,
        )
    }

    /// Opens shared access to a file, returning the locked version of a file.
    ///
    /// This function will fail if `path` doesn't already exist, but if it does
    /// then it will acquire a shared lock on `path`.
    ///
    /// If the lock cannot be acquired, this function will block until it is
    /// acquired.
    ///
    /// The returned file can be accessed to look at the path and also has read
    /// access to the underlying file. Any writes to the file will return an
    /// error.
    pub fn open_ro(path: impl Into<PathBuf>) -> Result<Self> {
        Ok(Self::open(
            path.into(),
            OpenOptions::new().read(true),
            Access::Shared,
            false,
        )?
        .unwrap())
    }

    fn open(
        path: PathBuf,
        opts: &OpenOptions,
        access: Access,
        try_lock: bool,
    ) -> Result<Option<Self>> {
        // If we want an exclusive lock then if we fail because of NotFound it's
        // likely because an intermediate directory didn't exist, so try to
        // create the directory and then continue.
        let file = opts
            .open(&path)
            .or_else(|e| {
                if e.kind() == io::ErrorKind::NotFound && access == Access::Exclusive {
                    std::fs::create_dir_all(path.parent().unwrap())?;
                    Ok(opts.open(&path)?)
                } else {
                    Err(anyhow::Error::from(e))
                }
            })
            .with_context(|| format!("failed to open `{path}`", path = path.display()))?;

        let lock = Self { file, path };

        // File locking on Unix is currently implemented via `flock`, which is known
        // to be broken on NFS. We could in theory just ignore errors that happen on
        // NFS, but apparently the failure mode [1] for `flock` on NFS is **blocking
        // forever**, even if the "non-blocking" flag is passed!
        //
        // As a result, we just skip all file locks entirely on NFS mounts. That
        // should avoid calling any `flock` functions at all, and it wouldn't work
        // there anyway.
        //
        // [1]: https://github.com/rust-lang/cargo/issues/2615
        if is_on_nfs_mount(&lock.path) {
            return Ok(Some(lock));
        }

        let res = match (access, try_lock) {
            (Access::Shared, true) => sys::try_lock_shared(&lock.file),
            (Access::Exclusive, true) => sys::try_lock_exclusive(&lock.file),
            (Access::Shared, false) => sys::lock_shared(&lock.file),
            (Access::Exclusive, false) => sys::lock_exclusive(&lock.file),
        };

        return match res {
            Ok(_) => Ok(Some(lock)),

            // In addition to ignoring NFS which is commonly not working we also
            // just ignore locking on file systems that look like they don't
            // implement file locking.
            Err(e) if sys::error_unsupported(&e) => Ok(Some(lock)),

            // Check to see if it was a contention error
            Err(e) if try_lock && sys::error_contended(&e) => Ok(None),

            Err(e) => Err(anyhow!(e).context(format!(
                "failed to lock file `{path}`",
                path = lock.path.display()
            ))),
        };

        #[cfg(all(target_os = "linux", not(target_env = "musl")))]
        fn is_on_nfs_mount(path: &Path) -> bool {
            use std::ffi::CString;
            use std::mem;
            use std::os::unix::prelude::*;

            let path = match CString::new(path.as_os_str().as_bytes()) {
                Ok(path) => path,
                Err(_) => return false,
            };

            unsafe {
                let mut buf: libc::statfs = mem::zeroed();
                let r = libc::statfs(path.as_ptr(), &mut buf);

                r == 0 && buf.f_type as u32 == libc::NFS_SUPER_MAGIC as u32
            }
        }

        #[cfg(any(not(target_os = "linux"), target_env = "musl"))]
        fn is_on_nfs_mount(_path: &Path) -> bool {
            false
        }
    }

    /// Returns the underlying file handle of this lock.
    pub fn file(&self) -> &File {
        &self.file
    }
}

impl Read for FileLock {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file().read(buf)
    }
}

impl Seek for FileLock {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        self.file().seek(to)
    }
}

impl Write for FileLock {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file().flush()
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = sys::unlock(&self.file);
    }
}

#[cfg(unix)]
mod sys {
    use std::fs::File;
    use std::io::{Error, Result};
    use std::os::unix::io::AsRawFd;

    pub(super) fn lock_shared(file: &File) -> Result<()> {
        flock(file, libc::LOCK_SH)
    }

    pub(super) fn lock_exclusive(file: &File) -> Result<()> {
        flock(file, libc::LOCK_EX)
    }

    pub(super) fn try_lock_shared(file: &File) -> Result<()> {
        flock(file, libc::LOCK_SH | libc::LOCK_NB)
    }

    pub(super) fn try_lock_exclusive(file: &File) -> Result<()> {
        flock(file, libc::LOCK_EX | libc::LOCK_NB)
    }

    pub(super) fn unlock(file: &File) -> Result<()> {
        flock(file, libc::LOCK_UN)
    }

    pub(super) fn error_contended(err: &Error) -> bool {
        err.raw_os_error().map_or(false, |x| x == libc::EWOULDBLOCK)
    }

    pub(super) fn error_unsupported(err: &Error) -> bool {
        match err.raw_os_error() {
            // Unfortunately, depending on the target, these may or may not be the same.
            // For targets in which they are the same, the duplicate pattern causes a warning.
            #[allow(unreachable_patterns)]
            Some(libc::ENOTSUP | libc::EOPNOTSUPP) => true,
            Some(libc::ENOSYS) => true,
            _ => false,
        }
    }

    #[cfg(not(target_os = "solaris"))]
    fn flock(file: &File, flag: libc::c_int) -> Result<()> {
        let ret = unsafe { libc::flock(file.as_raw_fd(), flag) };
        if ret < 0 {
            Err(Error::last_os_error())
        } else {
            Ok(())
        }
    }

    #[cfg(target_os = "solaris")]
    fn flock(file: &File, flag: libc::c_int) -> Result<()> {
        // Solaris lacks flock(), so try to emulate using fcntl()
        let mut flock = libc::flock {
            l_type: 0,
            l_whence: 0,
            l_start: 0,
            l_len: 0,
            l_sysid: 0,
            l_pid: 0,
            l_pad: [0, 0, 0, 0],
        };
        flock.l_type = if flag & libc::LOCK_UN != 0 {
            libc::F_UNLCK
        } else if flag & libc::LOCK_EX != 0 {
            libc::F_WRLCK
        } else if flag & libc::LOCK_SH != 0 {
            libc::F_RDLCK
        } else {
            panic!("unexpected flock() operation")
        };

        let mut cmd = libc::F_SETLKW;
        if (flag & libc::LOCK_NB) != 0 {
            cmd = libc::F_SETLK;
        }

        let ret = unsafe { libc::fcntl(file.as_raw_fd(), cmd, &flock) };

        if ret < 0 {
            Err(Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

#[cfg(windows)]
mod sys {
    use std::fs::File;
    use std::io::{Error, Result};
    use std::mem;
    use std::os::windows::io::AsRawHandle;

    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Foundation::{ERROR_INVALID_FUNCTION, ERROR_LOCK_VIOLATION};
    use windows_sys::Win32::Storage::FileSystem::{
        LockFileEx, UnlockFile, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
    };

    pub(super) fn lock_shared(file: &File) -> Result<()> {
        lock_file(file, 0)
    }

    pub(super) fn lock_exclusive(file: &File) -> Result<()> {
        lock_file(file, LOCKFILE_EXCLUSIVE_LOCK)
    }

    pub(super) fn try_lock_shared(file: &File) -> Result<()> {
        lock_file(file, LOCKFILE_FAIL_IMMEDIATELY)
    }

    pub(super) fn try_lock_exclusive(file: &File) -> Result<()> {
        lock_file(file, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY)
    }

    pub(super) fn error_contended(err: &Error) -> bool {
        err.raw_os_error()
            .map_or(false, |x| x == ERROR_LOCK_VIOLATION as i32)
    }

    pub(super) fn error_unsupported(err: &Error) -> bool {
        err.raw_os_error()
            .map_or(false, |x| x == ERROR_INVALID_FUNCTION as i32)
    }

    pub(super) fn unlock(file: &File) -> Result<()> {
        unsafe {
            let ret = UnlockFile(file.as_raw_handle() as HANDLE, 0, 0, !0, !0);
            if ret == 0 {
                Err(Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }

    fn lock_file(file: &File, flags: u32) -> Result<()> {
        unsafe {
            let mut overlapped = mem::zeroed();
            let ret = LockFileEx(
                file.as_raw_handle() as HANDLE,
                flags,
                0,
                !0,
                !0,
                &mut overlapped,
            );
            if ret == 0 {
                Err(Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }
}
