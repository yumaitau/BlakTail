//! Share-root pinning and link-free path resolution for the overlay share.
//!
//! The agent runs as root (or SYSTEM) and the shared folder is usually owned
//! by an ordinary user. That user can swap the folder, or anything inside it,
//! for a symbolic link or junction at any moment. Every request therefore
//! walks the stored canonical root one component at a time without following
//! links, and then works on the directory it holds instead of on a path.
//!
//! - Unix: each component is opened with `openat(O_NOFOLLOW)` relative to the
//!   directory descriptor above it, from `/`. Later operations use the `*at`
//!   calls on the pinned descriptor, so a swap after the walk changes nothing.
//! - Windows: each component is opened without following reparse points and
//!   refused when it is a symbolic link or junction. The handles are held
//!   without `FILE_SHARE_DELETE`, so no component can be renamed or replaced
//!   while the request runs; path operations below the held chain are safe.
use std::{
    fs::{self, File},
    io,
    path::{Path, PathBuf},
    time::SystemTime,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
    /// A link, junction, device, socket or anything else the share refuses.
    Other,
}

#[derive(Debug)]
pub struct Entry {
    pub name: String,
    pub kind: Kind,
    pub len: u64,
    pub modified: Option<SystemTime>,
}

/// One request path component the share accepts. Dot-files are refused
/// (they are hidden from listings too), and so are separators, NTFS stream
/// names (`:`), control characters and Windows trailing dots or spaces.
pub fn safe_component(part: &str) -> bool {
    !part.is_empty()
        && !part.starts_with('.')
        && !part
            .chars()
            .any(|c| c.is_control() || matches!(c, '/' | '\\' | ':'))
        && !(cfg!(windows) && (part.ends_with('.') || part.ends_with(' ')))
}

fn refused(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message.to_owned())
}

/// A directory held open below the share root.
pub struct Dir {
    path: PathBuf,
    file: File,
    #[cfg(windows)]
    chain: Vec<File>,
}

/// Open the stored share root. It must still canonicalise to itself (no
/// link anywhere on the path) and every component is opened without
/// following links.
pub fn open_root(stored: &Path) -> io::Result<Dir> {
    if !stored.is_absolute() {
        return Err(refused("share root is not absolute"));
    }
    let resolved = fs::canonicalize(stored)?;
    if resolved != stored {
        return Err(refused(
            "share root no longer resolves to the shared folder",
        ));
    }
    imp::open_root(stored)
}

impl Dir {
    pub fn metadata(&self) -> io::Result<fs::Metadata> {
        self.file.metadata()
    }

    /// Descend into a child directory. Links are refused.
    pub fn descend(self, name: &str) -> io::Result<Dir> {
        check(name)?;
        imp::descend(self, name)
    }

    /// What `name` is, without following links. `None` when absent.
    pub fn kind(&self, name: &str) -> io::Result<Option<Kind>> {
        check(name)?;
        imp::kind(self, name)
    }

    /// Open a regular file for reading. Links and special files are refused.
    pub fn open_file(&self, name: &str) -> io::Result<File> {
        check(name)?;
        imp::open_file(self, name)
    }

    /// Create a new file; fails if anything (including a link) has that name.
    pub fn create_new(&self, name: &str) -> io::Result<File> {
        check_internal(name)?;
        imp::create_new(self, name)
    }

    pub fn mkdir(&self, name: &str) -> io::Result<()> {
        check(name)?;
        imp::mkdir(self, name)
    }

    pub fn remove_file(&self, name: &str) -> io::Result<()> {
        check_internal(name)?;
        imp::remove_file(self, name)
    }

    pub fn remove_dir(&self, name: &str) -> io::Result<()> {
        check(name)?;
        imp::remove_dir(self, name)
    }

    /// Rename `from` here to `to` in `target` (atomic replace of a file).
    pub fn rename(&self, from: &str, target: &Dir, to: &str) -> io::Result<()> {
        check_internal(from)?;
        check_internal(to)?;
        imp::rename(self, from, target, to)
    }

    /// Visible entries (no dot-files), sorted by name, at most `limit`.
    /// Metadata never follows a link; links are reported as `Kind::Other`.
    pub fn entries(&self, limit: usize) -> Vec<Entry> {
        let mut names = fs::read_dir(&self.path)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|entry| entry.file_name().into_string().ok())
            .filter(|name| safe_component(name))
            .collect::<Vec<_>>();
        names.sort();
        names
            .into_iter()
            .filter_map(|name| imp::entry(self, name))
            .take(limit)
            .collect()
    }
}

fn check(name: &str) -> io::Result<()> {
    if safe_component(name) {
        Ok(())
    } else {
        Err(refused("share path component is not acceptable"))
    }
}

/// Like `check`, but also accepts the agent's own `.blaktail-partial-*`
/// temporary names.
fn check_internal(name: &str) -> io::Result<()> {
    if name
        .strip_prefix(".blaktail-partial-")
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Ok(());
    }
    check(name)
}

#[cfg(unix)]
mod imp {
    use super::{refused, Dir, Entry, Kind};
    use std::{
        ffi::CString,
        fs::File,
        io,
        os::unix::{
            ffi::OsStrExt,
            io::{AsRawFd, FromRawFd},
        },
        path::{Component, Path},
        time::{Duration, UNIX_EPOCH},
    };

    fn c_name(name: &[u8]) -> io::Result<CString> {
        CString::new(name).map_err(|_| refused("share path component is not acceptable"))
    }

    fn open_at(dir: libc::c_int, name: &[u8], flags: libc::c_int) -> io::Result<File> {
        let name = c_name(name)?;
        let fd = unsafe {
            libc::openat(
                dir,
                name.as_ptr(),
                flags | libc::O_CLOEXEC,
                0o644 as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    const DIR_FLAGS: libc::c_int = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW;

    pub fn open_root(stored: &Path) -> io::Result<Dir> {
        let mut file = open_at(libc::AT_FDCWD, b"/", libc::O_RDONLY | libc::O_DIRECTORY)?;
        for component in stored.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(name) => {
                    file = open_at(file.as_raw_fd(), name.as_bytes(), DIR_FLAGS)?;
                }
                _ => return Err(refused("share root is not canonical")),
            }
        }
        Ok(Dir {
            path: stored.to_path_buf(),
            file,
        })
    }

    pub fn descend(dir: Dir, name: &str) -> io::Result<Dir> {
        let file = open_at(dir.file.as_raw_fd(), name.as_bytes(), DIR_FLAGS)?;
        Ok(Dir {
            path: dir.path.join(name),
            file,
        })
    }

    fn stat_at(dir: &Dir, name: &str) -> io::Result<libc::stat> {
        let name = c_name(name.as_bytes())?;
        let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
        let result = unsafe {
            libc::fstatat(
                dir.file.as_raw_fd(),
                name.as_ptr(),
                &mut stat,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(stat)
    }

    fn kind_of(stat: &libc::stat) -> Kind {
        match stat.st_mode & libc::S_IFMT {
            libc::S_IFREG => Kind::File,
            libc::S_IFDIR => Kind::Dir,
            _ => Kind::Other,
        }
    }

    pub fn kind(dir: &Dir, name: &str) -> io::Result<Option<Kind>> {
        match stat_at(dir, name) {
            Ok(stat) => Ok(Some(kind_of(&stat))),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub fn entry(dir: &Dir, name: String) -> Option<Entry> {
        // Names come from a path listing; metadata comes from the pinned
        // descriptor, so a swapped directory contributes nothing.
        let stat = stat_at(dir, &name).ok()?;
        let modified = UNIX_EPOCH.checked_add(Duration::from_secs(
            u64::try_from(stat.st_mtime).unwrap_or(0),
        ));
        Some(Entry {
            kind: kind_of(&stat),
            len: u64::try_from(stat.st_size).unwrap_or(0),
            modified,
            name,
        })
    }

    pub fn open_file(dir: &Dir, name: &str) -> io::Result<File> {
        // O_NONBLOCK keeps a planted FIFO from hanging the request.
        let file = open_at(
            dir.file.as_raw_fd(),
            name.as_bytes(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )?;
        if !file.metadata()?.is_file() {
            return Err(refused("share path is not a regular file"));
        }
        Ok(file)
    }

    pub fn create_new(dir: &Dir, name: &str) -> io::Result<File> {
        open_at(
            dir.file.as_raw_fd(),
            name.as_bytes(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
        )
    }

    pub fn mkdir(dir: &Dir, name: &str) -> io::Result<()> {
        let name = c_name(name.as_bytes())?;
        if unsafe { libc::mkdirat(dir.file.as_raw_fd(), name.as_ptr(), 0o755) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn unlink(dir: &Dir, name: &str, flags: libc::c_int) -> io::Result<()> {
        let name = c_name(name.as_bytes())?;
        if unsafe { libc::unlinkat(dir.file.as_raw_fd(), name.as_ptr(), flags) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn remove_file(dir: &Dir, name: &str) -> io::Result<()> {
        unlink(dir, name, 0)
    }

    pub fn remove_dir(dir: &Dir, name: &str) -> io::Result<()> {
        unlink(dir, name, libc::AT_REMOVEDIR)
    }

    pub fn rename(dir: &Dir, from: &str, target: &Dir, to: &str) -> io::Result<()> {
        let from = c_name(from.as_bytes())?;
        let to = c_name(to.as_bytes())?;
        let result = unsafe {
            libc::renameat(
                dir.file.as_raw_fd(),
                from.as_ptr(),
                target.file.as_raw_fd(),
                to.as_ptr(),
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(windows)]
mod imp {
    use super::{refused, Dir, Entry, Kind};
    use std::{
        fs::{self, File, OpenOptions},
        io,
        os::windows::fs::OpenOptionsExt,
        path::{Component, Path, PathBuf},
    };

    const FILE_LIST_DIRECTORY: u32 = 0x0001;
    const FILE_READ_ATTRIBUTES: u32 = 0x0080;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const FILE_SHARE_READ: u32 = 0x0001;
    const FILE_SHARE_WRITE: u32 = 0x0002;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    /// Hold a directory so it cannot be renamed, deleted or replaced by a
    /// junction while the request runs (no `FILE_SHARE_DELETE`).
    fn pin(path: &Path) -> io::Result<File> {
        let file = OpenOptions::new()
            .access_mode(FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        let metadata = file.metadata()?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(refused("share path goes through a link or junction"));
        }
        Ok(file)
    }

    pub fn open_root(stored: &Path) -> io::Result<Dir> {
        let mut path = PathBuf::new();
        let mut chain = Vec::new();
        for component in stored.components() {
            match component {
                Component::Prefix(_) | Component::RootDir => path.push(component),
                Component::Normal(name) => {
                    path.push(name);
                    chain.push(pin(&path)?);
                }
                _ => return Err(refused("share root is not canonical")),
            }
        }
        let file = chain
            .pop()
            .ok_or_else(|| refused("a drive root cannot be shared"))?;
        Ok(Dir { path, file, chain })
    }

    pub fn descend(dir: Dir, name: &str) -> io::Result<Dir> {
        let path = dir.path.join(name);
        let file = pin(&path)?;
        let mut chain = dir.chain;
        chain.push(dir.file);
        Ok(Dir { path, file, chain })
    }

    fn kind_of(metadata: &fs::Metadata) -> Kind {
        let kind = metadata.file_type();
        if kind.is_symlink() {
            Kind::Other
        } else if kind.is_dir() {
            Kind::Dir
        } else if kind.is_file() {
            Kind::File
        } else {
            Kind::Other
        }
    }

    pub fn kind(dir: &Dir, name: &str) -> io::Result<Option<Kind>> {
        match fs::symlink_metadata(dir.path.join(name)) {
            Ok(metadata) => Ok(Some(kind_of(&metadata))),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub fn entry(dir: &Dir, name: String) -> Option<Entry> {
        let metadata = fs::symlink_metadata(dir.path.join(&name)).ok()?;
        Some(Entry {
            kind: kind_of(&metadata),
            len: metadata.len(),
            modified: metadata.modified().ok(),
            name,
        })
    }

    pub fn open_file(dir: &Dir, name: &str) -> io::Result<File> {
        let file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(dir.path.join(name))?;
        let metadata = file.metadata()?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(refused("share path is not a regular file"));
        }
        Ok(file)
    }

    pub fn create_new(dir: &Dir, name: &str) -> io::Result<File> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(dir.path.join(name))
    }

    pub fn mkdir(dir: &Dir, name: &str) -> io::Result<()> {
        fs::create_dir(dir.path.join(name))
    }

    pub fn remove_file(dir: &Dir, name: &str) -> io::Result<()> {
        fs::remove_file(dir.path.join(name))
    }

    pub fn remove_dir(dir: &Dir, name: &str) -> io::Result<()> {
        fs::remove_dir(dir.path.join(name))
    }

    pub fn rename(dir: &Dir, from: &str, target: &Dir, to: &str) -> io::Result<()> {
        fs::rename(dir.path.join(from), target.path.join(to))
    }
}
