use std::{
    ffi::{OsStr, OsString},
    fs, io,
    path::{Component, Path, PathBuf},
    time::{Duration, UNIX_EPOCH},
};

use cap_fs_ext::{DirExt as _, FollowSymlinks, OpenOptionsFollowExt as _, SystemTimeSpec};
use cap_std::{
    ambient_authority,
    fs::{Dir, File, OpenOptions},
};
use filetime::FileTime;

use super::OverwritePolicy;
use crate::{
    Result,
    error::{invalid_path, message},
    index::EntryRecord,
};

pub(super) fn normalize_archive_path(value: &str) -> Result<String> {
    let value = value.replace('\\', "/");
    if value.is_empty() || value.starts_with('/') || value.contains(':') {
        return Err(invalid_path(value));
    }
    let mut parts = Vec::new();
    for part in value.split('/') {
        validate_component(part)?;
        parts.push(part);
    }
    Ok(parts.join("/"))
}

pub(super) fn validate_component(value: &str) -> Result<()> {
    if value.is_empty() || value == "." || value == ".." || value.contains(['/', '\\', '\0']) {
        return Err(invalid_path(value));
    }
    Ok(())
}

pub(super) fn validate_link_target(entry_path: &Path, target: &str) -> Result<()> {
    let target_path = Path::new(target);
    if target_path.is_absolute() || target.contains(':') {
        return Err(invalid_path(target));
    }
    let mut depth = entry_path
        .parent()
        .map_or(0isize, |value| value.components().count() as isize);
    for component in target_path.components() {
        match component {
            Component::Normal(_) => depth += 1,
            Component::ParentDir => {
                depth -= 1;
                if depth < 0 {
                    return Err(invalid_path(target));
                }
            }
            Component::CurDir => {}
            _ => return Err(invalid_path(target)),
        }
    }
    Ok(())
}

pub(super) fn safe_target(root: &Path, relative: &Path) -> Result<PathBuf> {
    let normalized = normalize_archive_path(
        relative
            .to_str()
            .ok_or_else(|| invalid_path(relative.display()))?,
    )?;
    Ok(root.join(normalized))
}

pub(super) struct ExtractionRoot {
    dir: Dir,
}

impl ExtractionRoot {
    pub(super) fn open_or_create(path: &Path) -> Result<Self> {
        let mut cursor = path;
        let mut missing = Vec::new();
        while fs::symlink_metadata(cursor).is_err() {
            let Some(name) = cursor.file_name() else {
                break;
            };
            missing.push(name.to_owned());
            cursor = cursor.parent().unwrap_or_else(|| Path::new("."));
            if cursor.as_os_str().is_empty() {
                cursor = Path::new(".");
            }
        }

        let mut dir = if missing.is_empty() {
            match (path.parent(), path.file_name()) {
                (Some(parent), Some(name)) if !name.is_empty() => {
                    let parent = if parent.as_os_str().is_empty() {
                        Path::new(".")
                    } else {
                        parent
                    };
                    Dir::open_ambient_dir(parent, ambient_authority())?.open_dir_nofollow(name)?
                }
                _ => Dir::open_ambient_dir(path, ambient_authority())?,
            }
        } else {
            Dir::open_ambient_dir(cursor, ambient_authority())?
        };
        for component in missing.into_iter().rev() {
            match dir.create_dir(&component) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
            dir = dir.open_dir_nofollow(&component)?;
        }
        Ok(Self { dir })
    }

    pub(super) fn walker(&self) -> Result<DirWalker> {
        DirWalker::new(self.dir.try_clone()?)
    }
}

pub(super) struct DirWalker {
    components: Vec<OsString>,
    dirs: Vec<Dir>,
}

impl DirWalker {
    fn new(root: Dir) -> Result<Self> {
        Ok(Self {
            components: Vec::new(),
            dirs: vec![root],
        })
    }

    pub(super) fn directory(&mut self, relative: &Path, create: bool) -> Result<&Dir> {
        let wanted = path_components(relative)?;
        let common = self
            .components
            .iter()
            .zip(&wanted)
            .take_while(|(left, right)| left == right)
            .count();
        self.components.truncate(common);
        self.dirs.truncate(common + 1);

        for component in wanted.into_iter().skip(common) {
            let parent = self.dirs.last().expect("root directory handle");
            let child = match parent.open_dir_nofollow(&component) {
                Ok(dir) => dir,
                Err(error) if create && error.kind() == io::ErrorKind::NotFound => {
                    match parent.create_dir(&component) {
                        Ok(()) => {}
                        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                        Err(error) => return Err(error.into()),
                    }
                    parent.open_dir_nofollow(&component)?
                }
                Err(error) => return Err(error.into()),
            };
            self.components.push(component);
            self.dirs.push(child);
        }
        Ok(self.dirs.last().expect("root directory handle"))
    }

    pub(super) fn existing_directory(&mut self, relative: &Path) -> Result<Option<&Dir>> {
        let wanted = path_components(relative)?;
        let common = self
            .components
            .iter()
            .zip(&wanted)
            .take_while(|(left, right)| left == right)
            .count();
        self.components.truncate(common);
        self.dirs.truncate(common + 1);
        for component in wanted.into_iter().skip(common) {
            let parent = self.dirs.last().expect("root directory handle");
            match parent.open_dir_nofollow(&component) {
                Ok(child) => {
                    self.components.push(component);
                    self.dirs.push(child);
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error.into()),
            }
        }
        Ok(Some(self.dirs.last().expect("root directory handle")))
    }
}

fn path_components(path: &Path) -> Result<Vec<OsString>> {
    path.components()
        .map(|component| match component {
            Component::Normal(value) => Ok(value.to_owned()),
            _ => Err(invalid_path(path.display())),
        })
        .collect()
}

pub(super) fn split_parent_name(path: &Path) -> Result<(&Path, &OsStr)> {
    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    let name = path
        .file_name()
        .ok_or_else(|| invalid_path(path.display()))?;
    Ok((parent, name))
}

pub(super) fn symlink_metadata_at(dir: &Dir, name: &OsStr) -> io::Result<cap_std::fs::Metadata> {
    dir.symlink_metadata(name)
}

pub(super) struct ScopedTempFile<'a> {
    parent: &'a Dir,
    name: OsString,
    file: Option<File>,
}

impl<'a> ScopedTempFile<'a> {
    pub(super) fn new(parent: &'a Dir) -> Result<Self> {
        for _ in 0..32 {
            let name = OsString::from(format!(".engage-tmp-{}", uuid::Uuid::new_v4()));
            let mut options = OpenOptions::new();
            options
                .read(true)
                .write(true)
                .create_new(true)
                .follow(FollowSymlinks::No);
            match parent.open_with(&name, &options) {
                Ok(file) => {
                    return Ok(Self {
                        parent,
                        name,
                        file: Some(file),
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(message(
            "could not allocate a unique extraction temporary file",
        ))
    }

    pub(super) fn file_mut(&mut self) -> &mut File {
        self.file.as_mut().expect("temporary file is active")
    }

    pub(super) fn sync_all(&self) -> Result<()> {
        self.file
            .as_ref()
            .expect("temporary file is active")
            .sync_all()?;
        Ok(())
    }

    pub(super) fn apply_metadata(&self, record: &EntryRecord) -> Result<()> {
        apply_file_metadata(
            self.file.as_ref().expect("temporary file is active"),
            record,
        )
    }

    pub(super) fn persist(mut self, target: &OsStr, overwrite: OverwritePolicy) -> Result<()> {
        drop(self.file.take());
        match overwrite {
            OverwritePolicy::ReplaceFiles => {
                self.parent.rename(&self.name, self.parent, target)?;
            }
            OverwritePolicy::Refuse => {
                self.parent.hard_link(&self.name, self.parent, target)?;
                self.parent.remove_file(&self.name)?;
            }
        }
        self.name.clear();
        Ok(())
    }
}

impl Drop for ScopedTempFile<'_> {
    fn drop(&mut self) {
        if !self.name.is_empty() {
            let _ = self.parent.remove_file(&self.name);
        }
    }
}

fn apply_file_metadata(file: &File, record: &EntryRecord) -> Result<()> {
    let std_file = file.try_clone()?.into_std();
    filetime::set_file_handle_times(
        &std_file,
        None,
        Some(FileTime::from_unix_time(record.mtime, 0)),
    )?;
    let mut permissions = std_file.metadata()?.permissions();
    permissions.set_readonly(record.mode & 0o200 == 0);
    std_file.set_permissions(permissions)?;
    Ok(())
}

pub(super) fn apply_directory_metadata(dir: &Dir, record: &EntryRecord) -> Result<()> {
    let mtime = if record.mtime >= 0 {
        UNIX_EPOCH + Duration::from_secs(record.mtime as u64)
    } else {
        UNIX_EPOCH - Duration::from_secs(record.mtime.unsigned_abs())
    };
    dir.set_mtime(
        ".",
        SystemTimeSpec::Absolute(cap_std::time::SystemTime::from_std(mtime)),
    )?;
    let mut permissions = dir.dir_metadata()?.permissions();
    permissions.set_readonly(record.mode & 0o200 == 0);
    dir.set_permissions(".", permissions)?;
    Ok(())
}

pub(super) fn create_symlink_at(
    parent: &Dir,
    target: &str,
    name: &OsStr,
    is_dir: bool,
) -> Result<()> {
    if is_dir {
        parent.symlink_dir(target, name)?;
    } else {
        parent.symlink_file(target, name)?;
    }
    Ok(())
}

#[cfg(unix)]
pub(super) fn metadata_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode()
}

#[cfg(not(unix))]
pub(super) fn metadata_mode(metadata: &fs::Metadata) -> u32 {
    if metadata.permissions().readonly() {
        0o444
    } else {
        0o644
    }
}
