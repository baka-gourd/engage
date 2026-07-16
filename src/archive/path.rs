use std::{
    collections::HashSet,
    fs, io,
    path::{Component, Path, PathBuf},
};

use filetime::FileTime;

use super::OverwritePolicy;
use crate::{
    Result,
    error::{invalid_path, message},
    index::{EntryKind, EntryRecord},
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

pub(super) fn preflight_targets(
    root: &Path,
    entries: &[(EntryRecord, PathBuf)],
    overwrite: OverwritePolicy,
) -> Result<()> {
    let mut folded = HashSet::new();
    for (record, relative) in entries {
        let text = relative
            .to_str()
            .ok_or_else(|| invalid_path(relative.display()))?;
        if !folded.insert(text.to_lowercase()) {
            return Err(invalid_path(format!(
                "case-insensitive path collision: {text}"
            )));
        }
        let target = safe_target(root, relative)?;
        if let Ok(metadata) = fs::symlink_metadata(&target) {
            let allowed = overwrite == OverwritePolicy::ReplaceFiles
                && ((record.kind == EntryKind::File && metadata.is_file())
                    || (record.kind == EntryKind::Directory && metadata.is_dir()));
            if !allowed {
                return Err(message(format!(
                    "target already exists: {}",
                    target.display()
                )));
            }
        }
    }
    Ok(())
}

pub(super) fn reject_link_ancestors(root: &Path, target: &Path) -> Result<()> {
    if let Ok(metadata) = fs::symlink_metadata(root)
        && metadata.file_type().is_symlink()
    {
        return Err(invalid_path(format!(
            "output root is a symlink: {}",
            root.display()
        )));
    }
    let relative = target.strip_prefix(root).unwrap_or(Path::new(""));
    let mut current = root.to_owned();
    for component in relative.components() {
        current.push(component);
        if let Ok(metadata) = fs::symlink_metadata(&current)
            && metadata.file_type().is_symlink()
        {
            return Err(invalid_path(format!(
                "output path traverses a symlink: {}",
                current.display()
            )));
        }
    }
    Ok(())
}

pub(super) fn apply_metadata(path: &Path, record: &EntryRecord) -> Result<()> {
    filetime::set_file_mtime(path, FileTime::from_unix_time(record.mtime, 0))?;
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_readonly(record.mode & 0o200 == 0);
    fs::set_permissions(path, permissions)?;
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

#[cfg(unix)]
pub(super) fn create_symlink(target: &str, link: &Path, _is_dir: bool) -> io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
pub(super) fn create_symlink(target: &str, link: &Path, is_dir: bool) -> io::Result<()> {
    if is_dir {
        std::os::windows::fs::symlink_dir(target, link)
    } else {
        std::os::windows::fs::symlink_file(target, link)
    }
}
