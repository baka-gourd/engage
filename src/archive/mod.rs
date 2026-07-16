use std::{
    collections::HashMap,
    fs::{self, File},
    io::{Read, Seek, Write},
    path::{Path, PathBuf},
};

use age::{Decryptor, Encryptor, Identity, Recipient, secrecy::SecretString};
use eros::Context;

use crate::{
    CancellationToken, HybridIdentity, HybridRecipient, OperationProgress, OperationStage, Result,
    error::{invalid, invalid_path, not_found},
    format::{DEFAULT_SEGMENT_SIZE, FileRegion, SegmentedReader},
    index::{
        EntryId, EntryKind, EntryPage, EntryRecord, IndexCursor, IndexReader, ROOT_ID, ReadSeek,
    },
    progress::ProgressEmitter,
};

use self::{create::hash_prefix, path::*};

const BODY_FRAME_SIZE: u32 = 2 * 1024 * 1024;
const INDEX_FRAME_SIZE: u32 = 256 * 1024;
const BODY_PREFIX_SIZE: usize = 64 * 1024;

mod create;
mod parallel_zstd;
mod path;

pub use create::{create_archive, create_archive_controlled, create_archive_with_progress};

pub enum EncryptCredential {
    Passphrase(SecretString),
    PostQuantum(HybridRecipient),
    PostQuantumRecipients(Vec<HybridRecipient>),
}

pub enum DecryptCredential {
    Passphrase(SecretString),
    PostQuantum(HybridIdentity),
}

#[derive(Debug, Clone)]
pub struct CreateOptions {
    pub sort_memory_bytes: usize,
    pub metadata_segment_bytes: u64,
    /// Maximum number of compression workers. `None` selects a value from the available CPUs.
    pub compression_threads: Option<usize>,
}

impl Default for CreateOptions {
    fn default() -> Self {
        Self {
            sort_memory_bytes: 64 * 1024 * 1024,
            metadata_segment_bytes: DEFAULT_SEGMENT_SIZE,
            compression_threads: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverwritePolicy {
    Refuse,
    ReplaceFiles,
}

#[derive(Debug, Clone)]
pub struct ExtractOptions {
    pub overwrite: OverwritePolicy,
    /// Keep each selected entry at its full path inside the archive.
    /// When false, every selected root is extracted directly under the destination.
    pub preserve_hierarchy: bool,
}

impl Default for ExtractOptions {
    fn default() -> Self {
        Self {
            overwrite: OverwritePolicy::Refuse,
            preserve_hierarchy: true,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Selection {
    All,
    Paths(Vec<String>),
    EntryIds(Vec<EntryId>),
}

#[derive(Debug, Clone)]
pub struct EntryInfo {
    pub id: EntryId,
    pub parent_id: EntryId,
    pub name: String,
    pub kind: EntryKind,
    pub size: u64,
    pub mtime: i64,
    pub mode: u32,
    pub link_target: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictKind {
    ReplaceableFile,
    ExistingDirectory,
    Blocked,
}

#[derive(Debug, Clone)]
pub struct ExtractionConflict {
    pub path: PathBuf,
    pub kind: ConflictKind,
}

impl From<EntryRecord> for EntryInfo {
    fn from(value: EntryRecord) -> Self {
        Self {
            id: value.id,
            parent_id: value.parent_id,
            name: value.name,
            kind: value.kind,
            size: value.size,
            mtime: value.mtime,
            mode: value.mode,
            link_target: value.link_target,
        }
    }
}

fn make_encryptor(credential: &EncryptCredential) -> Result<Encryptor> {
    Ok(match credential {
        EncryptCredential::Passphrase(passphrase) => {
            Encryptor::with_user_passphrase(passphrase.clone())
        }
        EncryptCredential::PostQuantum(recipient) => {
            Encryptor::with_recipients(std::iter::once(recipient as &dyn Recipient))?
        }
        EncryptCredential::PostQuantumRecipients(recipients) => Encryptor::with_recipients(
            recipients
                .iter()
                .map(|recipient| recipient as &dyn Recipient),
        )?,
    })
}

fn decrypt_seekable<R: Read + Seek + 'static>(
    input: R,
    credential: &DecryptCredential,
) -> Result<Box<dyn ReadSeek>> {
    let decryptor = Decryptor::new(input)?;
    let reader = match credential {
        DecryptCredential::Passphrase(passphrase) => {
            let identity = age::scrypt::Identity::new(passphrase.clone());
            decryptor.decrypt(std::iter::once(&identity as &dyn Identity))?
        }
        DecryptCredential::PostQuantum(identity) => {
            decryptor.decrypt(std::iter::once(identity as &dyn Identity))?
        }
    };
    Ok(Box::new(reader))
}

pub struct Archive {
    file: File,
    body_len: u64,
    credential: DecryptCredential,
    index: IndexReader,
    seen_paths: HashMap<EntryId, String>,
}

impl Archive {
    pub fn open(
        path: impl AsRef<Path>,
        credential: DecryptCredential,
        page_cache_bytes: usize,
    ) -> Result<Self> {
        let file = File::open(path)?;
        let segmented = SegmentedReader::open(file.try_clone()?)
            .context("reading metadata frames from archive tail")?;
        let body_len = segmented.body_len();
        let metadata =
            decrypt_seekable(segmented, &credential).context("decrypting archive metadata")?;
        let index = IndexReader::new(metadata, page_cache_bytes.max(64 * 1024))
            .context("opening seekable metadata index")?;
        if index.superblock.body_len != body_len {
            return Err(invalid("index body length does not match the container"));
        }
        let prefix = hash_prefix(&mut file.try_clone()?, body_len)?;
        if prefix != index.superblock.body_prefix_hash {
            return Err(invalid("metadata belongs to a different encrypted body"));
        }
        Ok(Self {
            file,
            body_len,
            credential,
            index,
            seen_paths: HashMap::from([(ROOT_ID, String::new())]),
        })
    }

    pub fn lookup(&mut self, path: &str) -> Result<Option<EntryInfo>> {
        let path = normalize_archive_path(path)?;
        let value = self.index.lookup_path(&path)?;
        if let Some(record) = &value {
            self.seen_paths.insert(record.id, path);
        }
        Ok(value.map(EntryInfo::from))
    }

    pub fn list_children(
        &mut self,
        parent: EntryId,
        cursor: Option<IndexCursor>,
        limit: usize,
    ) -> Result<EntryPage<EntryInfo>> {
        let page = self.index.children(parent, cursor, limit)?;
        if let Some(parent_path) = self.seen_paths.get(&parent).cloned() {
            for entry in &page.entries {
                let path = if parent_path.is_empty() {
                    entry.name.clone()
                } else {
                    format!("{parent_path}/{}", entry.name)
                };
                self.seen_paths.insert(entry.id, path);
            }
        }
        Ok(EntryPage {
            entries: page.entries.into_iter().map(EntryInfo::from).collect(),
            next: page.next,
        })
    }

    pub fn extract(
        &mut self,
        destination: impl AsRef<Path>,
        selection: Selection,
        options: ExtractOptions,
    ) -> Result<()> {
        self.extract_controlled(destination, selection, options, &CancellationToken::new())
    }

    pub fn plan_extraction(
        &mut self,
        destination: impl AsRef<Path>,
        selection: Selection,
    ) -> Result<Vec<ExtractionConflict>> {
        self.plan_extraction_with_options(destination, selection, &ExtractOptions::default())
    }

    pub fn plan_extraction_with_options(
        &mut self,
        destination: impl AsRef<Path>,
        selection: Selection,
        options: &ExtractOptions,
    ) -> Result<Vec<ExtractionConflict>> {
        let destination = destination.as_ref();
        let selected = self.resolve_selection(
            selection,
            options.preserve_hierarchy,
            &CancellationToken::new(),
        )?;
        let mut conflicts = Vec::new();
        for (record, relative) in selected {
            let target = safe_target(destination, &relative)?;
            if let Ok(metadata) = fs::symlink_metadata(&target) {
                let kind = if metadata.file_type().is_symlink() {
                    ConflictKind::Blocked
                } else if record.kind == EntryKind::File && metadata.is_file() {
                    ConflictKind::ReplaceableFile
                } else if record.kind == EntryKind::Directory && metadata.is_dir() {
                    ConflictKind::ExistingDirectory
                } else {
                    ConflictKind::Blocked
                };
                conflicts.push(ExtractionConflict { path: target, kind });
            }
        }
        Ok(conflicts)
    }

    pub fn extract_controlled(
        &mut self,
        destination: impl AsRef<Path>,
        selection: Selection,
        options: ExtractOptions,
        cancellation: &CancellationToken,
    ) -> Result<()> {
        let mut ignore_progress = |_: OperationProgress| {};
        self.extract_with_progress(
            destination,
            selection,
            options,
            cancellation,
            &mut ignore_progress,
        )
    }

    pub fn extract_with_progress(
        &mut self,
        destination: impl AsRef<Path>,
        selection: Selection,
        options: ExtractOptions,
        cancellation: &CancellationToken,
        reporter: &mut dyn FnMut(OperationProgress),
    ) -> Result<()> {
        let destination = destination.as_ref();
        let mut progress = ProgressEmitter::new(reporter);
        progress.set_stage(OperationStage::ResolvingSelection, None, None);
        cancellation.checkpoint()?;
        let extraction_root = ExtractionRoot::open_or_create(destination)?;
        let selected =
            self.resolve_selection(selection, options.preserve_hierarchy, cancellation)?;
        let selected_entries = selected.len() as u64;
        let selected_bytes = selected
            .iter()
            .filter(|(record, _)| record.kind == EntryKind::File)
            .try_fold(0u64, |total, (record, _)| total.checked_add(record.size))
            .ok_or_else(|| invalid("selected content size overflow"))?;
        let mut preflight_walker = extraction_root.walker()?;
        preflight_capability(&mut preflight_walker, &selected, options.overwrite)
            .context("checking extraction targets")?;

        let mut directory_walker = extraction_root.walker()?;
        for (_, relative) in selected
            .iter()
            .filter(|(v, _)| v.kind == EntryKind::Directory)
        {
            cancellation.checkpoint()?;
            directory_walker.directory(relative, true)?;
        }

        cancellation.checkpoint()?;
        let body = FileRegion::new(self.file.try_clone()?, 0, self.body_len);
        let decrypted =
            decrypt_seekable(body, &self.credential).context("decrypting archive body")?;
        let mut decoder = zeekstd::Decoder::new(decrypted)?;
        progress.set_stage(
            OperationStage::Extracting,
            Some(selected_entries),
            Some(selected_bytes),
        );
        let mut file_walker = extraction_root.walker()?;
        for (record, relative) in selected.iter().filter(|(v, _)| v.kind == EntryKind::File) {
            cancellation.checkpoint()?;
            let (parent_path, name) = split_parent_name(relative)?;
            let parent = file_walker.directory(parent_path, true)?;
            decoder.set_offset(record.tar_offset)?;
            decoder.set_offset_limit(
                record
                    .tar_offset
                    .checked_add(record.size)
                    .ok_or_else(|| invalid("file offset overflow"))?,
            )?;
            let mut temp = ScopedTempFile::new(parent)?;
            let mut hasher = blake3::Hasher::new();
            let mut written = 0u64;
            let mut buffer = [0u8; 64 * 1024];
            while written < record.size {
                cancellation.checkpoint()?;
                let want = (record.size - written).min(buffer.len() as u64) as usize;
                let read = decoder.read(&mut buffer[..want])?;
                if read == 0 {
                    return Err(invalid("selected file data is truncated"));
                }
                temp.file_mut().write_all(&buffer[..read])?;
                hasher.update(&buffer[..read]);
                written += read as u64;
                progress.advance(0, read as u64, Some(relative.clone()));
            }
            if <[u8; 32]>::from(hasher.finalize()) != record.hash {
                return Err(invalid(format!(
                    "content hash mismatch for {}",
                    relative.display()
                )));
            }
            temp.sync_all()?;
            cancellation.checkpoint()?;
            temp.apply_metadata(record)?;
            temp.persist(name, options.overwrite)?;
            progress.advance(1, 0, Some(relative.clone()));
        }

        progress.set_stage(
            OperationStage::ApplyingMetadata,
            Some(selected_entries),
            None,
        );
        let mut symlink_walker = extraction_root.walker()?;
        for (record, relative) in selected
            .iter()
            .filter(|(v, _)| v.kind == EntryKind::Symlink)
        {
            cancellation.checkpoint()?;
            let (parent_path, name) = split_parent_name(relative)?;
            let parent = symlink_walker.directory(parent_path, true)?;
            let link = record
                .link_target
                .as_deref()
                .ok_or_else(|| invalid("symlink record has no target"))?;
            validate_link_target(relative, link)?;
            create_symlink_at(parent, link, name, record.link_is_dir)?;
            progress.advance(1, 0, Some(relative.clone()));
        }

        let mut directories: Vec<_> = selected
            .iter()
            .filter(|(record, _)| record.kind == EntryKind::Directory)
            .collect();
        directories.sort_by_key(|(_, path)| std::cmp::Reverse(path.components().count()));
        let mut metadata_walker = extraction_root.walker()?;
        for (record, relative) in directories {
            cancellation.checkpoint()?;
            let dir = metadata_walker.directory(relative, false)?;
            apply_directory_metadata(dir, record)?;
            progress.advance(1, 0, Some(relative.clone()));
        }
        progress.set_stage(OperationStage::Finalizing, None, None);
        progress.complete(selected_entries, selected_bytes);
        Ok(())
    }

    fn resolve_selection(
        &mut self,
        selection: Selection,
        preserve_hierarchy: bool,
        cancellation: &CancellationToken,
    ) -> Result<Vec<(EntryRecord, PathBuf)>> {
        let mut selected = Vec::new();
        match selection {
            Selection::All => {
                self.collect_children(ROOT_ID, PathBuf::new(), &mut selected, cancellation)?
            }
            Selection::Paths(paths) => {
                for path in paths {
                    cancellation.checkpoint()?;
                    let normalized = normalize_archive_path(&path)?;
                    let record = self
                        .index
                        .lookup_path(&normalized)?
                        .ok_or_else(|| not_found(&path))?;
                    let output_path = selection_output_path(&normalized, preserve_hierarchy)?;
                    self.collect_record(record, output_path, &mut selected, cancellation)?;
                }
            }
            Selection::EntryIds(ids) => {
                for id in ids {
                    cancellation.checkpoint()?;
                    let path = self
                        .seen_paths
                        .get(&id)
                        .cloned()
                        .ok_or_else(|| not_found(format!("entry ID {id} was not listed")))?;
                    let record = self
                        .index
                        .lookup_path(&path)?
                        .ok_or_else(|| not_found(&path))?;
                    let output_path = selection_output_path(&path, preserve_hierarchy)?;
                    self.collect_record(record, output_path, &mut selected, cancellation)?;
                }
            }
        }
        selected.sort_by_key(|(_, path)| path.clone());
        selected.dedup_by(|a, b| a.1 == b.1);
        Ok(selected)
    }

    fn collect_record(
        &mut self,
        record: EntryRecord,
        path: PathBuf,
        out: &mut Vec<(EntryRecord, PathBuf)>,
        cancellation: &CancellationToken,
    ) -> Result<()> {
        self.collect_stack(vec![(record, path)], out, cancellation)
    }

    fn collect_children(
        &mut self,
        parent: EntryId,
        path: PathBuf,
        out: &mut Vec<(EntryRecord, PathBuf)>,
        cancellation: &CancellationToken,
    ) -> Result<()> {
        let mut stack = Vec::new();
        self.push_children(parent, path, &mut stack, cancellation)?;
        self.collect_stack(stack, out, cancellation)
    }

    fn collect_stack(
        &mut self,
        mut stack: Vec<(EntryRecord, PathBuf)>,
        out: &mut Vec<(EntryRecord, PathBuf)>,
        cancellation: &CancellationToken,
    ) -> Result<()> {
        let mut seen = HashMap::<EntryId, PathBuf>::new();
        while let Some((record, path)) = stack.pop() {
            cancellation.checkpoint()?;
            validate_component(&record.name)?;
            if record.id == ROOT_ID {
                return Err(invalid("archive entry reuses the root ID"));
            }
            if let Some(previous) = seen.insert(record.id, path.clone()) {
                return Err(invalid(format!(
                    "archive entry ID {} occurs at both {} and {}",
                    record.id,
                    previous.display(),
                    path.display()
                )));
            }
            let recurse = record.kind == EntryKind::Directory;
            let id = record.id;
            out.push((record, path.clone()));
            if recurse {
                self.push_children(id, path, &mut stack, cancellation)?;
            }
        }
        Ok(())
    }

    fn push_children(
        &mut self,
        parent: EntryId,
        path: PathBuf,
        stack: &mut Vec<(EntryRecord, PathBuf)>,
        cancellation: &CancellationToken,
    ) -> Result<()> {
        let mut children = Vec::new();
        let mut cursor = None;
        loop {
            let page = self.index.children(parent, cursor, 1024)?;
            for record in page.entries {
                cancellation.checkpoint()?;
                if record.parent_id != parent {
                    return Err(invalid("index child has the wrong parent ID"));
                }
                validate_component(&record.name)?;
                let child_path = path.join(&record.name);
                children.push((record, child_path));
            }
            cursor = page.next;
            if cursor.is_none() {
                children.reverse();
                stack.extend(children);
                return Ok(());
            }
        }
    }
}

fn preflight_capability(
    walker: &mut DirWalker,
    entries: &[(EntryRecord, PathBuf)],
    overwrite: OverwritePolicy,
) -> Result<()> {
    let mut folded = std::collections::HashSet::new();
    for (record, relative) in entries {
        let text = relative
            .to_str()
            .ok_or_else(|| invalid_path(relative.display()))?;
        if !folded.insert(text.to_lowercase()) {
            return Err(invalid_path(format!(
                "case-insensitive path collision: {text}"
            )));
        }
        let (parent_path, name) = split_parent_name(relative)?;
        let parent = match walker.existing_directory(parent_path)? {
            Some(parent) => parent,
            None => continue,
        };
        match symlink_metadata_at(parent, name) {
            Ok(metadata) => {
                let allowed = overwrite == OverwritePolicy::ReplaceFiles
                    && ((record.kind == EntryKind::File && metadata.is_file())
                        || (record.kind == EntryKind::Directory && metadata.is_dir()));
                if !allowed {
                    return Err(crate::error::message(format!(
                        "target already exists: {}",
                        relative.display()
                    )));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn selection_output_path(path: &str, preserve_hierarchy: bool) -> Result<PathBuf> {
    if preserve_hierarchy {
        return Ok(PathBuf::from(path));
    }
    Path::new(path)
        .file_name()
        .map(PathBuf::from)
        .ok_or_else(|| invalid(format!("selected path has no file name: {path}")))
}
