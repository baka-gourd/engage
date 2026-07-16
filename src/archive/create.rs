use std::{
    collections::HashSet,
    ffi::{OsStr, OsString},
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{SyncSender, sync_channel},
    },
    thread,
    time::UNIX_EPOCH,
};

use cap_fs_ext::{DirExt as _, FollowSymlinks, OpenOptionsFollowExt as _};
use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions},
};
use eros::Context;
use same_file::Handle as FileIdentity;
use tempfile::NamedTempFile;

use super::{
    BODY_FRAME_SIZE, BODY_PREFIX_SIZE, CreateOptions, EncryptCredential, INDEX_FRAME_SIZE,
    make_encryptor,
    parallel_zstd::SeekableEncoder,
    path::{metadata_mode, validate_component, validate_link_target},
};
use crate::{
    CancellationToken, OperationProgress, OperationStage, Result,
    error::{invalid, invalid_path, message},
    format::SegmentWriter,
    index::{BuiltIndex, EntryId, EntryKind, EntryRecord, IndexBuilder, ROOT_ID},
    progress::ProgressEmitter,
};

pub fn create_archive(
    inputs: impl IntoIterator<Item = PathBuf>,
    destination: impl AsRef<Path>,
    credential: &EncryptCredential,
    options: CreateOptions,
) -> Result<()> {
    create_archive_controlled(
        inputs,
        destination,
        credential,
        options,
        false,
        &CancellationToken::new(),
    )
}

pub fn create_archive_controlled(
    inputs: impl IntoIterator<Item = PathBuf>,
    destination: impl AsRef<Path>,
    credential: &EncryptCredential,
    options: CreateOptions,
    overwrite: bool,
    cancellation: &CancellationToken,
) -> Result<()> {
    let mut ignore_progress = |_: OperationProgress| {};
    create_archive_with_progress(
        inputs,
        destination,
        credential,
        options,
        overwrite,
        cancellation,
        &mut ignore_progress,
    )
}

pub fn create_archive_with_progress(
    inputs: impl IntoIterator<Item = PathBuf>,
    destination: impl AsRef<Path>,
    credential: &EncryptCredential,
    options: CreateOptions,
    overwrite: bool,
    cancellation: &CancellationToken,
    reporter: &mut dyn FnMut(OperationProgress),
) -> Result<()> {
    let destination = destination.as_ref();
    let compression_thread_limit = compression_thread_limit(&options)?;
    let mut progress = ProgressEmitter::new(reporter);
    progress.set_stage(OperationStage::Scanning, None, None);
    cancellation.checkpoint()?;
    if destination.exists() && !overwrite {
        return Err(message(format!(
            "target already exists: {}",
            destination.display()
        )));
    }
    let destination_parent = destination.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(destination_parent)?;
    let inputs =
        validate_inputs(inputs.into_iter().collect()).context("validating archive inputs")?;
    if inputs.is_empty() {
        return Err(invalid("at least one input is required"));
    }
    let mut output = NamedTempFile::new_in(destination_parent)?;
    let mut index = IndexBuilder::new(destination_parent, options.sort_memory_bytes)?;
    let exclusions = SourceExclusions::new(
        destination_parent,
        [output.path(), index.temporary_path()],
        if overwrite && destination.exists() {
            Some(destination)
        } else {
            None
        },
    )?;
    let totals_exclusions = SourceExclusions::new(
        destination_parent,
        [output.path(), index.temporary_path()],
        if overwrite && destination.exists() {
            Some(destination)
        } else {
            None
        },
    )?;
    progress.set_stage(OperationStage::Archiving, None, None);

    let mut completed_totals = (0, 0);
    let staging_result: Result<()> = (|| {
        let encryptor = make_encryptor(credential)?;
        let mut age_writer = encryptor.wrap_output(output.as_file_mut())?;
        let mut zstd = SeekableEncoder::new(
            &mut age_writer,
            BODY_FRAME_SIZE,
            1,
            compression_thread_limit,
            cancellation,
        )?;
        let counter = CountingWriter::new(&mut zstd);
        let mut tar = tar::Builder::new(counter);
        let scan_status = Arc::new(ScanStatus::default());
        let (entry_tx, entry_rx) = sync_channel(4_096);
        thread::scope(|scope| -> Result<()> {
            let totals_status = scan_status.clone();
            let totals_inputs = inputs.clone();
            let totals_scanner = scope.spawn(move || {
                let result = scan_input_totals(&totals_inputs, &totals_exclusions, cancellation);
                if let Ok(totals) = result {
                    totals_status.publish(totals);
                }
                result
            });
            let producer =
                scope.spawn(move || produce_inputs(&inputs, &exclusions, cancellation, &entry_tx));
            let consume_result = (|| {
                while let Ok(entry) = entry_rx.recv() {
                    let source = entry.source.clone();
                    append_scanned_entry(
                        &mut tar,
                        &mut index,
                        entry,
                        cancellation,
                        &scan_status,
                        &mut progress,
                    )
                    .with_context(|| format!("adding {}", source.display()))?;
                }
                cancellation.checkpoint()
            })();
            drop(entry_rx);
            let produce_result = producer
                .join()
                .map_err(|_| message("archive scanner panicked"))?;
            if consume_result.is_err() || produce_result.is_err() {
                cancellation.cancel();
            }
            let _ = totals_scanner.join();
            consume_result?;
            produce_result?;
            scan_status.apply(&mut progress);
            Ok(())
        })?;
        cancellation.checkpoint()?;
        tar.finish()?;
        let counter = tar.into_inner()?;
        let tar_len = counter.position;
        zstd.finish()?;
        age_writer.finish()?;
        let body_len = output.as_file_mut().stream_position()?;
        output.as_file_mut().flush()?;
        let body_prefix_hash = hash_prefix(output.as_file_mut(), body_len)?;
        output.as_file_mut().seek(SeekFrom::Start(body_len))?;

        let archive_totals = progress.completed_work();
        completed_totals = archive_totals;
        let index_work = archive_totals
            .0
            .checked_mul(2)
            .ok_or_else(|| invalid("too many index records to report progress"))?;
        progress.set_stage(OperationStage::BuildingIndex, Some(index_work), None);
        let mut pending_index_progress = 0u64;
        let mut reported_index_progress = 0u64;
        let mut report_index_progress = |records| {
            pending_index_progress += records;
            if pending_index_progress >= 256
                || reported_index_progress + pending_index_progress == index_work
            {
                progress.advance(pending_index_progress, 0, None);
                reported_index_progress += pending_index_progress;
                pending_index_progress = 0;
            }
        };
        let mut built = index.finish(
            destination_parent,
            tar_len,
            body_len,
            body_prefix_hash,
            &mut report_index_progress,
        )?;
        let metadata_len = built.file.as_file().metadata()?.len();
        built.file.as_file_mut().seek(SeekFrom::Start(0))?;
        cancellation.checkpoint()?;
        progress.set_stage(OperationStage::WritingIndex, None, Some(metadata_len));
        append_metadata(
            output.as_file_mut(),
            body_len,
            &mut built,
            credential,
            MetadataCompression {
                segment_size: options.metadata_segment_bytes,
                input_len: metadata_len,
                thread_limit: compression_thread_limit,
            },
            cancellation,
            &mut progress,
        )
        .context("writing encrypted metadata index")?;
        output.as_file_mut().sync_all()?;
        cancellation.checkpoint()?;
        progress.set_stage(OperationStage::Finalizing, None, None);
        Ok(())
    })();
    if let Err(operation_error) = staging_result {
        let temporary_path = output.path().to_owned();
        if let Err(cleanup_error) = output.close() {
            return Err(message(format!(
                "{operation_error:#?}; failed to remove temporary archive {}: {cleanup_error}",
                temporary_path.display()
            )));
        }
        return Err(operation_error);
    }
    if overwrite {
        output.persist(destination).map_err(|error| error.error)?;
    } else {
        output
            .persist_noclobber(destination)
            .map_err(|error| error.error)?;
    }
    progress.complete(completed_totals.0, completed_totals.1);
    Ok(())
}

struct MetadataCompression {
    segment_size: u64,
    input_len: u64,
    thread_limit: usize,
}

fn append_metadata(
    output: &mut File,
    body_len: u64,
    built: &mut BuiltIndex,
    credential: &EncryptCredential,
    compression: MetadataCompression,
    cancellation: &CancellationToken,
    progress: &mut ProgressEmitter<'_>,
) -> Result<()> {
    let mut segment_writer = SegmentWriter::new(output, body_len, compression.segment_size)?;
    let encryptor = make_encryptor(credential)?;
    let mut age_writer = encryptor.wrap_output(&mut segment_writer)?;
    let frame_count = compression
        .input_len
        .div_ceil(INDEX_FRAME_SIZE as u64)
        .max(1);
    let frames_per_job = (BODY_FRAME_SIZE / INDEX_FRAME_SIZE) as usize;
    let job_count = frame_count.div_ceil(frames_per_job as u64);
    let workers = compression.thread_limit.min(job_count as usize).max(1);
    let mut zstd = SeekableEncoder::new(
        &mut age_writer,
        INDEX_FRAME_SIZE,
        frames_per_job,
        workers,
        cancellation,
    )?;
    io::copy(
        &mut MetadataProgressReader::new(built.file.as_file_mut(), cancellation, progress),
        &mut zstd,
    )?;
    zstd.finish()?;
    age_writer.finish()?;
    segment_writer.finish()?;
    Ok(())
}

fn compression_thread_limit(options: &CreateOptions) -> Result<usize> {
    if options.compression_threads == Some(0) {
        return Err(invalid("compression thread count must be at least one"));
    }
    Ok(options.compression_threads.unwrap_or_else(|| {
        automatic_compression_thread_limit(
            std::thread::available_parallelism().map_or(1, usize::from),
        )
    }))
}

fn automatic_compression_thread_limit(available: usize) -> usize {
    available.saturating_sub(1).clamp(1, 5)
}

fn validate_inputs(inputs: Vec<PathBuf>) -> Result<Vec<PathBuf>> {
    let mut names = HashSet::new();
    for input in &inputs {
        if !input.exists() && fs::symlink_metadata(input).is_err() {
            return Err(message(format!(
                "input does not exist: {}",
                input.display()
            )));
        }
        let name = input
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or_else(|| invalid_path(input.display()))?;
        validate_component(name)?;
        if !names.insert(name.to_lowercase()) {
            return Err(message(format!(
                "input names collide in the archive root: {name}"
            )));
        }
    }
    let mut ordered = inputs.iter().collect::<Vec<_>>();
    ordered.sort_unstable();
    for pair in ordered.windows(2) {
        let [parent, input] = pair else {
            unreachable!("windows(2) always contains two paths");
        };
        if input.starts_with(parent) {
            return Err(message(format!(
                "nested inputs are not supported: {} is inside {}",
                input.display(),
                parent.display()
            )));
        }
    }
    Ok(inputs)
}

fn open_parent(path: &Path) -> Result<(Dir, OsString)> {
    let name = path
        .file_name()
        .ok_or_else(|| invalid_path(path.display()))?
        .to_owned();
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    Ok((Dir::open_ambient_dir(parent, ambient_authority())?, name))
}

fn open_file_nofollow(parent: &Dir, name: &OsStr) -> Result<cap_std::fs::File> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    Ok(parent.open_with(name, &options)?)
}

struct SourceExclusions {
    parent: FileIdentity,
    names: HashSet<OsString>,
}

impl SourceExclusions {
    fn new<'a>(
        parent: &Path,
        temporary_paths: impl IntoIterator<Item = &'a Path>,
        destination: Option<&Path>,
    ) -> Result<Self> {
        let parent_dir = Dir::open_ambient_dir(parent, ambient_authority())?;
        let parent = FileIdentity::from_file(parent_dir.into_std_file())?;
        let mut names = HashSet::new();
        for path in temporary_paths {
            if let Some(name) = path.file_name() {
                names.insert(name.to_owned());
            }
        }
        if let Some(name) = destination.and_then(Path::file_name) {
            names.insert(name.to_owned());
        }
        Ok(Self { parent, names })
    }

    fn skips_directory_entry(&self, directory: &Dir, name: &OsStr) -> Result<bool> {
        if !self.names.contains(name) {
            return Ok(false);
        }
        let directory = FileIdentity::from_file(directory.try_clone()?.into_std_file())?;
        Ok(directory == self.parent)
    }
}

#[derive(Debug, Clone, Copy)]
struct InputTotals {
    entries: u64,
    bytes: u64,
}

#[derive(Default)]
struct ScanStatus {
    entries: AtomicU64,
    bytes: AtomicU64,
    complete: AtomicBool,
    reported: AtomicBool,
}

impl ScanStatus {
    fn publish(&self, totals: InputTotals) {
        self.entries.store(totals.entries, Ordering::Relaxed);
        self.bytes.store(totals.bytes, Ordering::Relaxed);
        self.complete.store(true, Ordering::Release);
    }

    fn apply(&self, progress: &mut ProgressEmitter<'_>) {
        if self.complete.load(Ordering::Acquire) && !self.reported.swap(true, Ordering::AcqRel) {
            progress.set_totals(
                self.entries.load(Ordering::Relaxed),
                self.bytes.load(Ordering::Relaxed),
            );
        }
    }
}

struct ScannedEntry {
    parent: Arc<Dir>,
    name_on_disk: OsString,
    source: PathBuf,
    archive_path: PathBuf,
    parent_id: EntryId,
    id: EntryId,
}

fn produce_inputs(
    inputs: &[PathBuf],
    exclusions: &SourceExclusions,
    cancellation: &CancellationToken,
    sender: &SyncSender<ScannedEntry>,
) -> Result<()> {
    let mut next_id = 1;
    for input in inputs {
        let (parent, name) = open_parent(input)?;
        let archive_path = PathBuf::from(&name);
        produce_source(
            Arc::new(parent),
            name,
            input.clone(),
            archive_path,
            ROOT_ID,
            &mut next_id,
            exclusions,
            cancellation,
            sender,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn produce_source(
    parent: Arc<Dir>,
    name_on_disk: OsString,
    source: PathBuf,
    archive_path: PathBuf,
    parent_id: EntryId,
    next_id: &mut EntryId,
    exclusions: &SourceExclusions,
    cancellation: &CancellationToken,
    sender: &SyncSender<ScannedEntry>,
) -> Result<()> {
    cancellation.checkpoint()?;
    let metadata = parent.symlink_metadata(&name_on_disk)?;
    let id = *next_id;
    *next_id = next_id
        .checked_add(1)
        .ok_or_else(|| invalid("too many archive entries"))?;
    sender
        .send(ScannedEntry {
            parent: parent.clone(),
            name_on_disk: name_on_disk.clone(),
            source: source.clone(),
            archive_path: archive_path.clone(),
            parent_id,
            id,
        })
        .map_err(|_| message("archive consumer stopped"))?;

    if metadata.is_dir() {
        let directory = Arc::new(parent.open_dir_nofollow(&name_on_disk)?);
        let mut children = directory.entries()?.collect::<io::Result<Vec<_>>>()?;
        children.sort_by_key(cap_std::fs::DirEntry::file_name);
        for child in children {
            let child_name = child.file_name();
            if exclusions.skips_directory_entry(&directory, &child_name)? {
                continue;
            }
            let archive_child_name = child_name
                .to_str()
                .ok_or_else(|| invalid_path(source.join(&child_name).display()))?
                .to_owned();
            produce_source(
                directory.clone(),
                child_name.clone(),
                source.join(&child_name),
                archive_path.join(archive_child_name),
                id,
                next_id,
                exclusions,
                cancellation,
                sender,
            )?;
        }
    }
    Ok(())
}

fn scan_input_totals(
    inputs: &[PathBuf],
    exclusions: &SourceExclusions,
    cancellation: &CancellationToken,
) -> Result<InputTotals> {
    let mut totals = InputTotals {
        entries: 0,
        bytes: 0,
    };
    for input in inputs {
        let (parent, name) = open_parent(input)?;
        scan_source_totals(&parent, &name, exclusions, cancellation, &mut totals)?;
    }
    Ok(totals)
}

fn scan_source_totals(
    parent: &Dir,
    name_on_disk: &OsStr,
    exclusions: &SourceExclusions,
    cancellation: &CancellationToken,
    totals: &mut InputTotals,
) -> Result<()> {
    cancellation.checkpoint()?;
    let metadata = parent.symlink_metadata(name_on_disk)?;
    totals.entries = totals
        .entries
        .checked_add(1)
        .ok_or_else(|| invalid("too many archive entries"))?;
    if metadata.is_file() {
        totals.bytes = totals
            .bytes
            .checked_add(metadata.len())
            .ok_or_else(|| invalid("archive input size overflow"))?;
    } else if metadata.is_dir() {
        let directory = parent.open_dir_nofollow(name_on_disk)?;
        for child in directory.entries()? {
            let child_name = child?.file_name();
            if exclusions.skips_directory_entry(&directory, &child_name)? {
                continue;
            }
            scan_source_totals(&directory, &child_name, exclusions, cancellation, totals)?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn append_scanned_entry<W: Write>(
    tar: &mut tar::Builder<CountingWriter<W>>,
    index: &mut IndexBuilder,
    entry: ScannedEntry,
    cancellation: &CancellationToken,
    scan_status: &ScanStatus,
    progress: &mut ProgressEmitter<'_>,
) -> Result<()> {
    cancellation.checkpoint()?;
    let ScannedEntry {
        parent,
        name_on_disk,
        source,
        archive_path,
        parent_id,
        id,
    } = entry;
    let metadata = parent.symlink_metadata(&name_on_disk)?;
    let name = archive_path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| invalid_path(archive_path.display()))?;
    validate_component(name)?;
    let mtime = metadata
        .modified()
        .ok()
        .map(cap_std::time::SystemTime::into_std)
        .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |value| value.as_secs() as i64);
    let file_type = metadata.file_type();
    let mut record = EntryRecord {
        id,
        parent_id,
        name: name.to_owned(),
        kind: EntryKind::File,
        tar_offset: 0,
        size: 0,
        mtime,
        mode: if metadata.permissions().readonly() {
            0o444
        } else {
            0o644
        },
        hash: blake3::hash(&[]).into(),
        link_target: None,
        link_is_dir: false,
    };
    if file_type.is_file() {
        let file = open_file_nofollow(&parent, &name_on_disk)?;
        let std_metadata = file.try_clone()?.into_std().metadata()?;
        record.mode = metadata_mode(&std_metadata);
        append_file(
            tar,
            file.into_std(),
            &source,
            &archive_path,
            &std_metadata,
            &mut record,
            cancellation,
            scan_status,
            progress,
        )?;
    } else if file_type.is_dir() {
        let directory = parent.open_dir_nofollow(&name_on_disk)?;
        let std_metadata = directory.try_clone()?.into_std_file().metadata()?;
        record.mode = metadata_mode(&std_metadata);
        record.kind = EntryKind::Directory;
        let mut header = tar::Header::new_gnu();
        header.set_metadata(&std_metadata);
        header.set_size(0);
        header.set_entry_type(tar::EntryType::Directory);
        header.set_cksum();
        tar.append_data(&mut header, &archive_path, io::empty())?;
        record.tar_offset = tar.get_ref().position;
    } else if file_type.is_symlink() {
        append_symlink(tar, &parent, &name_on_disk, &archive_path, &mut record)?;
    } else {
        return Err(message(format!(
            "unsupported filesystem entry: {}",
            source.display()
        )));
    }
    index.push(&record)?;
    scan_status.apply(progress);
    progress.advance(1, 0, Some(source));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn append_file<W: Write>(
    tar: &mut tar::Builder<CountingWriter<W>>,
    file: File,
    source: &Path,
    archive_path: &Path,
    metadata: &fs::Metadata,
    record: &mut EntryRecord,
    cancellation: &CancellationToken,
    scan_status: &ScanStatus,
    progress: &mut ProgressEmitter<'_>,
) -> Result<()> {
    let size = metadata.len();
    let mut reader = HashingReader::new(
        file.take(size),
        cancellation,
        scan_status,
        progress,
        source.to_path_buf(),
    );
    let mut header = tar::Header::new_gnu();
    header.set_metadata(metadata);
    header.set_size(size);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_cksum();
    tar.append_data(&mut header, archive_path, &mut reader)?;
    if reader.bytes != size {
        return Err(message(format!(
            "archive changed while it was being created: {}",
            source.display()
        )));
    }
    record.tar_offset = tar.get_ref().position - size.div_ceil(512) * 512;
    record.size = size;
    record.hash = reader.hasher.finalize().into();
    Ok(())
}

fn append_symlink<W: Write>(
    tar: &mut tar::Builder<CountingWriter<W>>,
    parent: &Dir,
    name_on_disk: &OsStr,
    archive_path: &Path,
    record: &mut EntryRecord,
) -> Result<()> {
    let target = parent.read_link(name_on_disk)?;
    let target_string = target
        .to_str()
        .ok_or_else(|| invalid_path(target.display()))?
        .replace('\\', "/");
    validate_link_target(archive_path, &target_string)?;
    record.kind = EntryKind::Symlink;
    record.link_target = Some(target_string);
    record.link_is_dir = parent
        .metadata(name_on_disk)
        .is_ok_and(|value| value.is_dir());
    let mut header = tar::Header::new_gnu();
    header.set_mode(record.mode);
    header.set_mtime(record.mtime.max(0) as u64);
    header.set_size(0);
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_cksum();
    tar.append_link(&mut header, archive_path, &target)?;
    record.tar_offset = tar.get_ref().position;
    Ok(())
}

pub(super) fn hash_prefix(file: &mut File, len: u64) -> Result<[u8; 32]> {
    file.seek(SeekFrom::Start(0))?;
    let mut limited = file.take(len.min(BODY_PREFIX_SIZE as u64));
    let mut hasher = blake3::Hasher::new();
    io::copy(&mut limited, &mut hasher)?;
    Ok(hasher.finalize().into())
}

struct HashingReader<'a, 'b, R> {
    inner: R,
    hasher: blake3::Hasher,
    bytes: u64,
    cancellation: &'a CancellationToken,
    scan_status: &'a ScanStatus,
    progress: &'a mut ProgressEmitter<'b>,
    path: PathBuf,
}

impl<'a, 'b, R> HashingReader<'a, 'b, R> {
    fn new(
        inner: R,
        cancellation: &'a CancellationToken,
        scan_status: &'a ScanStatus,
        progress: &'a mut ProgressEmitter<'b>,
        path: PathBuf,
    ) -> Self {
        Self {
            inner,
            hasher: blake3::Hasher::new(),
            bytes: 0,
            cancellation,
            scan_status,
            progress,
            path,
        }
    }
}

impl<R: Read> Read for HashingReader<'_, '_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.cancellation.io_checkpoint()?;
        let read = self.inner.read(buffer)?;
        self.hasher.update(&buffer[..read]);
        self.bytes += read as u64;
        if read != 0 {
            self.scan_status.apply(self.progress);
            self.progress
                .advance(0, read as u64, Some(self.path.clone()));
        }
        Ok(read)
    }
}

struct MetadataProgressReader<'a, 'b, R> {
    inner: R,
    cancellation: &'a CancellationToken,
    progress: &'a mut ProgressEmitter<'b>,
}

impl<'a, 'b, R> MetadataProgressReader<'a, 'b, R> {
    fn new(
        inner: R,
        cancellation: &'a CancellationToken,
        progress: &'a mut ProgressEmitter<'b>,
    ) -> Self {
        Self {
            inner,
            cancellation,
            progress,
        }
    }
}

impl<R: Read> Read for MetadataProgressReader<'_, '_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.cancellation.io_checkpoint()?;
        let read = self.inner.read(buffer)?;
        if read != 0 {
            self.progress.advance(0, read as u64, None);
        }
        Ok(read)
    }
}

struct CountingWriter<W> {
    inner: W,
    position: u64,
}

impl<W> CountingWriter<W> {
    fn new(inner: W) -> Self {
        Self { inner, position: 0 }
    }
}

impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buffer)?;
        self.position += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::{automatic_compression_thread_limit, validate_inputs};

    #[test]
    fn automatic_compression_workers_reserve_one_cpu_and_cap_at_five() {
        assert_eq!(automatic_compression_thread_limit(1), 1);
        assert_eq!(automatic_compression_thread_limit(2), 1);
        assert_eq!(automatic_compression_thread_limit(4), 3);
        assert_eq!(automatic_compression_thread_limit(6), 5);
        assert_eq!(automatic_compression_thread_limit(20), 5);
    }

    #[test]
    fn nested_inputs_are_rejected_after_sorting_regardless_of_input_order() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("parent");
        let child = parent.join("child.txt");
        std::fs::create_dir(&parent).unwrap();
        std::fs::write(&child, b"child").unwrap();

        for inputs in [
            vec![parent.clone(), child.clone()],
            vec![child.clone(), parent.clone()],
        ] {
            let error = validate_inputs(inputs).unwrap_err();
            assert!(error.to_string().contains("nested inputs"));
        }
    }
}
