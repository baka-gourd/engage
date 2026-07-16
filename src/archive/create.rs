use std::{
    collections::HashSet,
    ffi::OsStr,
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::UNIX_EPOCH,
};

use eros::Context;
use tempfile::NamedTempFile;
use zeekstd::{EncodeOptions, FrameSizePolicy};

use super::{
    BODY_FRAME_SIZE, BODY_PREFIX_SIZE, CreateOptions, EncryptCredential, INDEX_FRAME_SIZE,
    make_encryptor,
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
    let totals = scan_inputs(&inputs, cancellation, &mut progress)?;
    progress.set_stage(
        OperationStage::Archiving,
        Some(totals.entries),
        Some(totals.bytes),
    );

    let mut output = NamedTempFile::new_in(destination_parent)?;
    let staging_result: Result<()> = (|| {
        let mut index = IndexBuilder::new(destination_parent, options.sort_memory_bytes)?;
        let encryptor = make_encryptor(credential)?;
        let mut age_writer = encryptor.wrap_output(output.as_file_mut())?;
        let body_options = EncodeOptions::new()
            .compression_level(9)
            .checksum_flag(true)
            .frame_size_policy(FrameSizePolicy::Uncompressed(BODY_FRAME_SIZE));
        let mut zstd = body_options.into_encoder(&mut age_writer)?;
        let counter = CountingWriter::new(&mut zstd);
        let mut tar = tar::Builder::new(counter);
        let mut next_id = 1u64;
        for input in &inputs {
            let name = input
                .file_name()
                .ok_or_else(|| invalid_path(input.display()))?;
            append_source(
                &mut tar,
                &mut index,
                input,
                Path::new(name),
                ROOT_ID,
                &mut next_id,
                cancellation,
                &mut progress,
            )
            .with_context(|| format!("adding {}", input.display()))?;
        }
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

        let mut built = index.finish(destination_parent, tar_len, body_len, body_prefix_hash)?;
        let metadata_len = built.file.as_file().metadata()?.len();
        built.file.as_file_mut().seek(SeekFrom::Start(0))?;
        cancellation.checkpoint()?;
        progress.set_stage(OperationStage::WritingIndex, None, Some(metadata_len));
        append_metadata(
            output.as_file_mut(),
            body_len,
            &mut built,
            credential,
            options.metadata_segment_bytes,
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
    progress.complete(totals.entries, totals.bytes);
    Ok(())
}

fn append_metadata(
    output: &mut File,
    body_len: u64,
    built: &mut BuiltIndex,
    credential: &EncryptCredential,
    segment_size: u64,
    cancellation: &CancellationToken,
    progress: &mut ProgressEmitter<'_>,
) -> Result<()> {
    let mut segment_writer = SegmentWriter::new(output, body_len, segment_size)?;
    let encryptor = make_encryptor(credential)?;
    let mut age_writer = encryptor.wrap_output(&mut segment_writer)?;
    let options = EncodeOptions::new()
        .compression_level(9)
        .checksum_flag(true)
        .frame_size_policy(FrameSizePolicy::Uncompressed(INDEX_FRAME_SIZE));
    let mut zstd = options.into_encoder(&mut age_writer)?;
    io::copy(
        &mut MetadataProgressReader::new(built.file.as_file_mut(), cancellation, progress),
        &mut zstd,
    )?;
    zstd.finish()?;
    age_writer.finish()?;
    segment_writer.finish()?;
    Ok(())
}

fn validate_inputs(inputs: Vec<PathBuf>) -> Result<Vec<PathBuf>> {
    let mut canonical = Vec::with_capacity(inputs.len());
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
        canonical.push(fs::canonicalize(input)?);
    }
    for (i, current) in canonical.iter().enumerate() {
        for (j, other) in canonical.iter().enumerate() {
            if i != j && current.starts_with(other) {
                return Err(message(format!(
                    "{} is nested under {}",
                    inputs[i].display(),
                    inputs[j].display()
                )));
            }
        }
    }
    Ok(inputs)
}

#[derive(Default)]
struct InputTotals {
    entries: u64,
    bytes: u64,
}

fn scan_inputs(
    inputs: &[PathBuf],
    cancellation: &CancellationToken,
    progress: &mut ProgressEmitter<'_>,
) -> Result<InputTotals> {
    let mut totals = InputTotals::default();
    for input in inputs {
        scan_source(input, cancellation, progress, &mut totals)?;
    }
    Ok(totals)
}

fn scan_source(
    source: &Path,
    cancellation: &CancellationToken,
    progress: &mut ProgressEmitter<'_>,
    totals: &mut InputTotals,
) -> Result<()> {
    cancellation.checkpoint()?;
    let metadata = fs::symlink_metadata(source)?;
    let bytes = if metadata.is_file() {
        metadata.len()
    } else {
        0
    };
    totals.entries = totals
        .entries
        .checked_add(1)
        .ok_or_else(|| invalid("too many archive entries"))?;
    totals.bytes = totals
        .bytes
        .checked_add(bytes)
        .ok_or_else(|| invalid("archive input size overflow"))?;
    progress.advance(1, bytes, Some(source.to_path_buf()));

    if metadata.is_dir() {
        for child in fs::read_dir(source)? {
            scan_source(&child?.path(), cancellation, progress, totals)?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn append_source<W: Write>(
    tar: &mut tar::Builder<CountingWriter<W>>,
    index: &mut IndexBuilder,
    source: &Path,
    archive_path: &Path,
    parent_id: EntryId,
    next_id: &mut EntryId,
    cancellation: &CancellationToken,
    progress: &mut ProgressEmitter<'_>,
) -> Result<()> {
    cancellation.checkpoint()?;
    let metadata = fs::symlink_metadata(source)?;
    let name = archive_path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| invalid_path(archive_path.display()))?;
    validate_component(name)?;
    let id = *next_id;
    *next_id = next_id
        .checked_add(1)
        .ok_or_else(|| invalid("too many archive entries"))?;
    let mtime = metadata
        .modified()
        .ok()
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
        mode: metadata_mode(&metadata),
        hash: blake3::hash(&[]).into(),
        link_target: None,
        link_is_dir: false,
    };

    if file_type.is_file() {
        append_file(
            tar,
            source,
            archive_path,
            &metadata,
            &mut record,
            cancellation,
            progress,
        )?;
    } else if file_type.is_dir() {
        record.kind = EntryKind::Directory;
        let mut header = tar::Header::new_gnu();
        header.set_metadata(&metadata);
        header.set_size(0);
        header.set_entry_type(tar::EntryType::Directory);
        header.set_cksum();
        tar.append_data(&mut header, archive_path, io::empty())?;
        record.tar_offset = tar.get_ref().position;
    } else if file_type.is_symlink() {
        append_symlink(tar, source, archive_path, &metadata, &mut record)?;
    } else {
        return Err(message(format!(
            "unsupported filesystem entry: {}",
            source.display()
        )));
    }
    index.push(&record)?;
    progress.advance(1, 0, Some(source.to_path_buf()));

    if file_type.is_dir() {
        let mut children: Vec<_> = fs::read_dir(source)?.collect::<io::Result<_>>()?;
        children.sort_by_key(std::fs::DirEntry::file_name);
        for child in children {
            let child_name = child
                .file_name()
                .to_str()
                .ok_or_else(|| invalid_path(child.path().display()))?
                .to_owned();
            append_source(
                tar,
                index,
                &child.path(),
                &archive_path.join(child_name),
                id,
                next_id,
                cancellation,
                progress,
            )?;
        }
    }
    Ok(())
}

fn append_file<W: Write>(
    tar: &mut tar::Builder<CountingWriter<W>>,
    source: &Path,
    archive_path: &Path,
    metadata: &fs::Metadata,
    record: &mut EntryRecord,
    cancellation: &CancellationToken,
    progress: &mut ProgressEmitter<'_>,
) -> Result<()> {
    let size = metadata.len();
    let mut reader = HashingReader::new(
        File::open(source)?.take(size),
        cancellation,
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
    source: &Path,
    archive_path: &Path,
    metadata: &fs::Metadata,
    record: &mut EntryRecord,
) -> Result<()> {
    let target = fs::read_link(source)?;
    let target_string = target
        .to_str()
        .ok_or_else(|| invalid_path(target.display()))?
        .replace('\\', "/");
    validate_link_target(archive_path, &target_string)?;
    record.kind = EntryKind::Symlink;
    record.link_target = Some(target_string);
    record.link_is_dir = fs::metadata(source).is_ok_and(|value| value.is_dir());
    let mut header = tar::Header::new_gnu();
    header.set_metadata(metadata);
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
    progress: &'a mut ProgressEmitter<'b>,
    path: PathBuf,
}

impl<'a, 'b, R> HashingReader<'a, 'b, R> {
    fn new(
        inner: R,
        cancellation: &'a CancellationToken,
        progress: &'a mut ProgressEmitter<'b>,
        path: PathBuf,
    ) -> Self {
        Self {
            inner,
            hasher: blake3::Hasher::new(),
            bytes: 0,
            cancellation,
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
