use std::{
    cmp::Ordering,
    collections::{BinaryHeap, HashMap},
    fs::File,
    io::{BufReader, Read, Seek, SeekFrom, Write},
    path::Path,
};

use tempfile::NamedTempFile;

use crate::{Result, error::invalid};

pub type EntryId = u64;
pub const ROOT_ID: EntryId = 0;
pub(crate) const PAGE_SIZE: usize = 64 * 1024;
const HEADER_SIZE: usize = 32;
const PAYLOAD_SIZE: usize = PAGE_SIZE - HEADER_SIZE;
const PAGE_MAGIC: &[u8; 4] = b"EIDX";
const PAGE_SUPER: u8 = 0;
const PAGE_INTERNAL: u8 = 1;
const PAGE_LEAF: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Directory,
    Symlink,
}

#[derive(Debug, Clone)]
pub struct EntryRecord {
    pub id: EntryId,
    pub parent_id: EntryId,
    pub name: String,
    pub kind: EntryKind,
    pub tar_offset: u64,
    pub size: u64,
    pub mtime: i64,
    pub mode: u32,
    pub hash: [u8; 32],
    pub link_target: Option<String>,
    pub link_is_dir: bool,
}

impl EntryRecord {
    fn key(&self) -> Key {
        Key {
            parent_id: self.parent_id,
            name: self.name.clone(),
        }
    }

    fn encode(&self) -> Result<Vec<u8>> {
        let name = self.name.as_bytes();
        let link = self.link_target.as_deref().unwrap_or("").as_bytes();
        if name.len() > u16::MAX as usize || link.len() > u16::MAX as usize {
            return Err(invalid("index name or link target is too long"));
        }
        let mut out = Vec::with_capacity(96 + name.len() + link.len());
        out.extend_from_slice(&self.id.to_le_bytes());
        out.extend_from_slice(&self.parent_id.to_le_bytes());
        out.push(match self.kind {
            EntryKind::File => 0,
            EntryKind::Directory => 1,
            EntryKind::Symlink => 2,
        });
        out.push(u8::from(self.link_is_dir));
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&(link.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&self.tar_offset.to_le_bytes());
        out.extend_from_slice(&self.size.to_le_bytes());
        out.extend_from_slice(&self.mtime.to_le_bytes());
        out.extend_from_slice(&self.mode.to_le_bytes());
        out.extend_from_slice(&self.hash);
        out.extend_from_slice(name);
        out.extend_from_slice(link);
        Ok(out)
    }

    fn decode(mut bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 84 {
            return Err(invalid("truncated index record"));
        }
        let id = take_u64(&mut bytes)?;
        let parent_id = take_u64(&mut bytes)?;
        let kind = match take_u8(&mut bytes)? {
            0 => EntryKind::File,
            1 => EntryKind::Directory,
            2 => EntryKind::Symlink,
            _ => return Err(invalid("unknown entry kind")),
        };
        let link_is_dir = take_u8(&mut bytes)? != 0;
        let name_len = take_u16(&mut bytes)? as usize;
        let link_len = take_u16(&mut bytes)? as usize;
        let _reserved = take_u16(&mut bytes)?;
        let tar_offset = take_u64(&mut bytes)?;
        let size = take_u64(&mut bytes)?;
        let mtime = take_i64(&mut bytes)?;
        let mode = take_u32(&mut bytes)?;
        if bytes.len() < 32 + name_len + link_len {
            return Err(invalid("truncated index record strings"));
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes[..32]);
        bytes = &bytes[32..];
        let name = std::str::from_utf8(&bytes[..name_len])
            .map_err(|_| invalid("index name is not UTF-8"))?
            .to_owned();
        let link_target = if link_len == 0 {
            None
        } else {
            Some(
                std::str::from_utf8(&bytes[name_len..name_len + link_len])
                    .map_err(|_| invalid("link target is not UTF-8"))?
                    .to_owned(),
            )
        };
        Ok(Self {
            id,
            parent_id,
            name,
            kind,
            tar_offset,
            size,
            mtime,
            mode,
            hash,
            link_target,
            link_is_dir,
        })
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct Key {
    parent_id: u64,
    name: String,
}

impl Ord for Key {
    fn cmp(&self, other: &Self) -> Ordering {
        self.parent_id
            .cmp(&other.parent_id)
            .then_with(|| self.name.as_bytes().cmp(other.name.as_bytes()))
    }
}

impl PartialOrd for Key {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn write_record(mut writer: impl Write, record: &EntryRecord) -> Result<usize> {
    let encoded = record.encode()?;
    writer.write_all(&(encoded.len() as u32).to_le_bytes())?;
    writer.write_all(&encoded)?;
    Ok(encoded.len() + 4)
}

fn read_record(mut reader: impl Read) -> Result<Option<EntryRecord>> {
    let mut len = [0u8; 4];
    let mut read = 0;
    while read < 4 {
        match reader.read(&mut len[read..])? {
            0 if read == 0 => return Ok(None),
            0 => return Err(invalid("truncated spool record length")),
            n => read += n,
        }
    }
    let len = u32::from_le_bytes(len) as usize;
    if len > PAGE_SIZE * 4 {
        return Err(invalid("unreasonably large index record"));
    }
    let mut bytes = vec![0; len];
    reader.read_exact(&mut bytes)?;
    Ok(Some(EntryRecord::decode(&bytes)?))
}

pub(crate) struct IndexBuilder {
    spool: NamedTempFile,
    count: u64,
    sort_memory: usize,
}

pub(crate) struct BuiltIndex {
    pub file: NamedTempFile,
}

impl IndexBuilder {
    pub(crate) fn new(temp_dir: &Path, sort_memory: usize) -> Result<Self> {
        Ok(Self {
            spool: NamedTempFile::new_in(temp_dir)?,
            count: 0,
            sort_memory: sort_memory.max(PAGE_SIZE * 2),
        })
    }

    pub(crate) fn push(&mut self, record: &EntryRecord) -> Result<()> {
        write_record(self.spool.as_file_mut(), record)?;
        self.count += 1;
        Ok(())
    }

    pub(crate) fn finish(
        mut self,
        temp_dir: &Path,
        tar_len: u64,
        body_len: u64,
        body_prefix_hash: [u8; 32],
    ) -> Result<BuiltIndex> {
        self.spool.as_file_mut().flush()?;
        self.spool.as_file_mut().seek(SeekFrom::Start(0))?;
        let mut runs = Vec::new();
        loop {
            let mut records = Vec::new();
            let mut bytes = 0usize;
            while bytes < self.sort_memory {
                match read_record(self.spool.as_file_mut())? {
                    Some(record) => {
                        bytes += record.encode()?.len() + 4;
                        records.push(record);
                    }
                    None => break,
                }
            }
            if records.is_empty() {
                break;
            }
            records.sort_unstable_by_key(EntryRecord::key);
            let mut run = NamedTempFile::new_in(temp_dir)?;
            for record in &records {
                write_record(run.as_file_mut(), record)?;
            }
            run.as_file_mut().flush()?;
            runs.push(run);
        }

        let mut page_file = NamedTempFile::new_in(temp_dir)?;
        page_file.as_file_mut().write_all(&vec![0u8; PAGE_SIZE])?;
        let mut readers: Vec<_> = runs
            .iter_mut()
            .map(|run| {
                run.as_file_mut().seek(SeekFrom::Start(0)).unwrap();
                BufReader::new(run.as_file().try_clone().unwrap())
            })
            .collect();
        let mut heap = BinaryHeap::new();
        for (run, reader) in readers.iter_mut().enumerate() {
            if let Some(record) = read_record(reader)? {
                heap.push(HeapItem { run, record });
            }
        }

        let mut leaf_descriptors = Vec::new();
        let mut payload = Vec::with_capacity(PAYLOAD_SIZE);
        let mut first_key = None;
        let mut leaf_count = 0u32;
        let mut page_id = 1u64;
        while let Some(item) = heap.pop() {
            let run = item.run;
            let encoded = item.record.encode()?;
            let needed = 4 + encoded.len();
            if needed > PAYLOAD_SIZE {
                return Err(invalid("index record exceeds page size"));
            }
            if payload.len() + needed > PAYLOAD_SIZE {
                write_page(
                    page_file.as_file_mut(),
                    page_id,
                    PAGE_LEAF,
                    0,
                    leaf_count,
                    page_id + 1,
                    &payload,
                )?;
                leaf_descriptors.push((first_key.take().unwrap(), page_id));
                page_id += 1;
                payload.clear();
                leaf_count = 0;
            }
            if first_key.is_none() {
                first_key = Some(item.record.key());
            }
            payload.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
            payload.extend_from_slice(&encoded);
            leaf_count += 1;
            if let Some(record) = read_record(&mut readers[run])? {
                heap.push(HeapItem { run, record });
            }
        }
        if first_key.is_none() {
            first_key = Some(Key {
                parent_id: 0,
                name: String::new(),
            });
        }
        write_page(
            page_file.as_file_mut(),
            page_id,
            PAGE_LEAF,
            0,
            leaf_count,
            0,
            &payload,
        )?;
        leaf_descriptors.push((first_key.unwrap(), page_id));
        page_id += 1;

        let first_leaf = 1u64;
        let mut level = 1u8;
        let mut descriptors = leaf_descriptors;
        while descriptors.len() > 1 {
            let mut next = Vec::new();
            let mut cursor = 0;
            while cursor < descriptors.len() {
                let first = descriptors[cursor].0.clone();
                let mut internal = Vec::new();
                let mut count = 0u32;
                while cursor < descriptors.len() {
                    let encoded = encode_internal(&descriptors[cursor]);
                    if !internal.is_empty() && internal.len() + encoded.len() > PAYLOAD_SIZE {
                        break;
                    }
                    if encoded.len() > PAYLOAD_SIZE {
                        return Err(invalid("internal index key exceeds page size"));
                    }
                    internal.extend_from_slice(&encoded);
                    count += 1;
                    cursor += 1;
                }
                write_page(
                    page_file.as_file_mut(),
                    page_id,
                    PAGE_INTERNAL,
                    level,
                    count,
                    0,
                    &internal,
                )?;
                next.push((first, page_id));
                page_id += 1;
            }
            descriptors = next;
            level = level
                .checked_add(1)
                .ok_or_else(|| invalid("index tree is too deep"))?;
        }
        let root_page = descriptors[0].1;
        let super_payload = encode_super(Superblock {
            root_page,
            first_leaf,
            page_count: page_id,
            entry_count: self.count,
            tar_len,
            body_len,
            body_prefix_hash,
        });
        write_page(
            page_file.as_file_mut(),
            0,
            PAGE_SUPER,
            0,
            1,
            0,
            &super_payload,
        )?;
        page_file
            .as_file_mut()
            .set_len(page_id * PAGE_SIZE as u64)?;
        page_file.as_file_mut().flush()?;
        Ok(BuiltIndex { file: page_file })
    }
}

struct HeapItem {
    run: usize,
    record: EntryRecord,
}

impl Eq for HeapItem {}
impl PartialEq for HeapItem {
    fn eq(&self, other: &Self) -> bool {
        self.record.key() == other.record.key() && self.run == other.run
    }
}
impl Ord for HeapItem {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .record
            .key()
            .cmp(&self.record.key())
            .then_with(|| other.run.cmp(&self.run))
    }
}
impl PartialOrd for HeapItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn encode_internal((key, child): &(Key, u64)) -> Vec<u8> {
    let name = key.name.as_bytes();
    let mut out = Vec::with_capacity(18 + name.len());
    out.extend_from_slice(&child.to_le_bytes());
    out.extend_from_slice(&key.parent_id.to_le_bytes());
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(name);
    out
}

fn write_page(
    file: &mut File,
    page_id: u64,
    kind: u8,
    level: u8,
    count: u32,
    next: u64,
    payload: &[u8],
) -> Result<()> {
    if payload.len() > PAYLOAD_SIZE {
        return Err(invalid("index page payload overflow"));
    }
    let mut page = vec![0u8; PAGE_SIZE];
    page[..4].copy_from_slice(PAGE_MAGIC);
    page[4..6].copy_from_slice(&1u16.to_le_bytes());
    page[6] = kind;
    page[7] = level;
    page[8..12].copy_from_slice(&count.to_le_bytes());
    page[12..20].copy_from_slice(&next.to_le_bytes());
    page[20..24].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    page[HEADER_SIZE..HEADER_SIZE + payload.len()].copy_from_slice(payload);
    let crc = crc32fast::hash(&page[HEADER_SIZE..HEADER_SIZE + payload.len()]);
    page[24..28].copy_from_slice(&crc.to_le_bytes());
    file.seek(SeekFrom::Start(page_id * PAGE_SIZE as u64))?;
    file.write_all(&page)?;
    Ok(())
}

#[derive(Debug, Clone)]
pub(crate) struct Superblock {
    pub root_page: u64,
    pub first_leaf: u64,
    pub page_count: u64,
    pub entry_count: u64,
    pub tar_len: u64,
    pub body_len: u64,
    pub body_prefix_hash: [u8; 32],
}

fn encode_super(value: Superblock) -> Vec<u8> {
    let mut out = Vec::with_capacity(80);
    out.extend_from_slice(b"ENGIDX01");
    out.extend_from_slice(&value.root_page.to_le_bytes());
    out.extend_from_slice(&value.first_leaf.to_le_bytes());
    out.extend_from_slice(&value.page_count.to_le_bytes());
    out.extend_from_slice(&value.entry_count.to_le_bytes());
    out.extend_from_slice(&value.tar_len.to_le_bytes());
    out.extend_from_slice(&value.body_len.to_le_bytes());
    out.extend_from_slice(&value.body_prefix_hash);
    out
}

fn decode_super(bytes: &[u8]) -> Result<Superblock> {
    if bytes.len() < 88 || &bytes[..8] != b"ENGIDX01" {
        return Err(invalid("invalid index superblock"));
    }
    let mut bytes = &bytes[8..];
    let root_page = take_u64(&mut bytes)?;
    let first_leaf = take_u64(&mut bytes)?;
    let page_count = take_u64(&mut bytes)?;
    let entry_count = take_u64(&mut bytes)?;
    let tar_len = take_u64(&mut bytes)?;
    let body_len = take_u64(&mut bytes)?;
    let mut body_prefix_hash = [0u8; 32];
    body_prefix_hash.copy_from_slice(&bytes[..32]);
    Ok(Superblock {
        root_page,
        first_leaf,
        page_count,
        entry_count,
        tar_len,
        body_len,
        body_prefix_hash,
    })
}

struct Page {
    kind: u8,
    level: u8,
    count: u32,
    next: u64,
    payload: Vec<u8>,
}

pub(crate) trait ReadSeek: Read + Seek {}
impl<T: Read + Seek> ReadSeek for T {}

pub(crate) struct IndexReader {
    decoder: zeekstd::Decoder<'static, Box<dyn ReadSeek>>,
    pub superblock: Superblock,
    cache: HashMap<u64, Page>,
    cache_pages: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexCursor {
    leaf_page: u64,
    record_index: u32,
}

#[derive(Debug, Clone)]
pub struct EntryPage<T = EntryRecord> {
    pub entries: Vec<T>,
    pub next: Option<IndexCursor>,
}

impl IndexReader {
    pub(crate) fn new(source: Box<dyn ReadSeek>, cache_bytes: usize) -> Result<Self> {
        let decoder = zeekstd::Decoder::new(source)?;
        let mut this = Self {
            decoder,
            superblock: Superblock {
                root_page: 0,
                first_leaf: 0,
                page_count: 0,
                entry_count: 0,
                tar_len: 0,
                body_len: 0,
                body_prefix_hash: [0; 32],
            },
            cache: HashMap::new(),
            cache_pages: (cache_bytes / PAGE_SIZE).max(1),
        };
        let page = this.read_page_uncached(0)?;
        if page.kind != PAGE_SUPER {
            return Err(invalid("index page zero is not a superblock"));
        }
        this.superblock = decode_super(&page.payload)?;
        Ok(this)
    }

    fn read_page_uncached(&mut self, id: u64) -> Result<Page> {
        if self.superblock.page_count != 0 && id >= self.superblock.page_count {
            return Err(invalid("index page ID out of range"));
        }
        let offset = id
            .checked_mul(PAGE_SIZE as u64)
            .ok_or_else(|| invalid("index page offset overflow"))?;
        self.decoder.set_offset(offset)?;
        self.decoder.set_offset_limit(offset + PAGE_SIZE as u64)?;
        let mut bytes = vec![0u8; PAGE_SIZE];
        self.decoder.read_exact(&mut bytes)?;
        if &bytes[..4] != PAGE_MAGIC || u16::from_le_bytes(bytes[4..6].try_into().unwrap()) != 1 {
            return Err(invalid("invalid index page header"));
        }
        let payload_len = u32::from_le_bytes(bytes[20..24].try_into().unwrap()) as usize;
        if payload_len > PAYLOAD_SIZE {
            return Err(invalid("index page payload length overflow"));
        }
        let expected = u32::from_le_bytes(bytes[24..28].try_into().unwrap());
        if crc32fast::hash(&bytes[HEADER_SIZE..HEADER_SIZE + payload_len]) != expected {
            return Err(invalid("index page checksum mismatch"));
        }
        Ok(Page {
            kind: bytes[6],
            level: bytes[7],
            count: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            next: u64::from_le_bytes(bytes[12..20].try_into().unwrap()),
            payload: bytes[HEADER_SIZE..HEADER_SIZE + payload_len].to_vec(),
        })
    }

    fn page(&mut self, id: u64) -> Result<&Page> {
        if !self.cache.contains_key(&id) {
            if self.cache.len() >= self.cache_pages {
                self.cache.clear();
            }
            let page = self.read_page_uncached(id)?;
            self.cache.insert(id, page);
        }
        Ok(self.cache.get(&id).unwrap())
    }

    fn find_leaf(&mut self, target: &Key) -> Result<u64> {
        let mut page_id = self.superblock.root_page;
        loop {
            let page = self.page(page_id)?;
            if page.kind == PAGE_LEAF {
                return Ok(page_id);
            }
            if page.kind != PAGE_INTERNAL || page.level == 0 {
                return Err(invalid("invalid internal index page"));
            }
            let entries = decode_internal_entries(&page.payload, page.count)?;
            let mut chosen = entries
                .first()
                .ok_or_else(|| invalid("empty internal index page"))?;
            for entry in &entries {
                if entry.0 <= *target {
                    chosen = entry;
                } else {
                    break;
                }
            }
            page_id = chosen.1;
        }
    }

    pub(crate) fn lookup_child(
        &mut self,
        parent: EntryId,
        name: &str,
    ) -> Result<Option<EntryRecord>> {
        let target = Key {
            parent_id: parent,
            name: name.to_owned(),
        };
        let leaf = self.find_leaf(&target)?;
        let page = self.page(leaf)?;
        for record in decode_leaf_records(&page.payload, page.count)? {
            match record.key().cmp(&target) {
                Ordering::Equal => return Ok(Some(record)),
                Ordering::Greater => return Ok(None),
                Ordering::Less => {}
            }
        }
        Ok(None)
    }

    pub(crate) fn lookup_path(&mut self, path: &str) -> Result<Option<EntryRecord>> {
        let mut parent = ROOT_ID;
        let mut found = None;
        for component in path.split('/').filter(|v| !v.is_empty()) {
            found = self.lookup_child(parent, component)?;
            match &found {
                Some(record) => parent = record.id,
                None => return Ok(None),
            }
        }
        Ok(found)
    }

    pub(crate) fn children(
        &mut self,
        parent: EntryId,
        cursor: Option<IndexCursor>,
        limit: usize,
    ) -> Result<EntryPage> {
        let target = Key {
            parent_id: parent,
            name: String::new(),
        };
        let mut leaf = cursor.map_or(self.find_leaf(&target)?, |v| v.leaf_page);
        let mut skip = cursor.map_or(0, |v| v.record_index as usize);
        let mut entries = Vec::new();
        loop {
            let page = self.page(leaf)?;
            let records = decode_leaf_records(&page.payload, page.count)?;
            for (idx, record) in records.into_iter().enumerate().skip(skip) {
                if record.parent_id < parent {
                    continue;
                }
                if record.parent_id > parent {
                    return Ok(EntryPage {
                        entries,
                        next: None,
                    });
                }
                entries.push(record);
                if entries.len() == limit.max(1) {
                    return Ok(EntryPage {
                        entries,
                        next: Some(IndexCursor {
                            leaf_page: leaf,
                            record_index: (idx + 1) as u32,
                        }),
                    });
                }
            }
            if page.next == 0 {
                return Ok(EntryPage {
                    entries,
                    next: None,
                });
            }
            leaf = page.next;
            skip = 0;
        }
    }
}

fn decode_internal_entries(bytes: &[u8], count: u32) -> Result<Vec<(Key, u64)>> {
    let mut bytes = bytes;
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let child = take_u64(&mut bytes)?;
        let parent_id = take_u64(&mut bytes)?;
        let len = take_u16(&mut bytes)? as usize;
        if bytes.len() < len {
            return Err(invalid("truncated internal index key"));
        }
        let name = std::str::from_utf8(&bytes[..len])
            .map_err(|_| invalid("internal index key is not UTF-8"))?
            .to_owned();
        bytes = &bytes[len..];
        out.push((Key { parent_id, name }, child));
    }
    Ok(out)
}

fn decode_leaf_records(bytes: &[u8], count: u32) -> Result<Vec<EntryRecord>> {
    let mut bytes = bytes;
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let len = take_u32(&mut bytes)? as usize;
        if bytes.len() < len {
            return Err(invalid("truncated leaf index record"));
        }
        out.push(EntryRecord::decode(&bytes[..len])?);
        bytes = &bytes[len..];
    }
    Ok(out)
}

fn take_u8(bytes: &mut &[u8]) -> Result<u8> {
    if bytes.is_empty() {
        return Err(invalid("truncated integer"));
    }
    let value = bytes[0];
    *bytes = &bytes[1..];
    Ok(value)
}
fn take_u16(bytes: &mut &[u8]) -> Result<u16> {
    take_array(bytes).map(u16::from_le_bytes)
}
fn take_u32(bytes: &mut &[u8]) -> Result<u32> {
    take_array(bytes).map(u32::from_le_bytes)
}
fn take_u64(bytes: &mut &[u8]) -> Result<u64> {
    take_array(bytes).map(u64::from_le_bytes)
}
fn take_i64(bytes: &mut &[u8]) -> Result<i64> {
    take_array(bytes).map(i64::from_le_bytes)
}
fn take_array<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N]> {
    if bytes.len() < N {
        return Err(invalid("truncated integer"));
    }
    let value = bytes[..N].try_into().unwrap();
    *bytes = &bytes[N..];
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_encoding_round_trip() {
        let record = EntryRecord {
            id: 9,
            parent_id: 4,
            name: "测试.txt".into(),
            kind: EntryKind::File,
            tar_offset: 123,
            size: 456,
            mtime: -5,
            mode: 0o644,
            hash: [7; 32],
            link_target: None,
            link_is_dir: false,
        };
        let decoded = EntryRecord::decode(&record.encode().unwrap()).unwrap();
        assert_eq!(decoded.id, record.id);
        assert_eq!(decoded.name, record.name);
        assert_eq!(decoded.hash, record.hash);
    }
}
