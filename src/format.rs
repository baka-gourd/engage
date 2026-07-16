use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
};

use crate::{Result, error::invalid};

pub(crate) const SKIPPABLE_MAGIC: u32 = 0x184D_2A5D;
const TRAILER_MAGIC: &[u8; 8] = b"ENGMETA1";
const TRAILER_SIZE: u64 = 48;
const FRAME_HEADER_SIZE: u64 = 8;
const FLAG_FIRST: u16 = 1;
const FLAG_LAST: u16 = 2;
pub(crate) const DEFAULT_SEGMENT_SIZE: u64 = 1024 * 1024 * 1024;

#[derive(Debug, Clone)]
struct Trailer {
    flags: u16,
    index: u32,
    cipher_len: u64,
    total_cipher_len: u64,
    body_len: u64,
    previous_frame_len: u32,
}

impl Trailer {
    fn encode(&self) -> [u8; TRAILER_SIZE as usize] {
        let mut out = [0u8; TRAILER_SIZE as usize];
        out[..8].copy_from_slice(TRAILER_MAGIC);
        out[8..10].copy_from_slice(&1u16.to_le_bytes());
        out[10..12].copy_from_slice(&self.flags.to_le_bytes());
        out[12..16].copy_from_slice(&self.index.to_le_bytes());
        out[16..24].copy_from_slice(&self.cipher_len.to_le_bytes());
        out[24..32].copy_from_slice(&self.total_cipher_len.to_le_bytes());
        out[32..40].copy_from_slice(&self.body_len.to_le_bytes());
        out[40..44].copy_from_slice(&self.previous_frame_len.to_le_bytes());
        let crc = crc32fast::hash(&out[..44]);
        out[44..48].copy_from_slice(&crc.to_le_bytes());
        out
    }

    fn decode(bytes: &[u8; TRAILER_SIZE as usize]) -> Result<Self> {
        if &bytes[..8] != TRAILER_MAGIC {
            return Err(invalid("metadata trailer signature mismatch"));
        }
        if u16::from_le_bytes(bytes[8..10].try_into().unwrap()) != 1 {
            return Err(invalid("unsupported metadata trailer version"));
        }
        let expected = u32::from_le_bytes(bytes[44..48].try_into().unwrap());
        if crc32fast::hash(&bytes[..44]) != expected {
            return Err(invalid("metadata trailer checksum mismatch"));
        }
        Ok(Self {
            flags: u16::from_le_bytes(bytes[10..12].try_into().unwrap()),
            index: u32::from_le_bytes(bytes[12..16].try_into().unwrap()),
            cipher_len: u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
            total_cipher_len: u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
            body_len: u64::from_le_bytes(bytes[32..40].try_into().unwrap()),
            previous_frame_len: u32::from_le_bytes(bytes[40..44].try_into().unwrap()),
        })
    }
}

pub(crate) struct SegmentWriter<W: Write + Seek> {
    inner: W,
    segment_limit: u64,
    body_len: u64,
    frame_start: u64,
    segment_len: u64,
    total_len: u64,
    index: u32,
    previous_frame_len: u32,
}

impl<W: Write + Seek> SegmentWriter<W> {
    pub(crate) fn new(mut inner: W, body_len: u64, segment_limit: u64) -> io::Result<Self> {
        if segment_limit == 0 || segment_limit + TRAILER_SIZE > u32::MAX as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid segment size",
            ));
        }
        let frame_start = inner.stream_position()?;
        inner.write_all(&SKIPPABLE_MAGIC.to_le_bytes())?;
        inner.write_all(&0u32.to_le_bytes())?;
        Ok(Self {
            inner,
            segment_limit,
            body_len,
            frame_start,
            segment_len: 0,
            total_len: 0,
            index: 0,
            previous_frame_len: 0,
        })
    }

    fn close_segment(&mut self, last: bool) -> io::Result<()> {
        let flags =
            (if self.index == 0 { FLAG_FIRST } else { 0 }) | (if last { FLAG_LAST } else { 0 });
        let trailer = Trailer {
            flags,
            index: self.index,
            cipher_len: self.segment_len,
            total_cipher_len: if last { self.total_len } else { 0 },
            body_len: self.body_len,
            previous_frame_len: self.previous_frame_len,
        };
        self.inner.write_all(&trailer.encode())?;
        let end = self.inner.stream_position()?;
        let payload_len = self.segment_len + TRAILER_SIZE;
        self.inner.seek(SeekFrom::Start(self.frame_start + 4))?;
        self.inner.write_all(&(payload_len as u32).to_le_bytes())?;
        self.inner.seek(SeekFrom::Start(end))?;
        self.previous_frame_len = (end - self.frame_start) as u32;
        if !last {
            self.index = self
                .index
                .checked_add(1)
                .ok_or_else(|| io::Error::other("too many metadata segments"))?;
            self.frame_start = end;
            self.segment_len = 0;
            self.inner.write_all(&SKIPPABLE_MAGIC.to_le_bytes())?;
            self.inner.write_all(&0u32.to_le_bytes())?;
        }
        Ok(())
    }

    pub(crate) fn finish(mut self) -> io::Result<W> {
        self.close_segment(true)?;
        self.inner.flush()?;
        Ok(self.inner)
    }
}

impl<W: Write + Seek> Write for SegmentWriter<W> {
    fn write(&mut self, mut buf: &[u8]) -> io::Result<usize> {
        let original = buf.len();
        while !buf.is_empty() {
            if self.segment_len == self.segment_limit {
                self.close_segment(false)?;
            }
            let amount = (self.segment_limit - self.segment_len).min(buf.len() as u64) as usize;
            self.inner.write_all(&buf[..amount])?;
            self.segment_len += amount as u64;
            self.total_len += amount as u64;
            buf = &buf[amount..];
        }
        Ok(original)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[derive(Debug, Clone)]
struct Segment {
    physical_start: u64,
    logical_start: u64,
    len: u64,
}

pub(crate) struct SegmentedReader {
    file: File,
    segments: Vec<Segment>,
    len: u64,
    pos: u64,
    body_len: u64,
}

impl SegmentedReader {
    pub(crate) fn open(mut file: File) -> Result<Self> {
        let file_len = file.seek(SeekFrom::End(0))?;
        if file_len < TRAILER_SIZE + FRAME_HEADER_SIZE {
            return Err(invalid("archive is too short"));
        }
        let mut end = file_len;
        let mut reverse = Vec::new();
        let mut expected_index = None;
        let mut total_expected = None;
        let mut body_len = None;
        loop {
            if end < TRAILER_SIZE + FRAME_HEADER_SIZE {
                return Err(invalid("metadata frame underflow"));
            }
            file.seek(SeekFrom::Start(end - TRAILER_SIZE))?;
            let mut bytes = [0u8; TRAILER_SIZE as usize];
            file.read_exact(&mut bytes)?;
            let trailer = Trailer::decode(&bytes)?;
            if expected_index.is_none() {
                if trailer.flags & FLAG_LAST == 0 {
                    return Err(invalid("last metadata frame is not marked LAST"));
                }
                expected_index = Some(trailer.index);
                total_expected = Some(trailer.total_cipher_len);
            }
            if Some(trailer.index) != expected_index {
                return Err(invalid("metadata segment sequence mismatch"));
            }
            let frame_len = FRAME_HEADER_SIZE
                .checked_add(trailer.cipher_len)
                .and_then(|v| v.checked_add(TRAILER_SIZE))
                .ok_or_else(|| invalid("metadata frame length overflow"))?;
            let start = end
                .checked_sub(frame_len)
                .ok_or_else(|| invalid("metadata frame begins before archive"))?;
            file.seek(SeekFrom::Start(start))?;
            let mut header = [0u8; 8];
            file.read_exact(&mut header)?;
            if u32::from_le_bytes(header[..4].try_into().unwrap()) != SKIPPABLE_MAGIC
                || u32::from_le_bytes(header[4..].try_into().unwrap()) as u64
                    != trailer.cipher_len + TRAILER_SIZE
            {
                return Err(invalid("invalid metadata skippable frame header"));
            }
            reverse.push((start + FRAME_HEADER_SIZE, trailer.cipher_len));
            if body_len
                .replace(trailer.body_len)
                .is_some_and(|v| v != trailer.body_len)
            {
                return Err(invalid("metadata segments disagree on body length"));
            }
            if trailer.flags & FLAG_FIRST != 0 {
                if trailer.index != 0 || start != trailer.body_len {
                    return Err(invalid("invalid first metadata segment"));
                }
                break;
            }
            if trailer.previous_frame_len == 0 || trailer.previous_frame_len as u64 > start {
                return Err(invalid("invalid previous metadata frame length"));
            }
            end = start;
            expected_index = trailer.index.checked_sub(1);
        }
        reverse.reverse();
        let mut logical = 0u64;
        let mut segments = Vec::with_capacity(reverse.len());
        for (physical_start, len) in reverse {
            segments.push(Segment {
                physical_start,
                logical_start: logical,
                len,
            });
            logical = logical
                .checked_add(len)
                .ok_or_else(|| invalid("metadata ciphertext length overflow"))?;
        }
        if total_expected != Some(logical) {
            return Err(invalid("metadata total length mismatch"));
        }
        Ok(Self {
            file,
            segments,
            len: logical,
            pos: 0,
            body_len: body_len.ok_or_else(|| invalid("metadata has no segments"))?,
        })
    }

    pub(crate) fn body_len(&self) -> u64 {
        self.body_len
    }

    fn segment_for(&self, pos: u64) -> Option<&Segment> {
        let idx = self
            .segments
            .partition_point(|segment| segment.logical_start + segment.len <= pos);
        self.segments.get(idx)
    }
}

impl Read for SegmentedReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.len || buf.is_empty() {
            return Ok(0);
        }
        let segment = self
            .segment_for(self.pos)
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "metadata segment gap"))?
            .clone();
        let within = self.pos - segment.logical_start;
        let amount = (segment.len - within)
            .min(buf.len() as u64)
            .min(self.len - self.pos) as usize;
        self.file
            .seek(SeekFrom::Start(segment.physical_start + within))?;
        self.file.read_exact(&mut buf[..amount])?;
        self.pos += amount as u64;
        Ok(amount)
    }
}

impl Seek for SegmentedReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let target = match pos {
            SeekFrom::Start(v) => v as i128,
            SeekFrom::Current(v) => self.pos as i128 + v as i128,
            SeekFrom::End(v) => self.len as i128 + v as i128,
        };
        if target < 0 || target > self.len as i128 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek outside metadata",
            ));
        }
        self.pos = target as u64;
        Ok(self.pos)
    }
}

pub(crate) struct FileRegion {
    file: File,
    start: u64,
    len: u64,
    pos: u64,
}

impl FileRegion {
    pub(crate) fn new(file: File, start: u64, len: u64) -> Self {
        Self {
            file,
            start,
            len,
            pos: 0,
        }
    }
}

impl Read for FileRegion {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.len {
            return Ok(0);
        }
        let amount = (self.len - self.pos).min(buf.len() as u64) as usize;
        self.file.seek(SeekFrom::Start(self.start + self.pos))?;
        let read = self.file.read(&mut buf[..amount])?;
        self.pos += read as u64;
        Ok(read)
    }
}

impl Seek for FileRegion {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let target = match pos {
            SeekFrom::Start(v) => v as i128,
            SeekFrom::Current(v) => self.pos as i128 + v as i128,
            SeekFrom::End(v) => self.len as i128 + v as i128,
        };
        if target < 0 || target > self.len as i128 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek outside file region",
            ));
        }
        self.pos = target as u64;
        Ok(self.pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempfile;

    #[test]
    fn segmented_round_trip_and_seek() {
        let file = tempfile().unwrap();
        let mut writer = SegmentWriter::new(file, 0, 7).unwrap();
        writer.write_all(b"abcdefghijklmnopqrstuvwxyz").unwrap();
        let file = writer.finish().unwrap();
        let mut reader = SegmentedReader::open(file).unwrap();
        let mut all = Vec::new();
        reader.read_to_end(&mut all).unwrap();
        assert_eq!(all, b"abcdefghijklmnopqrstuvwxyz");
        reader.seek(SeekFrom::Start(13)).unwrap();
        let mut bytes = [0; 5];
        reader.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"nopqr");
    }
}
