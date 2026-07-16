use std::{
    collections::BTreeMap,
    io::{self, Write},
    sync::mpsc::{self, Receiver, SyncSender, TrySendError},
    thread::{self, JoinHandle},
};

use zeekstd::{EncodeOptions, FrameSizePolicy, SeekTable};

use crate::{CancellationToken, Result};

const WORK_BUFFER_SIZE: usize = 128 * 1024;

pub(super) enum SeekableEncoder<W: Write> {
    Serial(zeekstd::Encoder<'static, W>),
    Parallel(ParallelEncoder<W>),
}

impl<W: Write> SeekableEncoder<W> {
    pub(super) fn new(
        writer: W,
        frame_size: u32,
        frames_per_job: usize,
        workers: usize,
        cancellation: &CancellationToken,
    ) -> Result<Self> {
        let options = || {
            EncodeOptions::new()
                .compression_level(9)
                .checksum_flag(true)
                .frame_size_policy(FrameSizePolicy::Uncompressed(frame_size))
        };
        if workers <= 1 {
            Ok(Self::Serial(options().into_encoder(writer)?))
        } else {
            Ok(Self::Parallel(ParallelEncoder::new(
                writer,
                frame_size as usize,
                frames_per_job.max(1),
                workers,
                cancellation.clone(),
            )))
        }
    }

    pub(super) fn finish(self) -> Result<()> {
        match self {
            Self::Serial(encoder) => {
                encoder.finish()?;
                Ok(())
            }
            Self::Parallel(encoder) => encoder.finish().map_err(Into::into),
        }
    }
}

impl<W: Write> Write for SeekableEncoder<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Serial(encoder) => encoder.write(buf),
            Self::Parallel(encoder) => encoder.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Serial(encoder) => encoder.flush(),
            Self::Parallel(encoder) => encoder.flush(),
        }
    }
}

struct Job {
    sequence: u64,
    frames: Vec<Vec<u8>>,
}

struct EncodedFrame {
    compressed: Vec<u8>,
    uncompressed_size: u32,
}

struct JobResult {
    sequence: u64,
    result: std::result::Result<Vec<EncodedFrame>, String>,
}

struct Worker {
    sender: Option<SyncSender<Job>>,
    handle: Option<JoinHandle<()>>,
}

pub(super) struct ParallelEncoder<W: Write> {
    writer: Option<W>,
    frame_size: usize,
    frames_per_job: usize,
    worker_limit: usize,
    cancellation: CancellationToken,
    workers: Vec<Worker>,
    results_tx: mpsc::Sender<JobResult>,
    results_rx: Receiver<JobResult>,
    frame: Vec<u8>,
    batch: Vec<Vec<u8>>,
    next_sequence: u64,
    next_to_write: u64,
    inflight: usize,
    pending: BTreeMap<u64, Vec<EncodedFrame>>,
    seek_table: SeekTable,
    failed: Option<String>,
}

impl<W: Write> ParallelEncoder<W> {
    fn new(
        writer: W,
        frame_size: usize,
        frames_per_job: usize,
        worker_limit: usize,
        cancellation: CancellationToken,
    ) -> Self {
        let (results_tx, results_rx) = mpsc::channel();
        Self {
            writer: Some(writer),
            frame_size,
            frames_per_job,
            worker_limit,
            cancellation,
            workers: Vec::new(),
            results_tx,
            results_rx,
            frame: Vec::with_capacity(frame_size),
            batch: Vec::with_capacity(frames_per_job),
            next_sequence: 0,
            next_to_write: 0,
            inflight: 0,
            pending: BTreeMap::new(),
            seek_table: SeekTable::new(),
            failed: None,
        }
    }

    fn finish(mut self) -> io::Result<()> {
        if !self.frame.is_empty() || (self.batch.is_empty() && self.next_sequence == 0) {
            let frame = std::mem::replace(&mut self.frame, Vec::with_capacity(self.frame_size));
            self.queue_frame(frame)?;
        }
        self.submit_batch()?;
        while self.inflight != 0 {
            self.receive_one()?;
        }
        self.flush_ready()?;

        let mut serializer = std::mem::take(&mut self.seek_table).into_serializer();
        let mut buffer = [0u8; 8192];
        loop {
            let written = serializer.write_into(&mut buffer);
            if written == 0 {
                break;
            }
            self.writer_mut()?.write_all(&buffer[..written])?;
        }
        self.writer_mut()?.flush()?;
        self.shutdown_workers();
        Ok(())
    }

    fn queue_frame(&mut self, frame: Vec<u8>) -> io::Result<()> {
        self.batch.push(frame);
        if self.batch.len() == self.frames_per_job {
            self.submit_batch()?;
        }
        Ok(())
    }

    fn submit_batch(&mut self) -> io::Result<()> {
        if self.batch.is_empty() {
            return Ok(());
        }
        self.check_failed()?;
        while self.inflight > self.worker_limit {
            self.receive_one()?;
        }

        let mut job = Job {
            sequence: self.next_sequence,
            frames: std::mem::replace(&mut self.batch, Vec::with_capacity(self.frames_per_job)),
        };
        loop {
            for worker in &self.workers {
                let Some(sender) = &worker.sender else {
                    continue;
                };
                match sender.try_send(job) {
                    Ok(()) => {
                        self.next_sequence += 1;
                        self.inflight += 1;
                        return Ok(());
                    }
                    Err(TrySendError::Full(returned)) => job = returned,
                    Err(TrySendError::Disconnected(returned)) => job = returned,
                }
            }

            if self.workers.len() < self.worker_limit {
                self.spawn_worker()?;
                continue;
            }
            self.receive_one()?;
        }
    }

    fn spawn_worker(&mut self) -> io::Result<()> {
        let (sender, receiver) = mpsc::sync_channel(1);
        let results = self.results_tx.clone();
        let cancellation = self.cancellation.clone();
        let handle = thread::Builder::new()
            .name("engage-zstd".into())
            .spawn(move || worker_loop(receiver, results, cancellation))?;
        self.workers.push(Worker {
            sender: Some(sender),
            handle: Some(handle),
        });
        Ok(())
    }

    fn receive_one(&mut self) -> io::Result<()> {
        let result = self
            .results_rx
            .recv()
            .map_err(|_| io::Error::other("compression worker stopped unexpectedly"))?;
        self.inflight = self.inflight.saturating_sub(1);
        match result.result {
            Ok(frames) => {
                self.pending.insert(result.sequence, frames);
                self.flush_ready()
            }
            Err(error) => {
                self.failed = Some(error.clone());
                Err(io::Error::other(error))
            }
        }
    }

    fn flush_ready(&mut self) -> io::Result<()> {
        while let Some(frames) = self.pending.remove(&self.next_to_write) {
            for frame in frames {
                let compressed_size: u32 = frame
                    .compressed
                    .len()
                    .try_into()
                    .map_err(|_| io::Error::other("compressed zstd frame is too large"))?;
                self.writer_mut()?.write_all(&frame.compressed)?;
                self.seek_table
                    .log_frame(compressed_size, frame.uncompressed_size)
                    .map_err(io::Error::other)?;
            }
            self.next_to_write += 1;
        }
        Ok(())
    }

    fn check_failed(&self) -> io::Result<()> {
        if let Some(error) = &self.failed {
            Err(io::Error::other(error.clone()))
        } else if self.cancellation.is_cancelled() {
            // `Write::write_all` retries `Interrupted` forever, while cancellation is terminal.
            Err(io::Error::other("operation cancelled"))
        } else {
            Ok(())
        }
    }

    fn writer_mut(&mut self) -> io::Result<&mut W> {
        self.writer
            .as_mut()
            .ok_or_else(|| io::Error::other("compression writer is already finished"))
    }

    fn shutdown_workers(&mut self) {
        for worker in &mut self.workers {
            worker.sender.take();
        }
        for worker in &mut self.workers {
            if let Some(handle) = worker.handle.take() {
                let _ = handle.join();
            }
        }
    }
}

impl<W: Write> Write for ParallelEncoder<W> {
    fn write(&mut self, mut buf: &[u8]) -> io::Result<usize> {
        self.check_failed()?;
        let original_len = buf.len();
        while !buf.is_empty() {
            let available = self.frame_size - self.frame.len();
            let copied = available.min(buf.len());
            self.frame.extend_from_slice(&buf[..copied]);
            buf = &buf[copied..];
            if self.frame.len() == self.frame_size {
                let frame = std::mem::replace(&mut self.frame, Vec::with_capacity(self.frame_size));
                self.queue_frame(frame)?;
            }
        }
        Ok(original_len)
    }

    fn flush(&mut self) -> io::Result<()> {
        while self.inflight != 0 {
            self.receive_one()?;
        }
        self.flush_ready()?;
        self.writer_mut()?.flush()
    }
}

impl<W: Write> Drop for ParallelEncoder<W> {
    fn drop(&mut self) {
        self.shutdown_workers();
    }
}

fn worker_loop(
    receiver: Receiver<Job>,
    results: mpsc::Sender<JobResult>,
    cancellation: CancellationToken,
) {
    while let Ok(job) = receiver.recv() {
        let sequence = job.sequence;
        let result = encode_job(job, &cancellation).map_err(|error| error.to_string());
        if results.send(JobResult { sequence, result }).is_err() {
            break;
        }
    }
}

fn encode_job(job: Job, cancellation: &CancellationToken) -> Result<Vec<EncodedFrame>> {
    let mut encoder = EncodeOptions::new()
        .compression_level(9)
        .checksum_flag(true)
        .into_raw_encoder()?;
    let mut encoded = Vec::with_capacity(job.frames.len());
    let mut output = vec![0u8; WORK_BUFFER_SIZE];
    for frame in job.frames {
        cancellation.checkpoint()?;
        let mut compressed = Vec::new();
        let mut consumed = 0;
        while consumed < frame.len() {
            let progress = encoder.compress(&frame[consumed..], &mut output)?;
            consumed += progress.in_progress();
            compressed.extend_from_slice(&output[..progress.out_progress()]);
        }
        loop {
            let progress = encoder.end_frame(&mut output)?;
            compressed.extend_from_slice(&output[..progress.out_progress()]);
            if progress.data_left() == 0 {
                break;
            }
        }
        let uncompressed_size = frame
            .len()
            .try_into()
            .map_err(|_| eros::error!("uncompressed zstd frame is too large"))?;
        encoded.push(EncodedFrame {
            compressed,
            uncompressed_size,
        });
        encoder.reset_seek_table();
    }
    cancellation.checkpoint()?;
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read};

    use super::*;

    const FRAME_SIZE: usize = 64 * 1024;

    fn encode(input: &[u8], frames_per_job: usize, workers: usize) -> Vec<u8> {
        let mut output = Vec::new();
        let cancellation = CancellationToken::new();
        let mut encoder = SeekableEncoder::new(
            &mut output,
            FRAME_SIZE as u32,
            frames_per_job,
            workers,
            &cancellation,
        )
        .unwrap();
        encoder.write_all(input).unwrap();
        encoder.finish().unwrap();
        output
    }

    #[test]
    fn parallel_stream_matches_serial_stream_at_frame_boundaries() {
        for size in [0, 1, FRAME_SIZE, FRAME_SIZE + 1, FRAME_SIZE * 7 + 17] {
            let input = (0..size)
                .map(|index| ((index * 31 + index / 251) % 251) as u8)
                .collect::<Vec<_>>();
            let serial = encode(&input, 1, 1);
            let parallel = encode(&input, 3, 4);
            assert_eq!(parallel, serial, "encoded stream differs at size {size}");

            let mut decoded = Vec::new();
            zeekstd::Decoder::new(Cursor::new(parallel))
                .unwrap()
                .read_to_end(&mut decoded)
                .unwrap();
            assert_eq!(decoded, input);
        }
    }

    #[test]
    fn cancelled_parallel_encoder_stops_before_accepting_input() {
        let mut output = Vec::new();
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let mut encoder =
            SeekableEncoder::new(&mut output, FRAME_SIZE as u32, 1, 4, &cancellation).unwrap();
        let error = encoder.write_all(b"cancelled").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn dropping_cancelled_encoder_with_queued_frame_joins_workers() {
        let mut output = Vec::new();
        let cancellation = CancellationToken::new();
        let mut encoder =
            SeekableEncoder::new(&mut output, FRAME_SIZE as u32, 1, 4, &cancellation).unwrap();
        encoder.write_all(&vec![0x5a; FRAME_SIZE]).unwrap();
        cancellation.cancel();
        assert_eq!(
            encoder.write_all(b"cancelled").unwrap_err().kind(),
            io::ErrorKind::Other
        );
        drop(encoder);
    }
}
