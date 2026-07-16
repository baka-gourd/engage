use std::path::PathBuf;

/// A coarse phase of an archive operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationStage {
    Scanning,
    Archiving,
    WritingIndex,
    ResolvingSelection,
    Extracting,
    ApplyingMetadata,
    Finalizing,
    Complete,
}

/// Progress snapshot emitted by controlled archive operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationProgress {
    pub stage: OperationStage,
    pub current_path: Option<PathBuf>,
    pub entries_done: u64,
    pub entries_total: Option<u64>,
    pub bytes_done: u64,
    pub bytes_total: Option<u64>,
}

impl OperationProgress {
    pub(crate) fn new(stage: OperationStage) -> Self {
        Self {
            stage,
            current_path: None,
            entries_done: 0,
            entries_total: None,
            bytes_done: 0,
            bytes_total: None,
        }
    }
}

pub(crate) struct ProgressEmitter<'a> {
    callback: &'a mut dyn FnMut(OperationProgress),
    snapshot: OperationProgress,
}

impl<'a> ProgressEmitter<'a> {
    pub(crate) fn new(callback: &'a mut dyn FnMut(OperationProgress)) -> Self {
        Self {
            callback,
            snapshot: OperationProgress::new(OperationStage::Scanning),
        }
    }

    pub(crate) fn set_stage(
        &mut self,
        stage: OperationStage,
        entries_total: Option<u64>,
        bytes_total: Option<u64>,
    ) {
        self.snapshot = OperationProgress::new(stage);
        self.snapshot.entries_total = entries_total;
        self.snapshot.bytes_total = bytes_total;
        self.emit();
    }

    pub(crate) fn advance(&mut self, entries: u64, bytes: u64, path: Option<PathBuf>) {
        self.snapshot.entries_done = self.snapshot.entries_done.saturating_add(entries);
        self.snapshot.bytes_done = self.snapshot.bytes_done.saturating_add(bytes);
        self.snapshot.current_path = path;
        self.emit();
    }

    pub(crate) fn emit(&mut self) {
        (self.callback)(self.snapshot.clone());
    }

    pub(crate) fn complete(&mut self, entries: u64, bytes: u64) {
        self.snapshot = OperationProgress {
            stage: OperationStage::Complete,
            current_path: None,
            entries_done: entries,
            entries_total: Some(entries),
            bytes_done: bytes,
            bytes_total: Some(bytes),
        };
        self.emit();
    }
}
