use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use crate::{Result, error::message};

/// Thread-safe cooperative cancellation for long archive operations.
#[derive(Debug, Clone, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    pub(crate) fn checkpoint(&self) -> Result<()> {
        if self.is_cancelled() {
            Err(message("operation cancelled"))
        } else {
            Ok(())
        }
    }

    pub(crate) fn io_checkpoint(&self) -> std::io::Result<()> {
        if self.is_cancelled() {
            Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "operation cancelled",
            ))
        } else {
            Ok(())
        }
    }
}
