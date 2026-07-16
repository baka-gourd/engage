//! Core implementation of the `.engage` archive format.

mod archive;
mod cancel;
mod error;
mod format;
mod index;
mod keystore;
pub mod pq;
mod progress;

pub use archive::{
    Archive, ConflictKind, CreateOptions, DecryptCredential, EncryptCredential, EntryInfo,
    ExtractOptions, ExtractionConflict, OverwritePolicy, Selection, create_archive,
    create_archive_controlled, create_archive_with_progress,
};
pub use cancel::CancellationToken;
pub use error::{Error, Result};
pub use index::{EntryId, EntryKind, EntryPage, IndexCursor};
pub use keystore::{KeyEntry, KeyState, KeyStore, PublicKeyEntry};
pub use pq::{HybridIdentity, HybridRecipient, generate_pq_keypair};
pub use progress::{OperationProgress, OperationStage};
