use std::fmt;

/// Opaque, traced application error provided by `eros`.
pub type Error = eros::ErrorUnion<eros::AnyError>;
pub type Result<T> = eros::Result<T>;

pub(crate) fn message(message: impl fmt::Display) -> Error {
    eros::error!("{}", message)
}

pub(crate) fn invalid(message: impl fmt::Display) -> Error {
    eros::error!("invalid engage archive: {}", message)
}

pub(crate) fn invalid_path(path: impl fmt::Display) -> Error {
    eros::error!("invalid archive path: {}", path)
}

pub(crate) fn not_found(path: impl fmt::Display) -> Error {
    eros::error!("archive entry not found: {}", path)
}
