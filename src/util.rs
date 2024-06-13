use thiserror::Error;

/// Result type
pub type Result<T> = std::result::Result<T, UsbmuxError>;

/// Usbmux Error
#[derive(Error, Debug)]
pub enum UsbmuxError {
    /// FailedRequest
    #[error("Failed Requests")]
    FailedRequest,
    /// IOError
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    /// UTF8 encoding/decoding error
    #[error(transparent)]
    Utf8StringError(#[from] std::str::Utf8Error),
    /// ParseIntError
    #[error(transparent)]
    ParseIntError(#[from] std::num::ParseIntError),
    /// AddrParseError
    #[error(transparent)]
    AddrParseError(#[from] std::net::AddrParseError),
    /// error parsing/serialising plis
    #[error(transparent)]
    PlistError(#[from] plist::Error),
}
