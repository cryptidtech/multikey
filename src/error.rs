use thiserror::Error;

/// Errors created by this library
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// Formatting error
    #[error("fmt error {0}")]
    Fmt(#[from] std::fmt::Error),

    /// A generic error message
    #[error("General varsig error: {0}")]
    General(&'static str),

    /// A multibase conversion error
    #[error("Multibase conversion failed: {0}")]
    Multibase(#[from] multibase::Error),

    /// A multicodec decoding error
    #[error("Multicodec decoding failed: {0}")]
    Multicodec(#[from] multicodec::error::Error),

    /// Missing sigil 0x34
    #[error("Missing Multikey sigil")]
    MissingSigil,

    /// An unsigned-varint error
    #[error("Unsigned varint decode error: {0}")]
    UnsignedVarintDecode(#[from] unsigned_varint::decode::Error),

    /// Error decoding utf8
    #[error("Invalid UTF-8 sequence: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),

    /// Error converting from ssh keys
    #[error("Unsupported SSH key algorithm: {0}")]
    UnsupportedAlgorithm(String),
}
