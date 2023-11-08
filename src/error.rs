use thiserror::Error;

/// Errors created by this library
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// Multibase conversion error
    #[error(transparent)]
    Multibase(#[from] multibase::Error),

    /// Multicodec decoding error
    #[error(transparent)]
    Multicodec(#[from] multicodec::error::Error),

    /// Multiutil error
    #[error(transparent)]
    Multiutil(#[from] multiutil::Error),

    /// Sec1 encoding error
    #[error(transparent)]
    Sec1(#[from] sec1::Error),

    /// TryFromSlice error
    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),

    /// Missing sigil 0x34
    #[error("Missing Multikey sigil")]
    MissingSigil,

    /// Error converting from ssh keys
    #[error("Unsupported SSH key algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// Error with the kdf
    #[error("Unsupported PBKDF algorithm: {0}")]
    UnsupportedKdf(multicodec::codec::Codec),

    /// Error with the encryption scheme
    #[error("Unsupported encryption algorithm: {0}")]
    UnsupportedEncryption(multicodec::codec::Codec),

    /// Encryption key error
    #[error("Encryption key error: {0}")]
    Key(String),

    /// Nonce error
    #[error("Nonce error: {0}")]
    Nonce(String),

    /// Encryption error
    #[error("Encryption error: {0}")]
    EncryptionFailed(String),

    /// Decryption error
    #[error("Decryption error: {0}")]
    DecryptionFailed(String),

    /// Kdf error
    #[error("Pbkdf error: {0}")]
    PbkdfFailed(String),

    /// Cipher error
    #[error("Cipher error: {0}")]
    CipherFailed(String),

    /// Comment error
    #[error("Comment data unit missing")]
    MissingComment,

    /// Key error
    #[error("Key data unit missing")]
    MissingKey,
}
