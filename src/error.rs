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
    Multicodec(#[from] multicodec::Error),

    /// Multiutil error
    #[error(transparent)]
    Multiutil(#[from] multiutil::Error),

    /// Multitrait error
    #[error(transparent)]
    Multitrait(#[from] multitrait::Error),

    /// Multihash error
    #[error(transparent)]
    Multihash(#[from] multihash::Error),

    /// Sec1 encoding error
    #[error(transparent)]
    Sec1(#[from] sec1::Error),

    /// Ssh key error
    #[error(transparent)]
    SshKey(#[from] ssh_key::Error),

    /// TryFromSlice error
    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),

    /// Utf8 error
    #[error(transparent)]
    Utf8(#[from] std::string::FromUtf8Error),

    /// Bcrypt PBKDF error
    #[error(transparent)]
    Bcrypt(#[from] bcrypt_pbkdf::Error),

    /// Error converting from ssh keys
    #[error("Unsupported SSH key algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// Error with the kdf
    #[error("Unsupported PBKDF algorithm: {0}")]
    UnsupportedKdf(multicodec::codec::Codec),

    /// Error with the encryption scheme
    #[error("Unsupported encryption algorithm: {0}")]
    UnsupportedEncryption(multicodec::codec::Codec),

    /// Error with the key codec
    #[error("Unsupported key codec: {0}")]
    UnsupportedCodec(multicodec::codec::Codec),

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

    /// Fingerprint error
    #[error("Fingerprint error: {0}")]
    FingerprintFailed(String),

    /// Kdf error
    #[error("Pbkdf error: {0}")]
    PbkdfFailed(String),

    /// Cipher error
    #[error("Cipher error: {0}")]
    CipherFailed(String),

    /// Build error
    #[error("Building Multikey failed: {0}")]
    BuildFailed(String),

    /// Incorrect Multikey sigil
    #[error("Missing Multikey sigil")]
    MissingSigil,

    /// Comment error
    #[error("Comment data unit missing")]
    MissingComment,

    /// Key error
    #[error("Key data unit missing")]
    MissingKey,

    /// Public key operation failure
    #[error("Public key error: {0}")]
    PublicKeyFailure(String),

    /// Private key operation failure
    #[error("Private key error: {0}")]
    PrivateKeyFailure(String),

    /// Not a private key
    #[error("Not a private key {0}")]
    NotPrivateKey(multicodec::codec::Codec),
}
