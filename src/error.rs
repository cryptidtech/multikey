use thiserror::Error;

/// Errors created by this library
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Attributes error
    #[error(transparent)]
    Attributes(#[from] AttributesError),
    /// Conversions error
    #[error(transparent)]
    Conversions(#[from] ConversionsError),
    /// Cipher error
    #[error(transparent)]
    Cipher(#[from] CipherError),
    /// Kdf error
    #[error(transparent)]
    Kdf(#[from] KdfError),

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

    /// Utf8 error
    #[error(transparent)]
    Utf8(#[from] std::string::FromUtf8Error),
    /// Duplicate attribute error
    #[error("Duplicate Multikey attribute: {0}")]
    DuplicateAttribute(u8),
    /// Incorrect Multikey sigil
    #[error("Missing Multikey sigil")]
    MissingSigil,
}

/// Attributes errors created by this library
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum AttributesError {
    /// Error with the key codec
    #[error("Unsupported key codec: {0}")]
    UnsupportedCodec(multicodec::Codec),
    /// No key data attribute
    #[error("Key data unit missing")]
    MissingKey,
    /// Not a secret key
    #[error("Not a secret key {0}")]
    NotSecretKey(multicodec::codec::Codec),
    /// Key is encrypted
    #[error("Key is encrypted")]
    EncryptedKey,
    /// Invalid attribute name
    #[error("Invalid attribute name {0}")]
    InvalidAttributeName(String),
    /// Invalid attribute value
    #[error("Invalid attribute value {0}")]
    InvalidAttributeValue(u8),
}

/// Conversions errors created by this library
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum ConversionsError {
    /*
    /// Sec1 encoding error
    #[error(transparent)]
    Sec1(#[from] sec1::Error),
    /// Fingerprint error
    #[error("Fingerprint error: {0}")]
    FingerprintFailed(String),
    /// Public key operation failure
    #[error("Public key error: {0}")]
    PublicKeyFailure(String),
    /// Not a secret key
    #[error("Not a secret key {0}")]
    NotSecretKey(multicodec::codec::Codec),
    */
    /// Ssh key error
    #[error(transparent)]
    SshKey(#[from] ssh_key::Error),
    /// Private key operation failure
    #[error("Secret key error: {0}")]
    SecretKeyFailure(String),
    /// Error converting from ssh keys
    #[error("Unsupported SSH key algorithm: {0}")]
    UnsupportedAlgorithm(String),
    /// Error with the key codec
    #[error("Unsupported key codec: {0}")]
    UnsupportedCodec(multicodec::Codec),
}

/// Cipher errors created by this library
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum CipherError {
    /// Error with the cipher codec
    #[error("Unsupported cipher codec: {0}")]
    UnsupportedCodec(multicodec::Codec),
    /// Missing codec
    #[error("Missing cipher codec")]
    MissingCodec,
    /// Missing nonce error
    #[error("Missing cipher nonce")]
    MissingNonce,
    /// Missing nonce length error
    #[error("Missing cipher nonce length")]
    MissingNonceLen,
    /// Invalid nonce error
    #[error("Invalid cipher nonce")]
    InvalidNonce,
    /// Missing key error
    #[error("Missing cipher key")]
    MissingKey,
    /// Missing key length error
    #[error("Missing cipher key length")]
    MissingKeyLen,
    /// Invalid key error
    #[error("Invalid cipher key")]
    InvalidKey,
    /// Encryption error
    #[error("Encryption error: {0}")]
    EncryptionFailed(String),
    /// Decryption error
    #[error("Decryption failed")]
    DecryptionFailed,
}

/// Kdf errors created by this library
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum KdfError {
    /// Bcrypt PBKDF error
    #[error(transparent)]
    Bcrypt(#[from] bcrypt_pbkdf::Error),
    /// Error with the KDF codec
    #[error("Unsupported KDF codec: {0}")]
    UnsupportedCodec(multicodec::Codec),
    /// Missing codec
    #[error("Missing KDF codec")]
    MissingCodec,
    /// Missing salt error
    #[error("Missing KDF salt")]
    MissingSalt,
    /// Missing salt length error
    #[error("Missing KDF salt length")]
    MissingSaltLen,
    /// Missing rounds error
    #[error("Missing KDF rounds")]
    MissingRounds,
}
