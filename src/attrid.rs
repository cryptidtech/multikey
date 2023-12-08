use crate::{error::AttributesError, Error};
use multitrait::{EncodeInto, TryDecodeFrom};
use std::fmt;

/// enum of attribute identifiers. this is here to avoid collisions between
/// different codecs and encryption schemes. these is the common set of
/// attribute identifiers use in Multikeys
#[repr(u8)]
#[derive(Clone, Copy, Hash, Ord, PartialOrd, PartialEq, Eq)]
pub enum AttrId {
    /// bool attribute signaling if the key is encrypted
    KeyIsEncrypted,
    /// the key data
    KeyData,
    /// the cipher codec used to encrypt the key, if encrypted
    CipherCodec,
    /// the length of the cipher codec key in bytes, if encrypted
    CipherKeyLen,
    /// the length of the cipher nonce, if enccrypted
    CipherNonceLen,
    /// the nonce used to encrypt the key, if encrypted
    CipherNonce,
    /// the codec used to derive the encryption key, if encrypted
    KdfCodec,
    /// the length of the kdf salt, if encrypted
    KdfSaltLen,
    /// the salt used to derive the encryption key, if encrypted
    KdfSalt,
    /// the rounds used to derive the encryption key, if encrypted
    KdfRounds,
}

impl AttrId {
    /// Get the code for the attribute id
    pub fn code(&self) -> u8 {
        self.clone().into()
    }

    /// Convert the attribute id to &str
    pub fn as_str(&self) -> &str {
        match self {
            AttrId::KeyIsEncrypted => "key-is-encrypted",
            AttrId::KeyData => "key-data",
            AttrId::CipherCodec => "cipher-codec",
            AttrId::CipherKeyLen => "cipher-key-len",
            AttrId::CipherNonceLen => "cipher-nonce-len",
            AttrId::CipherNonce => "cipher-nonce",
            AttrId::KdfCodec => "kdf-codec",
            AttrId::KdfSaltLen => "kdf-salt-len",
            AttrId::KdfSalt => "kdf-salt",
            AttrId::KdfRounds => "kdf-rounds",
        }
    }
}

impl Into<u8> for AttrId {
    fn into(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for AttrId {
    type Error = Error;

    fn try_from(c: u8) -> Result<Self, Self::Error> {
        match c {
            0 => Ok(AttrId::KeyIsEncrypted),
            1 => Ok(AttrId::KeyData),
            2 => Ok(AttrId::CipherCodec),
            3 => Ok(AttrId::CipherKeyLen),
            4 => Ok(AttrId::CipherNonceLen),
            5 => Ok(AttrId::CipherNonce),
            6 => Ok(AttrId::KdfCodec),
            7 => Ok(AttrId::KdfSaltLen),
            8 => Ok(AttrId::KdfSalt),
            9 => Ok(AttrId::KdfRounds),
            _ => Err(AttributesError::InvalidAttributeValue(c).into()),
        }
    }
}

impl Into<Vec<u8>> for AttrId {
    fn into(self) -> Vec<u8> {
        let v: u8 = self.into();
        v.encode_into()
    }
}

impl<'a> TryFrom<&'a [u8]> for AttrId {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<AttrId, Error> {
        let (id, _) = Self::try_decode_from(bytes)?;
        Ok(id)
    }
}

impl<'a> TryDecodeFrom<'a> for AttrId {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        let (code, ptr) = u8::try_decode_from(bytes)?;
        Ok((AttrId::try_from(code)?, ptr))
    }
}

impl TryFrom<&str> for AttrId {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "key-is-encrypted" => Ok(AttrId::KeyIsEncrypted),
            "key-data" => Ok(AttrId::KeyData),
            "cipher-codec" => Ok(AttrId::CipherCodec),
            "cipher-key-len" => Ok(AttrId::CipherKeyLen),
            "cipher-nonce" => Ok(AttrId::CipherNonce),
            "cipher-nonce-len" => Ok(AttrId::CipherNonceLen),
            "kdf-codec" => Ok(AttrId::KdfCodec),
            "kdf-salt" => Ok(AttrId::KdfSalt),
            "kdf-salt-len" => Ok(AttrId::KdfSaltLen),
            "kdf-rounds" => Ok(AttrId::KdfRounds),
            _ => Err(AttributesError::InvalidAttributeName(s.to_string()).into()),
        }
    }
}

impl fmt::Display for AttrId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
