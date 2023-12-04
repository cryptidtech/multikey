use crate::{
    error::{AttributesError, CipherError, ConversionsError, KdfError},
    Error, Multikey,
};
use multicodec::Codec;
use multihash::Multihash;
use multitrait::{EncodeInto, TryDecodeFrom};
use std::{cell::RefCell, fmt, rc::Rc};
use zeroize::Zeroizing;

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

/// trait for returning various attributes about a Multikey
pub trait AttributesView {
    /// is this key encrypted
    fn is_encrypted(&self) -> bool;
    /// is this key a public key that can be shared? for symmetric encryption
    /// codecs, this is always false. for public key encryption codecs, this
    /// is true if this key is the public key of the key pair.
    fn is_public_key(&self) -> bool;
    /// is this key one that should be kept secret? for symmetric encryption
    /// codecs, this is always true. for public key encryption codecs, this
    /// is true if this key is the secret key of the key pair.
    fn is_secret_key(&self) -> bool;
    /// get the key bytes from the viewed Multikey. this is codec specific.
    fn key_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error>;
    /// get the bytes that constitutes the secret. this is codec specific and
    /// must return all of the bytes that should be encrypted to protect the
    /// secret part of the key
    fn secret_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error>;
}

/// trait for converting a Multikey in various ways
pub trait ConversionsView {
    /// get the fingerprint of this key. the fingerprint is the hash of the
    /// secret key if it is a symmetric key and the hash of the public key if
    /// this key codec is a public key encryption codec. if this key is the
    /// secret key of a public key encryption codec, the public key will
    /// automatically be derived if possible and the fingerprint will be
    /// generated from that.
    fn fingerprint(&self, codec: Codec) -> Result<Multihash, Error>;
    /// try to create a Multikey from this view that is the public key part of
    /// a key pair. this always fails for symmetric encryption codecs.
    fn to_public_key(&self) -> Result<Multikey, Error>;
    /// try to create a Multikey from this view that is the secret key part of
    /// a key pair. this always succeeds for symmetric encryption codecs
    fn to_secret_key(&self) -> Result<Multikey, Error>;
}

/// trait for encrypting and decrypting Multikeys
pub trait CipherView {
    /// decrypt the secret_bytes from the passed-in Multikey using the codec in
    /// the viewed Multikey. the result is a copy of the passed-in Multikey but
    /// with the decrypted bytes stored under the Data attribute.
    fn decrypt(&self, mk: &Multikey) -> Result<Multikey, Error>;
    /// encrypt the secret_bytes from the passed-in Multikey using the codec in
    /// the viewed Multikey. the result is a copy of the passed-in Multikey but
    /// with the encrypted bytes stored under the Data attribute. also, the
    /// EncryptionCodec and Nonce attributes are set to the values from the
    /// viewed Multikey.
    fn encrypt(&self, mk: &Multikey) -> Result<Multikey, Error>;
}

/// trait for viewing the cipher attributes in a Multikey
pub trait CipherAttributesView {
    /// get the cipher codec from the viewed multikey
    fn cipher_codec(&self) -> Result<Codec, Error>;
    /// get the nonce bytes from the viewed multikey
    fn nonce_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error>;
    /// get the nonce lgnth from the viewed multikey
    fn nonce_length(&self) -> Result<usize, Error>;
    /// get the key length from the viewed multikey
    fn key_length(&self) -> Result<usize, Error>;
}

/// trait for doing key derivation functions using a Multikey for the parameters
pub trait KdfView {
    /// derive an encryption key, storing the parameters in given Multikey
    /// the result is a copy of the passed-in Multikey with the derived key in
    /// the Data attribute. also, the KdfCodec, Salt, and Rounds attributes are
    /// set to the values from the viewed Multikey.
    fn derive_key(&self, mk: &Multikey, passphrase: &[u8]) -> Result<Multikey, Error>;
}

/// trait for viewing the kdf attributes in a Multikey
pub trait KdfAttributesView {
    /// get the kdf codec from the viewed multikey
    fn kdf_codec(&self) -> Result<Codec, Error>;
    /// get the salt bytes from the viewed multikey
    fn salt_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error>;
    /// get the salt length from the viewed multikey
    fn salt_length(&self) -> Result<usize, Error>;
    /// get the number of rounds for the KDF function from the viewed multikey
    fn rounds(&self) -> Result<usize, Error>;
}

// algorithms implement different sets of view
pub(crate) mod bcrypt; // KdfView
pub(crate) mod chacha20; // AttributesView, ConversionsView, CipherView
pub(crate) mod ed25519; // AttributesView, ConversionsView, CipherView

/// Provide a read-only view of the attributes of the given Multikey
pub fn attributes_view<'a>(
    mk: &'a Multikey,
) -> Result<Rc<RefCell<dyn AttributesView + 'a>>, Error> {
    match mk.codec {
        Codec::Ed25519Pub | Codec::Ed25519Priv => {
            Ok(Rc::new(RefCell::new(ed25519::View::try_from(mk)?)))
        }
        Codec::Chacha20Poly1305 => Ok(Rc::new(RefCell::new(chacha20::View::try_from(mk)?))),
        _ => Err(AttributesError::UnsupportedCodec(mk.codec).into()),
    }
}

/// Provide a read-only view to do common conversions from the given Multikey
pub fn conversions_view<'a>(
    mk: &'a Multikey,
) -> Result<Rc<RefCell<dyn ConversionsView + 'a>>, Error> {
    match mk.codec {
        Codec::Ed25519Pub | Codec::Ed25519Priv => {
            Ok(Rc::new(RefCell::new(ed25519::View::try_from(mk)?)))
        }
        Codec::Chacha20Poly1305 => Ok(Rc::new(RefCell::new(chacha20::View::try_from(mk)?))),
        _ => Err(ConversionsError::UnsupportedCodec(mk.codec).into()),
    }
}

/// Provide an interface to do encryption/decryption from the given Multikey
pub fn cipher_view<'a>(mk: &'a Multikey) -> Result<Rc<RefCell<dyn CipherView + 'a>>, Error> {
    match mk.codec {
        Codec::Chacha20Poly1305 => Ok(Rc::new(RefCell::new(chacha20::View::try_from(mk)?))),
        _ => Err(CipherError::UnsupportedCodec(mk.codec).into()),
    }
}

/// Provide a read-only view of the cipher attributes the given Multikey
pub fn cipher_attributes_view<'a>(
    mk: &'a Multikey,
) -> Result<Rc<RefCell<dyn CipherAttributesView + 'a>>, Error> {
    match mk.codec {
        Codec::Chacha20Poly1305 => Ok(Rc::new(RefCell::new(chacha20::View::try_from(mk)?))),
        Codec::Ed25519Pub | Codec::Ed25519Priv => {
            Ok(Rc::new(RefCell::new(ed25519::View::try_from(mk)?)))
        }
        _ => Err(CipherError::UnsupportedCodec(mk.codec).into()),
    }
}

/// Provide an interface to do common kdf operations from the given Multikey
pub fn kdf_view<'a>(mk: &'a Multikey) -> Result<Rc<RefCell<dyn KdfView + 'a>>, Error> {
    match mk.codec {
        Codec::BcryptPbkdf => Ok(Rc::new(RefCell::new(bcrypt::View::try_from(mk)?))),
        _ => Err(KdfError::UnsupportedCodec(mk.codec).into()),
    }
}

/// Provide a read-only view of the kdf attributes the given Multikey
pub fn kdf_attributes_view<'a>(
    mk: &'a Multikey,
) -> Result<Rc<RefCell<dyn KdfAttributesView + 'a>>, Error> {
    match mk.codec {
        Codec::BcryptPbkdf => Ok(Rc::new(RefCell::new(bcrypt::View::try_from(mk)?))),
        Codec::Chacha20Poly1305 => Ok(Rc::new(RefCell::new(chacha20::View::try_from(mk)?))),
        Codec::Ed25519Pub | Codec::Ed25519Priv => {
            Ok(Rc::new(RefCell::new(ed25519::View::try_from(mk)?)))
        }
        _ => Err(KdfError::UnsupportedCodec(mk.codec).into()),
    }
}
