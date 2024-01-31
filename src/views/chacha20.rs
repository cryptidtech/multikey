use crate::{
    error::{AttributesError, CipherError, KdfError},
    AttrId, AttrView, CipherAttrView, CipherView, Error, FingerprintView, KdfAttrView, KeyDataView,
    Multikey, Views,
};
use multicodec::Codec;
use multihash::{mh, Multihash};
use multitrait::TryDecodeFrom;
use multiutil::Varuint;
use sodiumoxide::crypto::aead::chacha20poly1305;
use zeroize::Zeroizing;

use super::bcrypt::SALT_LENGTH;

/// the constants for ChaCha20
pub const KEY_LENGTH: usize = chacha20poly1305::KEYBYTES;
pub const NONCE_LENGTH: usize = chacha20poly1305::NONCEBYTES;

pub(crate) struct View<'a> {
    mk: &'a Multikey,
    cipher: Option<&'a Multikey>,
}

impl<'a> View<'a> {
    pub fn new(mk: &'a Multikey, cipher: &'a Multikey) -> Self {
        Self {
            mk,
            cipher: Some(cipher),
        }
    }
}

impl<'a> TryFrom<&'a Multikey> for View<'a> {
    type Error = Error;

    fn try_from(mk: &'a Multikey) -> Result<Self, Self::Error> {
        Ok(Self { mk, cipher: None })
    }
}

impl<'a> AttrView for View<'a> {
    fn is_encrypted(&self) -> bool {
        if let Some(v) = self.mk.attributes.get(&AttrId::KeyIsEncrypted) {
            if let Ok((b, _)) = Varuint::<bool>::try_decode_from(v.as_slice()) {
                return b.to_inner();
            }
        }
        return false;
    }

    fn is_secret_key(&self) -> bool {
        true
    }

    fn is_public_key(&self) -> bool {
        false
    }

    fn is_secret_key_share(&self) -> bool {
        false
    }
}

impl<'a> KeyDataView for View<'a> {
    /// return the ChaCha20 key bytes
    fn key_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let key = self
            .mk
            .attributes
            .get(&AttrId::KeyData)
            .ok_or_else(|| AttributesError::MissingKey)?;
        Ok(key.clone())
    }

    /// Check to see if this is a secret key before returning the key bytes
    fn secret_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        if self.is_encrypted() {
            return Err(AttributesError::EncryptedKey.into());
        }
        Ok(self.key_bytes()?)
    }
}

impl<'a> CipherAttrView for View<'a> {
    fn cipher_codec(&self) -> Result<Codec, Error> {
        Ok(Codec::Chacha20Poly1305)
    }

    fn nonce_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        // try to look up the salt in the multikey attributes
        let nonce = self
            .mk
            .attributes
            .get(&AttrId::CipherNonce)
            .ok_or_else(|| CipherError::MissingNonce)?;
        if nonce.len() != NONCE_LENGTH {
            Err(CipherError::InvalidNonceLen.into())
        } else {
            Ok(nonce.clone())
        }
    }

    fn key_length(&self) -> Result<usize, Error> {
        Ok(KEY_LENGTH)
    }
}

impl<'a> KdfAttrView for View<'a> {
    fn kdf_codec(&self) -> Result<Codec, Error> {
        // try to look up the kdf codec in the multikey attributes
        let codec = self
            .mk
            .attributes
            .get(&AttrId::KdfCodec)
            .ok_or_else(|| KdfError::MissingCodec)?;
        Ok(Codec::try_from(codec.as_slice())?)
    }

    fn salt_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        // try to look up the salt in the multikey attributes
        let salt = self
            .mk
            .attributes
            .get(&AttrId::KdfSalt)
            .ok_or_else(|| KdfError::MissingSalt)?;
        if salt.len() != SALT_LENGTH {
            Err(KdfError::InvalidSaltLen.into())
        } else {
            Ok(salt.clone())
        }
    }

    fn rounds(&self) -> Result<usize, Error> {
        // try to look up the rounds in the multikey attributes
        let rounds = self
            .mk
            .attributes
            .get(&AttrId::KdfRounds)
            .ok_or_else(|| KdfError::MissingRounds)?;
        Ok(Varuint::<usize>::try_from(rounds.as_slice())?.to_inner())
    }
}

impl<'a> CipherView for View<'a> {
    fn decrypt(&self) -> Result<Multikey, Error> {
        let cipher = self.cipher.ok_or_else(|| CipherError::MissingCodec)?;
        // make sure the viewed key is an encrypted secret key
        let attr = self.mk.attr_view()?;
        if !attr.is_encrypted() || !attr.is_secret_key() {
            return Err(CipherError::DecryptionFailed.into());
        }

        // get the nonce data from the passed-in Multikey
        let nonce = {
            let cattr = cipher.cipher_attr_view()?;
            cattr.nonce_bytes()?
        };

        // create the chacha nonce from the data
        let n = chacha20poly1305::Nonce::from_slice(nonce.as_slice())
            .ok_or_else(|| CipherError::InvalidNonce)?;

        // get the key data from the passed-in Multikey
        let key = {
            let kd = cipher.key_data_view()?;
            let key = kd.secret_bytes()?;
            if key.len() != self.key_length()? {
                return Err(CipherError::InvalidKey.into());
            }
            key
        };

        // create the chacha key from the data
        let k = chacha20poly1305::Key::from_slice(key.as_slice())
            .ok_or_else(|| CipherError::InvalidKey)?;

        // get the encrypted key bytes from the viewed Multikey (self)
        let msg = {
            let attr = self.mk.key_data_view()?;
            let msg = attr.key_bytes()?;
            msg
        };

        // decrypt the key bytes
        let dec = chacha20poly1305::open(msg.as_slice(), None, &n, &k)
            .map_err(|_| CipherError::DecryptionFailed)?;

        // create a new Multikey from the viewed Multikey (self) with the
        // decrypted key and none of the kdf or cipher attributes
        let mut res = self.mk.clone();
        let _ = res.attributes.remove(&AttrId::KeyIsEncrypted);
        res.attributes.insert(AttrId::KeyData, dec.into());
        let _ = res.attributes.remove(&AttrId::CipherCodec);
        let _ = res.attributes.remove(&AttrId::CipherKeyLen);
        let _ = res.attributes.remove(&AttrId::CipherNonce);
        let _ = res.attributes.remove(&AttrId::KdfCodec);
        let _ = res.attributes.remove(&AttrId::KdfSalt);
        let _ = res.attributes.remove(&AttrId::KdfRounds);
        Ok(res)
    }

    fn encrypt(&self) -> Result<Multikey, Error> {
        let cipher = self.cipher.ok_or_else(|| CipherError::MissingCodec)?;
        // make sure the viewed key is not encrypted
        let attr = self.mk.attr_view()?;
        if attr.is_encrypted() {
            return Err(
                CipherError::EncryptionFailed("key is encrypted already".to_string()).into(),
            );
        }

        // get the nonce data from the passed-in Multikey
        let nonce = {
            let cattr = cipher.cipher_attr_view()?;
            cattr.nonce_bytes()?
        };

        let n = chacha20poly1305::Nonce::from_slice(nonce.as_slice())
            .ok_or_else(|| CipherError::InvalidNonce)?;

        // get the key data from the passed-in Multikey
        let key = {
            let kd = cipher.key_data_view()?;
            let key = kd.secret_bytes()?;
            if key.len() != self.key_length()? {
                return Err(CipherError::InvalidKey.into());
            }
            key
        };

        let k = chacha20poly1305::Key::from_slice(key.as_slice())
            .ok_or_else(|| CipherError::InvalidKey)?;

        // get the secret bytes from the viewed Multikey
        let msg = {
            let kd = self.mk.key_data_view()?;
            let msg = kd.secret_bytes()?;
            msg
        };

        // encrypt the secret bytes from the viewed Multikey
        let enc = chacha20poly1305::seal(msg.as_slice(), None, &n, &k);

        // prepare the cipher attributes
        let cattr = cipher.cipher_attr_view()?;
        let cipher_codec: Vec<u8> = cipher.codec.into();
        let key_length: Vec<u8> = Varuint(cattr.key_length()?).into();
        let is_encrypted: Vec<u8> = Varuint(true).into();

        // get a view on the kdf attributes
        let kattr = cipher.kdf_attr_view()?;
        let kdf_codec: Vec<u8> = kattr.kdf_codec()?.into();
        let salt = kattr.salt_bytes()?;
        let rounds: Vec<u8> = Varuint(kattr.rounds()?).into();

        // create a copy of the viewed Multikey (self) and add in the encrypted
        // key data as awell as the kdf and cipher attributes and data so that
        // the encrypted Multikey is self-describing about how it was encrypted
        let mut res = self.mk.clone();
        res.attributes
            .insert(AttrId::KeyIsEncrypted, is_encrypted.into());
        res.attributes.insert(AttrId::KeyData, enc.into());
        res.attributes
            .insert(AttrId::CipherCodec, cipher_codec.into());
        res.attributes
            .insert(AttrId::CipherKeyLen, key_length.into());
        res.attributes.insert(AttrId::CipherNonce, nonce.clone());
        res.attributes.insert(AttrId::KdfCodec, kdf_codec.into());
        res.attributes.insert(AttrId::KdfSalt, salt.clone());
        res.attributes.insert(AttrId::KdfRounds, rounds.into());
        Ok(res)
    }
}

impl<'a> FingerprintView for View<'a> {
    fn fingerprint(&self, codec: Codec) -> Result<Multihash, Error> {
        // get the key bytes
        let bytes = {
            let kd = self.mk.key_data_view()?;
            let bytes = kd.key_bytes()?;
            bytes
        };
        // hash the key bytes using the given codec
        Ok(mh::Builder::new_from_bytes(codec, bytes)?.try_build()?)
    }
}
