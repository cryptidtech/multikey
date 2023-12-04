use crate::{
    attributes_view, cipher_attributes_view, conversions_view,
    error::{AttributesError, CipherError, ConversionsError, KdfError},
    kdf_attributes_view, AttrId, AttributesView, Builder, CipherAttributesView, CipherView,
    ConversionsView, Error, KdfAttributesView, Multikey,
};
use multicodec::Codec;
use multihash::{mh, Multihash};
use multitrait::TryDecodeFrom;
use multiutil::Varuint;
use sodiumoxide::crypto::aead::chacha20poly1305;
use zeroize::Zeroizing;

/// the constants for ChaCha20
pub const KEY_LENGTH: usize = chacha20poly1305::KEYBYTES;
pub const NONCE_LENGTH: usize = chacha20poly1305::NONCEBYTES;

pub(crate) struct View<'a> {
    mk: &'a Multikey,
}

impl<'a> TryFrom<&'a Multikey> for View<'a> {
    type Error = Error;

    fn try_from(mk: &'a Multikey) -> Result<Self, Self::Error> {
        Ok(Self { mk })
    }
}

impl<'a> CipherView for View<'a> {
    fn decrypt(&self, mk: &Multikey) -> Result<Multikey, Error> {
        // get a view on the cipher attributes
        let cattr = cipher_attributes_view(&self.mk)?;

        // get the nonce
        let nonce = cattr.borrow().nonce_bytes()?;
        if nonce.len() != self.nonce_length()? {
            return Err(CipherError::InvalidNonce.into());
        }
        let n = chacha20poly1305::Nonce::from_slice(nonce.as_slice())
            .ok_or(CipherError::InvalidNonce)?;

        let attr = attributes_view(self.mk)?;
        let key = attr.borrow().secret_bytes()?;
        if key.len() != self.key_length()? {
            return Err(CipherError::InvalidKey.into());
        }
        let k = chacha20poly1305::Key::from_slice(key.as_slice()).ok_or(CipherError::InvalidKey)?;

        // get the encrypted key bytes from the passed-in Multikey
        let msg = {
            let attr = attributes_view(mk)?;
            let msg = attr.borrow().key_bytes()?;
            msg
        };

        let dec = chacha20poly1305::open(msg.as_slice(), None, &n, &k)
            .map_err(|_| CipherError::DecryptionFailed)?;

        // create a new multikey from the passed-in multikey with the decrypted
        // key and clear out all of the cipher and kdf attributes
        let mut res = mk.clone();
        let _ = res.attributes.remove(&AttrId::KeyIsEncrypted);
        res.attributes.insert(AttrId::KeyData, dec.into());
        let _ = res.attributes.remove(&AttrId::CipherCodec);
        let _ = res.attributes.remove(&AttrId::CipherKeyLen);
        let _ = res.attributes.remove(&AttrId::CipherNonce);
        let _ = res.attributes.remove(&AttrId::CipherNonceLen);
        let _ = res.attributes.remove(&AttrId::KdfCodec);
        let _ = res.attributes.remove(&AttrId::KdfSalt);
        let _ = res.attributes.remove(&AttrId::KdfSaltLen);
        let _ = res.attributes.remove(&AttrId::KdfRounds);
        Ok(res)
    }

    fn encrypt(&self, mk: &Multikey) -> Result<Multikey, Error> {
        // get a view on the cipher attributes
        let cattr = cipher_attributes_view(&self.mk)?;

        // get the nonce
        let nonce = cattr.borrow().nonce_bytes()?;
        if nonce.len() != self.nonce_length()? {
            return Err(CipherError::InvalidNonce.into());
        }
        let n = chacha20poly1305::Nonce::from_slice(nonce.as_slice())
            .ok_or(CipherError::InvalidNonce)?;

        let attr = attributes_view(self.mk)?;
        let key = attr.borrow().secret_bytes()?;
        if key.len() != self.key_length()? {
            return Err(CipherError::InvalidKey.into());
        }
        let k = chacha20poly1305::Key::from_slice(key.as_slice()).ok_or(CipherError::InvalidKey)?;

        // get the secret bytes from the passed-in Multikey
        let msg = {
            let attr = attributes_view(mk)?;
            let msg = attr.borrow().secret_bytes()?;
            msg
        };

        // encrypt the secret bytes from the passed-in Multikey
        let enc = chacha20poly1305::seal(msg.as_slice(), None, &n, &k);

        // prepare the attributes
        let codec: Vec<u8> = self.mk.codec.into();
        let key_length: Vec<u8> = Varuint(self.key_length()?).into();
        let nonce_length: Vec<u8> = Varuint(self.nonce_length()?).into();
        let is_encrypted: Vec<u8> = Varuint(true).into();

        // get a view on the kdf attributes
        let kattr = kdf_attributes_view(&self.mk)?;

        let kdf_codec: Vec<u8> = kattr.borrow().kdf_codec()?.into();
        let salt = kattr.borrow().salt_bytes()?;
        let salt_length: Vec<u8> = Varuint(kattr.borrow().salt_length()?).into();
        let rounds: Vec<u8> = Varuint(kattr.borrow().rounds()?).into();

        // create a new multikey from the passed-in multikey with the cipher
        // and kdf parameters added along with the encrypted key
        let mut res = mk.clone();
        res.attributes
            .insert(AttrId::KeyIsEncrypted, is_encrypted.into());
        res.attributes.insert(AttrId::KeyData, enc.into());
        res.attributes.insert(AttrId::CipherCodec, codec.into());
        res.attributes
            .insert(AttrId::CipherKeyLen, key_length.into());
        res.attributes.insert(AttrId::CipherNonce, nonce.clone());
        res.attributes
            .insert(AttrId::CipherNonceLen, nonce_length.into());
        res.attributes.insert(AttrId::KdfCodec, kdf_codec.into());
        res.attributes.insert(AttrId::KdfSalt, salt.clone());
        res.attributes
            .insert(AttrId::KdfSaltLen, salt_length.into());
        res.attributes.insert(AttrId::KdfRounds, rounds.into());
        Ok(res)
    }
}

impl<'a> AttributesView for View<'a> {
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

    /// return the ChaCha20 key bytes
    fn key_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let key = self
            .mk
            .attributes
            .get(&AttrId::KeyData)
            .ok_or(AttributesError::MissingKey)?;
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

impl<'a> CipherAttributesView for View<'a> {
    fn cipher_codec(&self) -> Result<Codec, Error> {
        Ok(self.mk.codec)
    }

    fn nonce_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        // try to look up the salt in the multikey attributes
        self.mk
            .attributes
            .get(&AttrId::CipherNonce)
            .ok_or(CipherError::MissingNonce.into())
            .cloned()
    }

    fn nonce_length(&self) -> Result<usize, Error> {
        Ok(NONCE_LENGTH)
    }

    fn key_length(&self) -> Result<usize, Error> {
        Ok(KEY_LENGTH)
    }
}

impl<'a> KdfAttributesView for View<'a> {
    fn kdf_codec(&self) -> Result<Codec, Error> {
        // try to look up the kdf codec in the multikey attributes
        let codec = self
            .mk
            .attributes
            .get(&AttrId::KdfCodec)
            .ok_or(KdfError::MissingCodec)?;
        Ok(Codec::try_from(codec.as_slice())?)
    }

    fn salt_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        // try to look up the salt in the multikey attributes
        self.mk
            .attributes
            .get(&AttrId::KdfSalt)
            .ok_or(KdfError::MissingSalt.into())
            .cloned()
    }

    fn salt_length(&self) -> Result<usize, Error> {
        // try to look up the kdf salt length in the multikey attributes
        let salt_length = self
            .mk
            .attributes
            .get(&AttrId::KdfSaltLen)
            .ok_or(KdfError::MissingSaltLen)?;
        Ok(Varuint::<usize>::try_from(salt_length.as_slice())?.to_inner())
    }

    fn rounds(&self) -> Result<usize, Error> {
        // try to look up the rounds in the multikey attributes
        let rounds = self
            .mk
            .attributes
            .get(&AttrId::KdfRounds)
            .ok_or(KdfError::MissingRounds)?;
        Ok(Varuint::<usize>::try_from(rounds.as_slice())?.to_inner())
    }
}

impl<'a> ConversionsView for View<'a> {
    fn fingerprint(&self, codec: Codec) -> Result<Multihash, Error> {
        let attr = attributes_view(&self.mk)?;
        if attr.borrow().is_secret_key() {
            // convert to a public key Multikey
            let pk = self.to_public_key()?;
            // get a conversions view on the public key
            let conv = conversions_view(&pk)?;
            // get the fingerprint
            let f = conv.borrow().fingerprint(codec)?;
            Ok(f)
        } else {
            // get the key bytes
            let bytes = attr.borrow().key_bytes()?;
            // hash the key bytes using the given codec
            Ok(mh::Builder::new_from_bytes(codec, bytes)?.try_build()?)
        }
    }

    fn to_public_key(&self) -> Result<Multikey, Error> {
        Err(ConversionsError::UnsupportedCodec(self.mk.codec).into())
    }

    fn to_secret_key(&self) -> Result<Multikey, Error> {
        let attr = attributes_view(&self.mk)?;
        // get the secret key bytes
        let key = attr.borrow().secret_bytes()?;
        // build a new secret key Multikey from it
        Builder::new(self.mk.codec)
            .with_comment(&self.mk.comment)
            .with_key_bytes(&key)
            .try_build()
    }
}
