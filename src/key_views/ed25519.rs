use crate::{
    error::{AttributesError, CipherError, ConversionsError, KdfError},
    AttrId, AttrView, Builder, CipherAttrView, Error, FingerprintView, KdfAttrView, KeyConvView,
    KeyDataView, KeyViews, Multikey,
};
use ed25519_dalek::{SigningKey, SECRET_KEY_LENGTH};
use multicodec::Codec;
use multihash::{mh, Multihash};
use multitrait::TryDecodeFrom;
use multiutil::Varuint;
use zeroize::Zeroizing;

pub(crate) struct View<'a> {
    mk: &'a Multikey,
}

impl<'a> TryFrom<&'a Multikey> for View<'a> {
    type Error = Error;

    fn try_from(mk: &'a Multikey) -> Result<Self, Self::Error> {
        Ok(Self { mk })
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
        self.mk.codec == Codec::Ed25519Priv
    }

    fn is_public_key(&self) -> bool {
        self.mk.codec == Codec::Ed25519Pub
    }
}

impl<'a> KeyDataView for View<'a> {
    /// For Ed25519Pub and Ed25519Priv Multikey values, the key data is stored
    /// using the AttrId::Data attribute id.
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
        if !self.is_secret_key() {
            return Err(AttributesError::NotSecretKey(self.mk.codec).into());
        }
        if self.is_encrypted() {
            return Err(AttributesError::EncryptedKey.into());
        }
        Ok(self.key_bytes()?)
    }
}

impl<'a> CipherAttrView for View<'a> {
    fn cipher_codec(&self) -> Result<Codec, Error> {
        // try to look up the cipher codec in the multikey attributes
        let codec = self
            .mk
            .attributes
            .get(&AttrId::CipherCodec)
            .ok_or(CipherError::MissingCodec)?;
        Ok(Codec::try_from(codec.as_slice())?)
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
        // try to look up the cipher nonce length in the multikey attributes
        let nonce_length = self
            .mk
            .attributes
            .get(&AttrId::CipherNonceLen)
            .ok_or(CipherError::MissingNonceLen)?;
        Ok(Varuint::<usize>::try_from(nonce_length.as_slice())?.to_inner())
    }

    fn key_length(&self) -> Result<usize, Error> {
        // try to look up the cipher key length in the multikey attributes
        let key_length = self
            .mk
            .attributes
            .get(&AttrId::CipherKeyLen)
            .ok_or(CipherError::MissingKeyLen)?;
        Ok(Varuint::<usize>::try_from(key_length.as_slice())?.to_inner())
    }
}

impl<'a> KdfAttrView for View<'a> {
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

impl<'a> FingerprintView for View<'a> {
    fn fingerprint(&self, codec: Codec) -> Result<Multihash, Error> {
        let attr = self.mk.attr_view()?;
        if attr.borrow().is_secret_key() {
            // convert to a public key Multikey
            let pk = self.to_public_key()?;
            // get a conversions view on the public key
            let fp = pk.fingerprint_view()?;
            // get the fingerprint
            let f = fp.borrow().fingerprint(codec)?;
            Ok(f)
        } else {
            // get the key bytes
            let bytes = {
                let kd = self.mk.key_data_view()?;
                let bytes = kd.borrow().key_bytes()?;
                bytes
            };
            // hash the key bytes using the given codec
            Ok(mh::Builder::new_from_bytes(codec, bytes)?.try_build()?)
        }
    }
}

impl<'a> KeyConvView for View<'a> {
    fn to_public_key(&self) -> Result<Multikey, Error> {
        // get the secret key bytes
        let secret_bytes = {
            let kd = self.mk.key_data_view()?;
            let secret_bytes = kd.borrow().secret_bytes()?;
            secret_bytes
        };

        // build an Ed25519 signing key so that we can derive the verifying key
        let bytes: [u8; SECRET_KEY_LENGTH] = secret_bytes.as_slice()[..SECRET_KEY_LENGTH]
            .try_into()
            .map_err(|_| {
                ConversionsError::SecretKeyFailure("failed to get secret key bytes".to_string())
            })?;
        let private_key = SigningKey::from_bytes(&bytes);
        // get the public key and build a Multikey out of it
        let public_key = private_key.verifying_key();
        Builder::new(Codec::Ed25519Pub)
            .with_comment(&self.mk.comment)
            .with_key_bytes(public_key.as_bytes())
            .try_build()
    }
}
