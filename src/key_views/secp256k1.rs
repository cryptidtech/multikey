use crate::{
    error::{AttributesError, CipherError, ConversionsError, KdfError, SignError, VerifyError},
    AttrId, AttrView, Builder, CipherAttrView, Error, FingerprintView, KdfAttrView, KeyConvView,
    KeyDataView, KeyViews, Multikey, SignView, VerifyView,
};

use k256::ecdsa::{
    signature::{Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
use multicodec::Codec;
use multihash::{mh, Multihash};
use multisig::{ms, Multisig, SigViews};
use multitrait::TryDecodeFrom;
use multiutil::Varuint;
use zeroize::Zeroizing;

const SECRET_KEY_LENGTH: usize = 32;
const PUBLIC_KEY_LENGTH: usize = 33;

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
        self.mk.codec == Codec::Secp256K1Priv
    }

    fn is_public_key(&self) -> bool {
        self.mk.codec == Codec::Secp256K1Pub
    }
}

impl<'a> KeyDataView for View<'a> {
    /// For Secp256K1Pub and Secp256K1Priv Multikey values, the key data is stored
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
        let secret_key = SigningKey::from_bytes(&bytes.into())
            .map_err(|e| ConversionsError::SecretKeyFailure(e.to_string()))?;
        // get the public key and build a Multikey out of it
        let public_key = secret_key.verifying_key();
        Builder::new(Codec::Secp256K1Pub)
            .with_comment(&self.mk.comment)
            .with_key_bytes(&public_key.to_sec1_bytes())
            .try_build()
    }
}

impl<'a> SignView for View<'a> {
    /// try to create a Multisig by siging the passed-in data with the Multikey
    fn sign(&self, msg: &[u8], combined: bool) -> Result<Multisig, Error> {
        let attr = self.mk.attr_view()?;
        if !attr.borrow().is_secret_key() {
            return Err(SignError::NotSigningKey.into());
        }

        // get the secret key bytes
        let secret_bytes = {
            let kd = self.mk.key_data_view()?;
            let secret_bytes = kd.borrow().secret_bytes()?;
            secret_bytes
        };

        let secret_key = {
            // build an Ed25519 signing key so that we can derive the verifying key
            let bytes: [u8; SECRET_KEY_LENGTH] = secret_bytes.as_slice()[..SECRET_KEY_LENGTH]
                .try_into()
                .map_err(|_| {
                    ConversionsError::SecretKeyFailure("failed to get secret key bytes".to_string())
                })?;
            let secret_key = SigningKey::from_bytes(&bytes.into())
                .map_err(|e| ConversionsError::SecretKeyFailure(e.to_string()))?;
            secret_key
        };

        // sign the data
        let signature: Signature = secret_key
            .try_sign(msg)
            .map_err(|e| SignError::SigningFailed(e.to_string()))?;

        let mut ms =
            ms::Builder::new(Codec::Secp256K1Pub).with_signature_bytes(signature.to_bytes());
        if combined {
            ms = ms.with_message_bytes(&msg);
        }
        Ok(ms.try_build()?)
    }
}

impl<'a> VerifyView for View<'a> {
    /// try to verify a Multisig using the Multikey
    fn verify(&self, multisig: &Multisig, msg: Option<&[u8]>) -> Result<(), Error> {
        let attr = self.mk.attr_view()?;
        let pubmk = if attr.borrow().is_secret_key() {
            let kc = self.mk.key_conv_view()?;
            let mk = kc.borrow().to_public_key()?;
            mk
        } else {
            self.mk.clone()
        };

        // get the secret key bytes
        let key_bytes = {
            let kd = pubmk.key_data_view()?;
            let key_bytes = kd.borrow().key_bytes()?;
            key_bytes
        };

        // build an Ed25519 verifying key so that we can derive the verifying key
        let bytes: [u8; PUBLIC_KEY_LENGTH] = key_bytes.as_slice()[..PUBLIC_KEY_LENGTH]
            .try_into()
            .map_err(|_| {
            ConversionsError::PublicKeyFailure("failed to get public key bytes".to_string())
        })?;

        // create the verifying key
        let verifying_key = VerifyingKey::from_sec1_bytes(&bytes)
            .map_err(|e| ConversionsError::PublicKeyFailure(e.to_string()))?;

        // get the signature data
        let sv = multisig.sig_data_view()?;
        let sig = sv
            .borrow()
            .sig_bytes()
            .map_err(|_| VerifyError::MissingSignature)?;

        // create the signature
        let sig = Signature::from_slice(sig.as_slice())
            .map_err(|e| VerifyError::BadSignature(e.to_string()))?;

        // get the message
        let msg = if let Some(msg) = msg {
            msg
        } else if multisig.message.len() > 0 {
            multisig.message.as_slice()
        } else {
            return Err(VerifyError::MissingMessage.into());
        };

        verifying_key.verify(msg, &sig).map_err(|e| {
            println!("{}", e.to_string());
            VerifyError::BadSignature(e.to_string())
        })?;

        Ok(())
    }
}
