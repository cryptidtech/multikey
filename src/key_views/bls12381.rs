use crate::{
    error::{AttributesError, CipherError, ConversionsError, KdfError, SignError, VerifyError},
    AttrId, AttrView, Builder, CipherAttrView, Error, FingerprintView, KdfAttrView, KeyConvView,
    KeyDataView, KeyViews, Multikey, SignView, ThresholdAttrView, VerifyView,
};
use blsful::{
    inner_types::{G1Projective, G2Projective},
    Bls12381G1Impl, Bls12381G2Impl, PublicKey, PublicKeyShare, SecretKey, SecretKeyShare,
    Signature, SignatureSchemes, SignatureShare, SECRET_KEY_BYTES,
};
use elliptic_curve::group::GroupEncoding;
use multicodec::Codec;
use multihash::{mh, Multihash};
use multisig::{ms, sig_views::bls12381::SchemeTypeId, Multisig, SigViews};
use multiutil::Varuint;
use ssh_encoding::{Decode, Encode};
use std::array::TryFromSliceError;
use vsss_rs::Share;
use zeroize::Zeroizing;

/// the RFC 4251 algorithm name for SSH compatibility
pub const ALGORITHM_NAME_G1: &'static str = "bls12_381-g1@multikey";
pub const ALGORITHM_NAME_G1_SHARE: &'static str = "bls12_381-g1-share@multikey";
pub const ALGORITHM_NAME_G2: &'static str = "bls12_381-g2@multikey";
pub const ALGORITHM_NAME_G2_SHARE: &'static str = "bls12_381-g2-share@multikey";

// number of bytes in a G1 and G2 public key
pub const G1_PUBLIC_KEY_BYTES: usize = 48;
pub const G2_PUBLIC_KEY_BYTES: usize = 96;

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
            if let Ok(b) = Varuint::<bool>::try_from(v.as_slice()) {
                return b.to_inner();
            }
        }
        return false;
    }

    fn is_secret_key(&self) -> bool {
        match self.mk.codec {
            Codec::Bls12381G1Priv
            | Codec::Bls12381G2Priv
            | Codec::Bls12381G1PrivShare
            | Codec::Bls12381G2PrivShare => true,
            _ => false,
        }
    }

    fn is_public_key(&self) -> bool {
        match self.mk.codec {
            Codec::Bls12381G1Pub | Codec::Bls12381G2Pub => true,
            _ => false,
        }
    }

    fn is_secret_key_share(&self) -> bool {
        match self.mk.codec {
            Codec::Bls12381G1PrivShare | Codec::Bls12381G2PrivShare => true,
            _ => false,
        }
    }
}

impl<'a> ThresholdAttrView for View<'a> {
    /// get the threshold value for the multikey
    fn threshold(&self) -> Result<usize, Error> {
        let v = self
            .mk
            .attributes
            .get(&AttrId::Threshold)
            .ok_or(AttributesError::MissingThreshold)?;
        Ok(*Varuint::<usize>::try_from(v.as_slice())?)
    }
    /// get the limit value for the multikey
    fn limit(&self) -> Result<usize, Error> {
        let v = self
            .mk
            .attributes
            .get(&AttrId::Limit)
            .ok_or(AttributesError::MissingLimit)?;
        Ok(*Varuint::<usize>::try_from(v.as_slice())?)
    }
    /// get the share identifier for the multikey
    fn identifier(&self) -> Result<u8, Error> {
        let v = self
            .mk
            .attributes
            .get(&AttrId::ShareIdentifier)
            .ok_or(AttributesError::MissingShareIdentifier)?;
        Ok(*Varuint::<u8>::try_from(v.as_slice())?)
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
        if attr.is_secret_key() {
            // convert to a public key Multikey
            let pk = self.to_public_key()?;
            // get a conversions view on the public key
            let fp = pk.fingerprint_view()?;
            // get the fingerprint
            let f = fp.fingerprint(codec)?;
            Ok(f)
        } else {
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
}

impl<'a> KeyConvView for View<'a> {
    /// try to convert a secret key to a public key
    fn to_public_key(&self) -> Result<Multikey, Error> {
        // get the secret key bytes
        let secret_bytes = {
            let kd = self.mk.key_data_view()?;
            let secret_bytes = kd.secret_bytes()?;
            secret_bytes
        };

        match self.mk.codec {
            Codec::Bls12381G1Priv => {
                let bytes: [u8; SECRET_KEY_BYTES] = secret_bytes.as_slice()[..SECRET_KEY_BYTES]
                    .try_into()
                    .map_err(|_| {
                        ConversionsError::SecretKeyFailure(
                            "failed to get secret key bytes".to_string(),
                        )
                    })?;
                let secret_key: SecretKey<Bls12381G1Impl> = {
                    let sk = Option::from(SecretKey::from_be_bytes(&bytes));
                    sk.ok_or(ConversionsError::SecretKeyFailure(
                        "failed to create secret key".to_string(),
                    ))?
                };
                // get the public key and build a Multikey out of it
                let public_key = secret_key.public_key();
                let key_bytes = public_key.0.to_bytes();
                Builder::new(Codec::Bls12381G1Pub)
                    .with_comment(&self.mk.comment)
                    .with_key_bytes(&key_bytes)
                    .try_build()
            }
            Codec::Bls12381G1PrivShare => {
                let av = self.mk.threshold_attr_view()?;
                let threshold = av.threshold()?;
                let limit = av.limit()?;
                let identifier = av.identifier()?;

                let secret_key: SecretKeyShare<Bls12381G1Impl> = SecretKeyShare(
                    Share::with_identifier_and_value(identifier, secret_bytes.as_slice()),
                );

                // get the public key and build a Multikey out of it
                let public_key = secret_key
                    .public_key()
                    .map_err(|e| ConversionsError::PublicKeyFailure(e.to_string()))?;
                let key_bytes = public_key.0.value().to_vec();
                Builder::new(Codec::Bls12381G1PubShare)
                    .with_comment(&self.mk.comment)
                    .with_key_bytes(&key_bytes)
                    .with_threshold(threshold)
                    .with_limit(limit)
                    .with_identifier(identifier)
                    .try_build()
            }
            Codec::Bls12381G2Priv => {
                let bytes: [u8; SECRET_KEY_BYTES] = secret_bytes.as_slice()[..SECRET_KEY_BYTES]
                    .try_into()
                    .map_err(|_| {
                        ConversionsError::SecretKeyFailure(
                            "failed to get secret key bytes".to_string(),
                        )
                    })?;
                let secret_key: SecretKey<Bls12381G2Impl> = {
                    let sk = Option::from(SecretKey::from_be_bytes(&bytes));
                    sk.ok_or(ConversionsError::SecretKeyFailure(
                        "failed to create secret key".to_string(),
                    ))?
                };
                // get the public key and build a Multikey out of it
                let public_key = secret_key.public_key();
                let key_bytes = public_key.0.to_bytes();
                Builder::new(Codec::Bls12381G2Pub)
                    .with_comment(&self.mk.comment)
                    .with_key_bytes(&key_bytes)
                    .try_build()
            }
            Codec::Bls12381G2PrivShare => {
                let av = self.mk.threshold_attr_view()?;
                let threshold = av.threshold()?;
                let limit = av.limit()?;
                let identifier = av.identifier()?;

                let secret_key: SecretKeyShare<Bls12381G2Impl> = SecretKeyShare(
                    Share::with_identifier_and_value(identifier, secret_bytes.as_slice()),
                );

                // get the public key and build a Multikey out of it
                let public_key = secret_key
                    .public_key()
                    .map_err(|e| ConversionsError::PublicKeyFailure(e.to_string()))?;
                let key_bytes = public_key.0.value().to_vec();
                Builder::new(Codec::Bls12381G1PubShare)
                    .with_comment(&self.mk.comment)
                    .with_key_bytes(&key_bytes)
                    .with_threshold(threshold)
                    .with_limit(limit)
                    .with_identifier(identifier)
                    .try_build()
            }
            _ => Err(ConversionsError::UnsupportedCodec(self.mk.codec).into()),
        }
    }

    /// try to convert a Multikey to an ssh_key::PublicKey
    fn to_ssh_public_key(&self) -> Result<ssh_key::PublicKey, Error> {
        let mut pk = self.mk.clone();
        if self.is_secret_key() {
            pk = self.to_public_key()?;
        }

        let key_bytes = {
            let kd = pk.key_data_view()?;
            let key_bytes = kd.key_bytes()?;
            key_bytes
        };

        let mut buff: Vec<u8> = Vec::new();
        key_bytes
            .encode(&mut buff)
            .map_err(|e| ConversionsError::SshEncoding(e))?;
        let opaque_key_bytes = ssh_key::public::OpaquePublicKeyBytes::decode(&mut buff.as_slice())
            .map_err(|e| ConversionsError::SshKey(e))?;

        let name = match self.mk.codec {
            Codec::Bls12381G1Priv => ALGORITHM_NAME_G1,
            Codec::Bls12381G1PrivShare => ALGORITHM_NAME_G1_SHARE,
            Codec::Bls12381G2Priv => ALGORITHM_NAME_G2,
            Codec::Bls12381G2PrivShare => ALGORITHM_NAME_G2_SHARE,
            _ => return Err(ConversionsError::UnsupportedCodec(self.mk.codec).into()),
        };

        Ok(ssh_key::PublicKey::new(
            ssh_key::public::KeyData::Other(ssh_key::public::OpaquePublicKey {
                algorithm: ssh_key::Algorithm::Other(
                    ssh_key::AlgorithmName::new(name)
                        .map_err(|e| ConversionsError::SshKeyLabel(e))?,
                ),
                key: opaque_key_bytes,
            }),
            pk.comment,
        ))
    }

    /// try to convert a Multikey to an ssh_key::PrivateKey
    fn to_ssh_private_key(&self) -> Result<ssh_key::PrivateKey, Error> {
        let secret_bytes = {
            let kd = self.mk.key_data_view()?;
            let secret_bytes = kd.secret_bytes()?;
            secret_bytes
        };

        let mut buf: Vec<u8> = Vec::new();
        secret_bytes
            .encode(&mut buf)
            .map_err(|e| ConversionsError::SshEncoding(e))?;
        let opaque_private_key_bytes =
            ssh_key::private::OpaquePrivateKeyBytes::decode(&mut buf.as_slice())
                .map_err(|e| ConversionsError::SshKey(e))?;

        let pk = self.to_public_key()?;
        let key_bytes = {
            let kd = pk.key_data_view()?;
            let key_bytes = kd.key_bytes()?;
            key_bytes
        };

        buf.clear();
        key_bytes
            .encode(&mut buf)
            .map_err(|e| ConversionsError::SshEncoding(e))?;
        let opaque_public_key_bytes =
            ssh_key::public::OpaquePublicKeyBytes::decode(&mut buf.as_slice())
                .map_err(|e| ConversionsError::SshKey(e))?;

        let name = match self.mk.codec {
            Codec::Bls12381G1Priv => ALGORITHM_NAME_G1,
            Codec::Bls12381G1PrivShare => ALGORITHM_NAME_G1_SHARE,
            Codec::Bls12381G2Priv => ALGORITHM_NAME_G2,
            Codec::Bls12381G2PrivShare => ALGORITHM_NAME_G2_SHARE,
            _ => return Err(ConversionsError::UnsupportedCodec(self.mk.codec).into()),
        };

        Ok(ssh_key::PrivateKey::new(
            ssh_key::private::KeypairData::Other(ssh_key::private::OpaqueKeypair {
                public: ssh_key::public::OpaquePublicKey {
                    algorithm: ssh_key::Algorithm::Other(
                        ssh_key::AlgorithmName::new(name)
                            .map_err(|e| ConversionsError::SshKeyLabel(e))?,
                    ),
                    key: opaque_public_key_bytes,
                },
                private: opaque_private_key_bytes,
            }),
            self.mk.comment.clone(),
        )
        .map_err(|e| ConversionsError::SshKey(e))?)
    }
}

impl<'a> SignView for View<'a> {
    /// try to create a Multisig by siging the passed-in data with the Multikey
    fn sign(&self, msg: &[u8], combined: bool, scheme: Option<u8>) -> Result<Multisig, Error> {
        let scheme = scheme.ok_or(SignError::MissingScheme)?;

        let attr = self.mk.attr_view()?;
        if !attr.is_secret_key() {
            return Err(SignError::NotSigningKey.into());
        }

        // get the secret key bytes
        let secret_bytes = {
            let kd = self.mk.key_data_view()?;
            let secret_bytes = kd.secret_bytes()?;
            secret_bytes
        };

        // get the signature scheme
        let sig_scheme: SignatureSchemes =
            multisig::sig_views::bls12381::SchemeTypeId::try_from(scheme)?.into();

        match self.mk.codec {
            Codec::Bls12381G1Priv => {
                let bytes: [u8; SECRET_KEY_BYTES] = secret_bytes.as_slice()[..SECRET_KEY_BYTES]
                    .try_into()
                    .map_err(|_| {
                        ConversionsError::SecretKeyFailure(
                            "failed to get secret key bytes".to_string(),
                        )
                    })?;
                let secret_key: SecretKey<Bls12381G1Impl> = {
                    let sk = Option::from(SecretKey::from_be_bytes(&bytes));
                    sk.ok_or(ConversionsError::SecretKeyFailure(
                        "failed to create secret key".to_string(),
                    ))?
                };
                // sign the data
                let signature = secret_key
                    .sign(sig_scheme, msg)
                    .map_err(|e| SignError::SigningFailed(e.to_string()))?;

                let mut ms = ms::Builder::new_from_bls_signature(&signature)?;
                if combined {
                    ms = ms.with_message_bytes(&msg);
                }
                Ok(ms.try_build()?)
            }
            Codec::Bls12381G1PrivShare => {
                let av = self.mk.threshold_attr_view()?;
                let threshold = av.threshold()?;
                let limit = av.limit()?;
                let identifier = av.identifier()?;

                let secret_key: SecretKeyShare<Bls12381G1Impl> = SecretKeyShare(
                    Share::with_identifier_and_value(identifier, secret_bytes.as_slice()),
                );

                // sign the data
                let signature = secret_key
                    .sign(sig_scheme, msg)
                    .map_err(|e| SignError::SigningFailed(e.to_string()))?;

                let mut ms =
                    ms::Builder::new_from_bls_signature_share(threshold, limit, &signature)?;
                if combined {
                    ms = ms.with_message_bytes(&msg);
                }
                Ok(ms.try_build()?)
            }
            Codec::Bls12381G2Priv => {
                let bytes: [u8; SECRET_KEY_BYTES] = secret_bytes.as_slice()[..SECRET_KEY_BYTES]
                    .try_into()
                    .map_err(|_| {
                        ConversionsError::SecretKeyFailure(
                            "failed to get secret key bytes".to_string(),
                        )
                    })?;
                let secret_key: SecretKey<Bls12381G2Impl> = {
                    let sk = Option::from(SecretKey::from_be_bytes(&bytes));
                    sk.ok_or(ConversionsError::SecretKeyFailure(
                        "failed to create secret key".to_string(),
                    ))?
                };
                // sign the data
                let signature = secret_key
                    .sign(sig_scheme, msg)
                    .map_err(|e| SignError::SigningFailed(e.to_string()))?;

                let mut ms = ms::Builder::new_from_bls_signature(&signature)?;
                if combined {
                    ms = ms.with_message_bytes(&msg);
                }
                Ok(ms.try_build()?)
            }
            Codec::Bls12381G2PrivShare => {
                let av = self.mk.threshold_attr_view()?;
                let threshold = av.threshold()?;
                let limit = av.limit()?;
                let identifier = av.identifier()?;

                let secret_key: SecretKeyShare<Bls12381G2Impl> = SecretKeyShare(
                    Share::with_identifier_and_value(identifier, secret_bytes.as_slice()),
                );

                // sign the data
                let signature = secret_key
                    .sign(sig_scheme, msg)
                    .map_err(|e| SignError::SigningFailed(e.to_string()))?;
                let mut ms =
                    ms::Builder::new_from_bls_signature_share(threshold, limit, &signature)?;
                if combined {
                    ms = ms.with_message_bytes(&msg);
                }
                Ok(ms.try_build()?)
            }
            _ => Err(ConversionsError::UnsupportedCodec(self.mk.codec).into()),
        }
    }
}

impl<'a> VerifyView for View<'a> {
    /// try to verify a Multisig using the Multikey
    fn verify(&self, multisig: &Multisig, msg: Option<&[u8]>) -> Result<(), Error> {
        let attr = self.mk.attr_view()?;
        let pubmk = if attr.is_secret_key() {
            let kc = self.mk.key_conv_view()?;
            let mk = kc.to_public_key()?;
            mk
        } else {
            self.mk.clone()
        };

        // get the secret key bytes
        let key_bytes = {
            let kd = pubmk.key_data_view()?;
            let key_bytes = kd.key_bytes()?;
            key_bytes.to_vec()
        };

        // get the signature scheme
        let av = multisig.attr_view()?;
        let sig_scheme = SchemeTypeId::try_from(av.scheme()?)?;

        match pubmk.codec {
            Codec::Bls12381G1Pub => {
                // build a blsful::PublicKey from the bytes
                let public_key = PublicKey::try_from(&key_bytes)
                    .map_err(|e| ConversionsError::PublicKeyFailure(e.to_string()))?;

                // get the signature data
                let sv = multisig.sig_data_view()?;
                let sig = sv.sig_bytes().map_err(|_| VerifyError::MissingSignature)?;

                let group_encoding: G1Projective = {
                    let bytes: [u8; G1_PUBLIC_KEY_BYTES] = sig.as_slice()[..G1_PUBLIC_KEY_BYTES]
                        .try_into()
                        .map_err(|e: TryFromSliceError| VerifyError::BadSignature(e.to_string()))?;
                    let res = Option::from(G1Projective::from_compressed(&bytes));
                    res.ok_or(VerifyError::BadSignature(
                        "failed to deserialize group encoding".to_string(),
                    ))?
                };

                let sig = match sig_scheme {
                    SchemeTypeId::Basic => Signature::<Bls12381G1Impl>::Basic(group_encoding),
                    SchemeTypeId::MessageAugmentation => {
                        Signature::<Bls12381G1Impl>::MessageAugmentation(group_encoding)
                    }
                    SchemeTypeId::ProofOfPossession => {
                        Signature::<Bls12381G1Impl>::ProofOfPossession(group_encoding)
                    }
                };

                // get the message
                let msg = if let Some(msg) = msg {
                    msg
                } else if multisig.message.len() > 0 {
                    multisig.message.as_slice()
                } else {
                    return Err(VerifyError::MissingMessage.into());
                };

                Ok(sig
                    .verify(&public_key, msg)
                    .map_err(|e| VerifyError::BadSignature(e.to_string()))?)
            }
            Codec::Bls12381G1PubShare => {
                // build a blsful::PublicKeyShare from the bytes
                let public_key = PublicKeyShare::try_from(&key_bytes)
                    .map_err(|e| ConversionsError::PublicKeyFailure(e.to_string()))?;

                // get the share identifier
                let av = multisig.threshold_attr_view()?;
                let identifier = av.identifier()?;

                // get the signature data
                let sv = multisig.sig_data_view()?;
                let value = sv.sig_bytes().map_err(|_| VerifyError::MissingSignature)?;

                let share = Share::with_identifier_and_value(identifier, &value);

                let sig = match sig_scheme {
                    SchemeTypeId::Basic => SignatureShare::<Bls12381G1Impl>::Basic(share),
                    SchemeTypeId::MessageAugmentation => {
                        SignatureShare::<Bls12381G1Impl>::MessageAugmentation(share)
                    }
                    SchemeTypeId::ProofOfPossession => {
                        SignatureShare::<Bls12381G1Impl>::ProofOfPossession(share)
                    }
                };

                // get the message
                let msg = if let Some(msg) = msg {
                    msg
                } else if multisig.message.len() > 0 {
                    multisig.message.as_slice()
                } else {
                    return Err(VerifyError::MissingMessage.into());
                };

                Ok(sig
                    .verify(&public_key, msg)
                    .map_err(|e| VerifyError::BadSignature(e.to_string()))?)
            }
            Codec::Bls12381G2Pub => {
                // build a blsful::PublicKey from the bytes
                let public_key = PublicKey::try_from(&key_bytes)
                    .map_err(|e| ConversionsError::PublicKeyFailure(e.to_string()))?;

                // get the signature data
                let sv = multisig.sig_data_view()?;
                let sig = sv.sig_bytes().map_err(|_| VerifyError::MissingSignature)?;

                let group_encoding: G2Projective = {
                    let bytes: [u8; G2_PUBLIC_KEY_BYTES] = sig.as_slice()[..G2_PUBLIC_KEY_BYTES]
                        .try_into()
                        .map_err(|e: TryFromSliceError| VerifyError::BadSignature(e.to_string()))?;
                    let res = Option::from(G2Projective::from_compressed(&bytes));
                    res.ok_or(VerifyError::BadSignature(
                        "failed to deserialize group encoding".to_string(),
                    ))?
                };

                let sig = match sig_scheme {
                    SchemeTypeId::Basic => Signature::<Bls12381G2Impl>::Basic(group_encoding),
                    SchemeTypeId::MessageAugmentation => {
                        Signature::<Bls12381G2Impl>::MessageAugmentation(group_encoding)
                    }
                    SchemeTypeId::ProofOfPossession => {
                        Signature::<Bls12381G2Impl>::ProofOfPossession(group_encoding)
                    }
                };

                // get the message
                let msg = if let Some(msg) = msg {
                    msg
                } else if multisig.message.len() > 0 {
                    multisig.message.as_slice()
                } else {
                    return Err(VerifyError::MissingMessage.into());
                };

                Ok(sig
                    .verify(&public_key, msg)
                    .map_err(|e| VerifyError::BadSignature(e.to_string()))?)
            }
            Codec::Bls12381G2PubShare => {
                // build a blsful::PublicKeyShare from the bytes
                let public_key = PublicKeyShare::try_from(&key_bytes)
                    .map_err(|e| ConversionsError::PublicKeyFailure(e.to_string()))?;

                // get the share identifier
                let av = multisig.threshold_attr_view()?;
                let identifier = av.identifier()?;

                // get the signature data
                let sv = multisig.sig_data_view()?;
                let value = sv.sig_bytes().map_err(|_| VerifyError::MissingSignature)?;

                let share = Share::with_identifier_and_value(identifier, &value);

                let sig = match sig_scheme {
                    SchemeTypeId::Basic => SignatureShare::<Bls12381G1Impl>::Basic(share),
                    SchemeTypeId::MessageAugmentation => {
                        SignatureShare::<Bls12381G1Impl>::MessageAugmentation(share)
                    }
                    SchemeTypeId::ProofOfPossession => {
                        SignatureShare::<Bls12381G1Impl>::ProofOfPossession(share)
                    }
                };

                // get the message
                let msg = if let Some(msg) = msg {
                    msg
                } else if multisig.message.len() > 0 {
                    multisig.message.as_slice()
                } else {
                    return Err(VerifyError::MissingMessage.into());
                };

                Ok(sig
                    .verify(&public_key, msg)
                    .map_err(|e| VerifyError::BadSignature(e.to_string()))?)
            }
            _ => Err(ConversionsError::UnsupportedCodec(self.mk.codec).into()),
        }
    }
}
