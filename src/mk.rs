use crate::{
    error::{AttributesError, CipherError, ConversionsError, KdfError},
    key_views::{bcrypt, bls12381, chacha20, ed25519, secp256k1},
    AttrId, AttrView, CipherAttrView, CipherView, Error, FingerprintView, KdfAttrView, KdfView,
    KeyConvView, KeyDataView, KeyViews, SignView, ThresholdAttrView, VerifyView,
};

use multibase::Base;
use multicodec::Codec;
use multitrait::TryDecodeFrom;
use multiutil::{BaseEncoded, CodecInfo, EncodingInfo, Varbytes, Varuint};
use rand::{CryptoRng, RngCore};
use ssh_key::{
    private::{EcdsaKeypair, Ed25519Keypair, KeypairData},
    public::{EcdsaPublicKey, KeyData},
    EcdsaCurve, PrivateKey, PublicKey,
};
use std::{collections::BTreeMap, fmt};
use zeroize::Zeroizing;

/// the multicodec sigil for multikey
pub const SIGIL: Codec = Codec::Multikey;

/// A base encoded Multikey structure
pub type EncodedMultikey = BaseEncoded<Multikey>;

/// The Multikey attributes type
pub type Attributes = BTreeMap<AttrId, Zeroizing<Vec<u8>>>;

/// The main multikey structure
#[derive(Clone, Default, Eq, PartialEq)]
pub struct Multikey {
    /// key codec
    pub(crate) codec: Codec,
    /// the comment for the key
    pub comment: String,
    /// codec-specific attributes, sorted by key
    pub attributes: Attributes,
}

impl CodecInfo for Multikey {
    /// Return that we are a Multikey object
    fn preferred_codec() -> Codec {
        SIGIL
    }

    /// Return the key coded for the Multikey
    fn codec(&self) -> Codec {
        self.codec
    }
}

impl EncodingInfo for Multikey {
    /// Return the preferred string encoding
    fn preferred_encoding() -> Base {
        Base::Base16Lower
    }

    /// Same
    fn encoding(&self) -> Base {
        Self::preferred_encoding()
    }
}

impl Into<Vec<u8>> for Multikey {
    fn into(self) -> Vec<u8> {
        let mut v = Vec::default();
        // add in the sigil
        v.append(&mut SIGIL.into());
        // add in the key codec
        v.append(&mut self.codec.clone().into());
        // add in the comment
        v.append(&mut Varbytes(self.comment.as_bytes().to_vec()).into());
        // add in the number of codec-specific attributes
        v.append(&mut Varuint(self.attributes.len()).into());
        // add in the codec-specific attributes
        self.attributes.iter().for_each(|(id, attr)| {
            v.append(&mut (*id).into());
            v.append(&mut Varbytes(attr.to_vec()).into());
        });
        v
    }
}

impl<'a> TryFrom<&'a [u8]> for Multikey {
    type Error = Error;

    fn try_from(s: &'a [u8]) -> Result<Self, Self::Error> {
        let (mk, _) = Self::try_decode_from(s)?;
        Ok(mk)
    }
}

impl<'a> TryDecodeFrom<'a> for Multikey {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        // decode the sigil
        let (sigil, ptr) = Codec::try_decode_from(bytes)?;
        if sigil != SIGIL {
            return Err(Error::MissingSigil);
        }
        // decode the key codec
        let (codec, ptr) = Codec::try_decode_from(ptr)?;
        // decode the comment
        let (comment, ptr) = Varbytes::try_decode_from(ptr)?;
        let comment = String::from_utf8(comment.to_inner())?;
        // decode the number of codec-specific attributes
        let (num_attr, ptr) = Varuint::<usize>::try_decode_from(ptr)?;
        // decode the codec-specific values
        let (attributes, ptr) = match *num_attr {
            0 => (Attributes::default(), ptr),
            _ => {
                let mut attributes = Attributes::new();
                let mut p = ptr;
                for _ in 0..*num_attr {
                    let (id, ptr) = AttrId::try_decode_from(p)?;
                    let (attr, ptr) = Varbytes::try_decode_from(ptr)?;
                    if attributes.insert(id, (*attr).clone().into()).is_some() {
                        return Err(Error::DuplicateAttribute(id.code()));
                    }
                    p = ptr;
                }
                (attributes, p)
            }
        };
        Ok((
            Self {
                codec,
                comment,
                attributes,
            },
            ptr,
        ))
    }
}

impl fmt::Debug for Multikey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // get an attributes view on the key
        let attr = self.attr_view().map_err(|_| fmt::Error)?;

        write!(
            f,
            "{:?} - {:?} - Encrypted: {}",
            SIGIL,
            self.codec(),
            if attr.is_encrypted() { "true" } else { "false" }
        )
    }
}

impl KeyViews for Multikey {
    /// Provide a read-only view of the basic attributes in the viewed Multikey
    fn attr_view<'a>(&'a self) -> Result<Box<dyn AttrView + 'a>, Error> {
        match self.codec {
            Codec::Bls12381G1PrivShare
            | Codec::Bls12381G1Priv
            | Codec::Bls12381G1Pub
            | Codec::Bls12381G2PrivShare
            | Codec::Bls12381G2Priv
            | Codec::Bls12381G2Pub => Ok(Box::new(bls12381::View::try_from(self)?)),
            Codec::Ed25519Pub | Codec::Ed25519Priv => Ok(Box::new(ed25519::View::try_from(self)?)),
            Codec::Secp256K1Pub | Codec::Secp256K1Priv => {
                Ok(Box::new(secp256k1::View::try_from(self)?))
            }
            Codec::Chacha20Poly1305 => Ok(Box::new(chacha20::View::try_from(self)?)),
            _ => Err(AttributesError::UnsupportedCodec(self.codec).into()),
        }
    }

    /// Provide a read-only view of the cipher attributes in the viewed Multikey
    fn cipher_attr_view<'a>(&'a self) -> Result<Box<dyn CipherAttrView + 'a>, Error> {
        let codec = if let Some(bytes) = self.attributes.get(&AttrId::CipherCodec) {
            Codec::try_from(bytes.as_slice())?
        } else {
            self.codec
        };
        match codec {
            Codec::Chacha20Poly1305 => Ok(Box::new(chacha20::View::try_from(self)?)),
            _ => Err(CipherError::UnsupportedCodec(self.codec).into()),
        }
    }

    /// Provide a read-only view of the kdf attributes in the viewed Multikey
    fn kdf_attr_view<'a>(&'a self) -> Result<Box<dyn KdfAttrView + 'a>, Error> {
        let codec = if let Some(bytes) = self.attributes.get(&AttrId::KdfCodec) {
            Codec::try_from(bytes.as_slice())?
        } else {
            self.codec
        };
        match codec {
            Codec::BcryptPbkdf => Ok(Box::new(bcrypt::View::try_from(self)?)),
            _ => Err(KdfError::UnsupportedCodec(self.codec).into()),
        }
    }

    /// Provide a read-only view of the threshold attributes in the viewed Multikey
    fn threshold_attr_view<'a>(&'a self) -> Result<Box<dyn ThresholdAttrView + 'a>, Error> {
        match self.codec {
            Codec::Bls12381G1PrivShare
            | Codec::Bls12381G1Priv
            | Codec::Bls12381G1Pub
            | Codec::Bls12381G2PrivShare
            | Codec::Bls12381G2Priv
            | Codec::Bls12381G2Pub => Ok(Box::new(bls12381::View::try_from(self)?)),
            _ => Err(ConversionsError::UnsupportedCodec(self.codec).into()),
        }
    }

    /// Provide a read-only view to key data in the viewed Multikey
    fn key_data_view<'a>(&'a self) -> Result<Box<dyn KeyDataView + 'a>, Error> {
        match self.codec {
            Codec::Bls12381G1PrivShare
            | Codec::Bls12381G1Priv
            | Codec::Bls12381G1Pub
            | Codec::Bls12381G2PrivShare
            | Codec::Bls12381G2Priv
            | Codec::Bls12381G2Pub => Ok(Box::new(bls12381::View::try_from(self)?)),
            Codec::Ed25519Pub | Codec::Ed25519Priv => Ok(Box::new(ed25519::View::try_from(self)?)),
            Codec::Secp256K1Pub | Codec::Secp256K1Priv => {
                Ok(Box::new(secp256k1::View::try_from(self)?))
            }
            Codec::Chacha20Poly1305 => Ok(Box::new(chacha20::View::try_from(self)?)),
            _ => Err(ConversionsError::UnsupportedCodec(self.codec).into()),
        }
    }

    /// Provide an interface to do encryption/decryption of the viewed Multikey
    fn cipher_view<'a>(&'a self, cipher: &'a Multikey) -> Result<Box<dyn CipherView + 'a>, Error> {
        match cipher.codec {
            Codec::Chacha20Poly1305 => Ok(Box::new(chacha20::View::new(self, cipher))),
            _ => Err(CipherError::UnsupportedCodec(self.codec).into()),
        }
    }

    /// Provide an interface to do key conversions from the viewe Multikey
    fn fingerprint_view<'a>(&'a self) -> Result<Box<dyn FingerprintView + 'a>, Error> {
        match self.codec {
            Codec::Bls12381G1PrivShare
            | Codec::Bls12381G1Priv
            | Codec::Bls12381G1Pub
            | Codec::Bls12381G2PrivShare
            | Codec::Bls12381G2Priv
            | Codec::Bls12381G2Pub => Ok(Box::new(bls12381::View::try_from(self)?)),
            Codec::Ed25519Pub | Codec::Ed25519Priv => Ok(Box::new(ed25519::View::try_from(self)?)),
            Codec::Secp256K1Pub | Codec::Secp256K1Priv => {
                Ok(Box::new(secp256k1::View::try_from(self)?))
            }
            Codec::Chacha20Poly1305 => Ok(Box::new(chacha20::View::try_from(self)?)),
            _ => Err(ConversionsError::UnsupportedCodec(self.codec).into()),
        }
    }

    /// Provide an interface to do kdf operations from the viewed Multikey
    fn kdf_view<'a>(&'a self, kdf: &'a Multikey) -> Result<Box<dyn KdfView + 'a>, Error> {
        match kdf.codec {
            Codec::BcryptPbkdf => Ok(Box::new(bcrypt::View::new(self, kdf))),
            _ => Err(KdfError::UnsupportedCodec(self.codec).into()),
        }
    }

    /// Provide an interface to do key conversions from the viewe Multikey
    fn key_conv_view<'a>(&'a self) -> Result<Box<dyn KeyConvView + 'a>, Error> {
        match self.codec {
            Codec::Bls12381G1PrivShare
            | Codec::Bls12381G1Priv
            | Codec::Bls12381G1Pub
            | Codec::Bls12381G2PrivShare
            | Codec::Bls12381G2Priv
            | Codec::Bls12381G2Pub => Ok(Box::new(bls12381::View::try_from(self)?)),
            Codec::Ed25519Pub | Codec::Ed25519Priv => Ok(Box::new(ed25519::View::try_from(self)?)),
            Codec::Secp256K1Pub | Codec::Secp256K1Priv => {
                Ok(Box::new(secp256k1::View::try_from(self)?))
            }
            _ => Err(ConversionsError::UnsupportedCodec(self.codec).into()),
        }
    }

    /// Provide an interface to sign a message and return a Multisig
    fn sign_view<'a>(&'a self) -> Result<Box<dyn SignView + 'a>, Error> {
        match self.codec {
            Codec::Bls12381G1PrivShare
            | Codec::Bls12381G1Priv
            | Codec::Bls12381G1Pub
            | Codec::Bls12381G2PrivShare
            | Codec::Bls12381G2Priv
            | Codec::Bls12381G2Pub => Ok(Box::new(bls12381::View::try_from(self)?)),
            Codec::Ed25519Pub | Codec::Ed25519Priv => Ok(Box::new(ed25519::View::try_from(self)?)),
            Codec::Secp256K1Pub | Codec::Secp256K1Priv => {
                Ok(Box::new(secp256k1::View::try_from(self)?))
            }
            _ => Err(ConversionsError::UnsupportedCodec(self.codec).into()),
        }
    }

    /// Provide an interface to verify a Multisig and optional message
    fn verify_view<'a>(&'a self) -> Result<Box<dyn VerifyView + 'a>, Error> {
        match self.codec {
            Codec::Bls12381G1PrivShare
            | Codec::Bls12381G1Priv
            | Codec::Bls12381G1Pub
            | Codec::Bls12381G2PrivShare
            | Codec::Bls12381G2Priv
            | Codec::Bls12381G2Pub => Ok(Box::new(bls12381::View::try_from(self)?)),
            Codec::Ed25519Pub | Codec::Ed25519Priv => Ok(Box::new(ed25519::View::try_from(self)?)),
            Codec::Secp256K1Pub | Codec::Secp256K1Priv => {
                Ok(Box::new(secp256k1::View::try_from(self)?))
            }
            _ => Err(ConversionsError::UnsupportedCodec(self.codec).into()),
        }
    }
}

/// Multikey builder constructs private keys only. If you need a public key you
/// must first generate a priate key and then get the public key from that.
#[derive(Clone, Default)]
pub struct Builder {
    codec: Codec,
    comment: Option<String>,
    base_encoding: Option<Base>,
    attributes: Option<Attributes>,
}

impl Builder {
    /// create a new multikey with the given codec
    pub fn new(codec: Codec) -> Self {
        Builder {
            codec,
            ..Default::default()
        }
    }

    /// new builder from random bytes source
    pub fn new_from_random_bytes(
        codec: Codec,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Self, Error> {
        let key_bytes = match codec {
            Codec::Ed25519Priv => Ed25519Keypair::random(rng).private.to_bytes().to_vec(),
            Codec::P256Priv => EcdsaKeypair::random(rng, EcdsaCurve::NistP256)
                .map_err(|e| ConversionsError::SshKey(e))?
                .private_key_bytes()
                .to_vec(),
            Codec::P384Priv => EcdsaKeypair::random(rng, EcdsaCurve::NistP384)
                .map_err(|e| ConversionsError::SshKey(e))?
                .private_key_bytes()
                .to_vec(),
            Codec::P521Priv => EcdsaKeypair::random(rng, EcdsaCurve::NistP521)
                .map_err(|e| ConversionsError::SshKey(e))?
                .private_key_bytes()
                .to_vec(),
            Codec::Secp256K1Priv => k256::SecretKey::random(rng).to_bytes().to_vec(),
            Codec::Bls12381G1Priv => blsful::Bls12381G1::new_secret_key()
                .to_be_bytes()
                .as_slice()
                .to_vec(),
            Codec::Bls12381G2Priv => blsful::Bls12381G2::new_secret_key()
                .to_be_bytes()
                .as_slice()
                .to_vec(),
            _ => return Err(ConversionsError::UnsupportedCodec(codec).into()),
        };
        let mut attributes = Attributes::new();
        attributes.insert(AttrId::KeyData, key_bytes.into());
        Ok(Builder {
            codec,
            attributes: Some(attributes),
            ..Default::default()
        })
    }

    /// new builder from ssh_key::PublicKey source
    pub fn new_from_ssh_public_key(sshkey: &PublicKey) -> Result<Self, Error> {
        use ssh_key::Algorithm::*;
        match sshkey.algorithm() {
            Ecdsa { curve } => {
                use EcdsaCurve::*;
                let (key_bytes, codec) = match curve {
                    NistP256 => {
                        if let KeyData::Ecdsa(EcdsaPublicKey::NistP256(point)) = sshkey.key_data() {
                            (point.as_bytes().to_vec(), Codec::P256Pub)
                        } else {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into());
                        }
                    }
                    NistP384 => {
                        if let KeyData::Ecdsa(EcdsaPublicKey::NistP384(point)) = sshkey.key_data() {
                            (point.as_bytes().to_vec(), Codec::P384Pub)
                        } else {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into());
                        }
                    }
                    NistP521 => {
                        if let KeyData::Ecdsa(EcdsaPublicKey::NistP521(point)) = sshkey.key_data() {
                            (point.as_bytes().to_vec(), Codec::P521Pub)
                        } else {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into());
                        }
                    }
                };
                let mut attributes = Attributes::new();
                attributes.insert(AttrId::KeyData, key_bytes.into());
                Ok(Builder {
                    codec,
                    comment: Some(sshkey.comment().to_string()),
                    attributes: Some(attributes),
                    base_encoding: None,
                })
            }
            Other(name) => match name.as_str() {
                secp256k1::ALGORITHM_NAME => {
                    let key_bytes = match sshkey.key_data() {
                        KeyData::Other(pk) => pk.key.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::Secp256K1Pub,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        base_encoding: None,
                    })
                }
                bls12381::ALGORITHM_NAME_G1 => {
                    let key_bytes = match sshkey.key_data() {
                        KeyData::Other(pk) => pk.key.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::Bls12381G1Pub,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        base_encoding: None,
                    })
                }
                bls12381::ALGORITHM_NAME_G1_SHARE => {
                    let key_bytes = match sshkey.key_data() {
                        KeyData::Other(pk) => pk.key.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::Bls12381G1PubShare,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        base_encoding: None,
                    })
                }
                bls12381::ALGORITHM_NAME_G2 => {
                    let key_bytes = match sshkey.key_data() {
                        KeyData::Other(pk) => pk.key.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::Bls12381G2Pub,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        base_encoding: None,
                    })
                }
                bls12381::ALGORITHM_NAME_G2_SHARE => {
                    let key_bytes = match sshkey.key_data() {
                        KeyData::Other(pk) => pk.key.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::Bls12381G1PubShare,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        base_encoding: None,
                    })
                }
                s => return Err(ConversionsError::UnsupportedAlgorithm(s.to_string()).into()),
            },
            Ed25519 => {
                let key_bytes = match sshkey.key_data() {
                    KeyData::Ed25519(e) => e.0.to_vec(),
                    _ => {
                        return Err(ConversionsError::UnsupportedAlgorithm(
                            sshkey.algorithm().to_string(),
                        )
                        .into())
                    }
                };
                let mut attributes = Attributes::new();
                attributes.insert(AttrId::KeyData, key_bytes.into());
                Ok(Builder {
                    codec: Codec::Ed25519Pub,
                    comment: Some(sshkey.comment().to_string()),
                    attributes: Some(attributes),
                    base_encoding: None,
                })
            }
            _ => Err(ConversionsError::UnsupportedAlgorithm(sshkey.algorithm().to_string()).into()),
        }
    }

    /// new builder from ssh_key::PrivateKey source
    pub fn new_from_ssh_private_key(sshkey: &PrivateKey) -> Result<Self, Error> {
        use ssh_key::Algorithm::*;
        match sshkey.algorithm() {
            Ecdsa { curve } => {
                use EcdsaCurve::*;
                let (key_bytes, codec) = match curve {
                    NistP256 => {
                        if let KeypairData::Ecdsa(EcdsaKeypair::NistP256 { private, .. }) =
                            sshkey.key_data()
                        {
                            (private.as_slice().to_vec(), Codec::P256Priv)
                        } else {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into());
                        }
                    }
                    NistP384 => {
                        if let KeypairData::Ecdsa(EcdsaKeypair::NistP384 { private, .. }) =
                            sshkey.key_data()
                        {
                            (private.as_slice().to_vec(), Codec::P384Priv)
                        } else {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into());
                        }
                    }
                    NistP521 => {
                        if let KeypairData::Ecdsa(EcdsaKeypair::NistP521 { private, .. }) =
                            sshkey.key_data()
                        {
                            (private.as_slice().to_vec(), Codec::P521Priv)
                        } else {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into());
                        }
                    }
                };
                let mut attributes = Attributes::new();
                attributes.insert(AttrId::KeyData, key_bytes.into());
                Ok(Builder {
                    codec,
                    comment: Some(sshkey.comment().to_string()),
                    attributes: Some(attributes),
                    base_encoding: None,
                })
            }
            Other(name) => match name.as_str() {
                secp256k1::ALGORITHM_NAME => {
                    let key_bytes = match sshkey.key_data() {
                        KeypairData::Other(kp) => kp.private.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::Secp256K1Priv,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        base_encoding: None,
                    })
                }
                bls12381::ALGORITHM_NAME_G1 => {
                    let key_bytes = match sshkey.key_data() {
                        KeypairData::Other(kp) => kp.private.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::Bls12381G1Priv,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        base_encoding: None,
                    })
                }
                bls12381::ALGORITHM_NAME_G1_SHARE => {
                    let key_bytes = match sshkey.key_data() {
                        KeypairData::Other(kp) => kp.private.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::Bls12381G1PrivShare,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        base_encoding: None,
                    })
                }
                bls12381::ALGORITHM_NAME_G2 => {
                    let key_bytes = match sshkey.key_data() {
                        KeypairData::Other(kp) => kp.private.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::Bls12381G2Priv,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        base_encoding: None,
                    })
                }
                bls12381::ALGORITHM_NAME_G2_SHARE => {
                    let key_bytes = match sshkey.key_data() {
                        KeypairData::Other(kp) => kp.private.as_ref().to_vec(),
                        _ => {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into())
                        }
                    };
                    let mut attributes = Attributes::new();
                    attributes.insert(AttrId::KeyData, key_bytes.into());
                    Ok(Builder {
                        codec: Codec::Bls12381G2PrivShare,
                        comment: Some(sshkey.comment().to_string()),
                        attributes: Some(attributes),
                        base_encoding: None,
                    })
                }
                s => return Err(ConversionsError::UnsupportedAlgorithm(s.to_string()).into()),
            },
            Ed25519 => {
                let key_bytes = match sshkey.key_data() {
                    KeypairData::Ed25519(e) => e.private.to_bytes().to_vec(),
                    _ => {
                        return Err(ConversionsError::UnsupportedAlgorithm(
                            sshkey.algorithm().to_string(),
                        )
                        .into())
                    }
                };
                let mut attributes = Attributes::new();
                attributes.insert(AttrId::KeyData, key_bytes.into());
                Ok(Builder {
                    codec: Codec::Ed25519Priv,
                    comment: Some(sshkey.comment().to_string()),
                    attributes: Some(attributes),
                    base_encoding: None,
                })
            }
            _ => Err(ConversionsError::UnsupportedAlgorithm(sshkey.algorithm().to_string()).into()),
        }
    }

    /// add an encoding
    pub fn with_base_encoding(mut self, base: Base) -> Self {
        self.base_encoding = Some(base);
        self
    }

    /// add a comment
    pub fn with_comment(mut self, comment: &str) -> Self {
        self.comment = Some(comment.to_string());
        self
    }

    fn with_attribute(mut self, attr: AttrId, data: &Vec<u8>) -> Self {
        let mut attributes = self.attributes.unwrap_or_default();
        attributes.insert(attr, data.clone().into());
        self.attributes = Some(attributes);
        self
    }

    /// add in the key bytes directly
    pub fn with_key_bytes(self, bytes: &impl AsRef<[u8]>) -> Self {
        self.with_attribute(AttrId::KeyData, &bytes.as_ref().to_vec())
    }

    /// add in the threshold value
    pub fn with_threshold(self, threshold: usize) -> Self {
        self.with_attribute(AttrId::Threshold, &Varuint(threshold).into())
    }

    /// add in the limit value
    pub fn with_limit(self, limit: usize) -> Self {
        self.with_attribute(AttrId::Limit, &Varuint(limit).into())
    }

    /// add in the share identifier value
    pub fn with_identifier(self, identifier: u8) -> Self {
        self.with_attribute(AttrId::ShareIdentifier, &Varuint(identifier).into())
    }

    /// build a base encoded multikey
    pub fn try_build_encoded(self) -> Result<EncodedMultikey, Error> {
        Ok(BaseEncoded::new(
            self.base_encoding
                .unwrap_or_else(|| Multikey::preferred_encoding()),
            self.try_build()?,
        ))
    }

    /// build a key using key bytes
    pub fn try_build(self) -> Result<Multikey, Error> {
        let codec = self.codec;
        let comment = self.comment.unwrap_or_default();
        let attributes = self.attributes.unwrap_or_default();
        Ok(Multikey {
            codec,
            comment,
            attributes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{cipher, kdf, key_views};

    #[test]
    fn test_ed25519_random() {
        let mut rng = rand::rngs::OsRng::default();
        let mk = Builder::new_from_random_bytes(Codec::Ed25519Priv, &mut rng)
            .unwrap()
            .with_comment("test key")
            .try_build()
            .unwrap();
        let v: Vec<u8> = mk.into();
        assert_eq!(47, v.len());
    }

    #[test]
    fn test_ed25519_encoded_random() {
        let mut rng = rand::rngs::OsRng::default();
        let mk = Builder::new_from_random_bytes(Codec::Ed25519Priv, &mut rng)
            .unwrap()
            .with_base_encoding(Base::Base58Btc)
            .with_comment("test key")
            .try_build_encoded()
            .unwrap();
        let s = mk.to_string();
        println!("ed25519: {}", s);
        assert_eq!(mk, EncodedMultikey::try_from(s.as_str()).unwrap());
    }

    #[test]
    fn test_secp256k1_random() {
        let mut rng = rand::rngs::OsRng::default();
        let mk = Builder::new_from_random_bytes(Codec::Secp256K1Priv, &mut rng)
            .unwrap()
            .with_comment("test key")
            .try_build()
            .unwrap();
        let v: Vec<u8> = mk.into();
        assert_eq!(47, v.len());
    }

    #[test]
    fn test_secp256k1_encoded_random() {
        let mut rng = rand::rngs::OsRng::default();
        let mk = Builder::new_from_random_bytes(Codec::Secp256K1Priv, &mut rng)
            .unwrap()
            .with_base_encoding(Base::Base58Btc)
            .with_comment("test key")
            .try_build_encoded()
            .unwrap();
        let s = mk.to_string();
        println!("secp256k1: {}", s);
        assert_eq!(mk, EncodedMultikey::try_from(s.as_str()).unwrap());
    }

    #[test]
    fn test_ed25519_random_public_ssh_key_roundtrip() {
        let mut rng = rand::rngs::OsRng::default();
        let mk = Builder::new_from_random_bytes(Codec::Ed25519Priv, &mut rng)
            .unwrap()
            .with_comment("test key")
            .try_build()
            .unwrap();
        let conv = mk.key_conv_view().unwrap();
        let pk = conv.to_public_key().unwrap();
        let ssh_key = conv.to_ssh_public_key().unwrap();
        let mk2 = Builder::new_from_ssh_public_key(&ssh_key)
            .unwrap()
            .try_build()
            .unwrap();
        assert_eq!(pk, mk2);
    }

    #[test]
    fn test_ed25519_random_private_ssh_key_roundtrip() {
        let mut rng = rand::rngs::OsRng::default();
        let mk = Builder::new_from_random_bytes(Codec::Ed25519Priv, &mut rng)
            .unwrap()
            .with_comment("test key")
            .try_build()
            .unwrap();
        let conv = mk.key_conv_view().unwrap();
        let ssh_key = conv.to_ssh_private_key().unwrap();
        let mk2 = Builder::new_from_ssh_private_key(&ssh_key)
            .unwrap()
            .try_build()
            .unwrap();
        assert_eq!(mk, mk2);
    }

    #[test]
    fn test_secp256k1_random_public_ssh_key_roundtrip() {
        let mut rng = rand::rngs::OsRng::default();
        let mk = Builder::new_from_random_bytes(Codec::Secp256K1Priv, &mut rng)
            .unwrap()
            .with_comment("test key")
            .try_build()
            .unwrap();
        let conv = mk.key_conv_view().unwrap();
        let pk = conv.to_public_key().unwrap();
        let ssh_key = conv.to_ssh_public_key().unwrap();
        let mk2 = Builder::new_from_ssh_public_key(&ssh_key)
            .unwrap()
            .try_build()
            .unwrap();
        assert_eq!(pk, mk2);
    }

    #[test]
    fn test_secp256k1_random_private_ssh_key_roundtrip() {
        let mut rng = rand::rngs::OsRng::default();
        let mk = Builder::new_from_random_bytes(Codec::Secp256K1Priv, &mut rng)
            .unwrap()
            .with_comment("test key")
            .try_build()
            .unwrap();
        let conv = mk.key_conv_view().unwrap();
        let ssh_key = conv.to_ssh_private_key().unwrap();
        let mk2 = Builder::new_from_ssh_private_key(&ssh_key)
            .unwrap()
            .try_build()
            .unwrap();
        assert_eq!(mk, mk2);
    }

    #[test]
    fn test_encryption_roundtrip() {
        let mut rng = rand::rngs::OsRng::default();
        let mk1 = Builder::new_from_random_bytes(Codec::Ed25519Priv, &mut rng)
            .unwrap()
            .with_comment("test key")
            .try_build()
            .unwrap();

        let attr = mk1.attr_view().unwrap();
        assert!(!attr.is_encrypted());
        assert!(!attr.is_public_key());
        assert!(attr.is_secret_key());
        let kd = mk1.key_data_view().unwrap();
        assert!(kd.key_bytes().is_ok());
        assert!(kd.secret_bytes().is_ok());

        let mk2 = {
            let kdfmk = kdf::Builder::new(Codec::BcryptPbkdf)
                .with_random_salt(key_views::bcrypt::SALT_LENGTH, &mut rng)
                .with_rounds(10)
                .try_build()
                .unwrap();
            let ciphermk = cipher::Builder::new(Codec::Chacha20Poly1305)
                .with_random_nonce(key_views::chacha20::NONCE_LENGTH, &mut rng)
                .try_build()
                .unwrap();
            // get the kdf view on the cipher multikey so we can generate a
            // new cipher multikey with the same parameters and the generated key
            let kdf = ciphermk.kdf_view(&kdfmk).unwrap();
            // derive a key from the passphrase and add it to the cipher multikey
            let ciphermk = kdf
                .derive_key(b"for great justice, move every zig!")
                .unwrap();
            // get the cipher view on the unencrypted ed25519 secret key so
            // that we can create a new ed25519 secret key with an encrypted
            // key and the kdf and cipher attributes and data
            let cipher = mk1.cipher_view(&ciphermk).unwrap();
            // encrypt the multikey using the cipher
            let mk = cipher.encrypt().unwrap();
            mk
        };

        let attr = mk2.attr_view().unwrap();
        assert_eq!(true, attr.is_encrypted());
        assert_eq!(false, attr.is_public_key());
        assert_eq!(true, attr.is_secret_key());
        let kd = mk2.key_data_view().unwrap();
        assert!(kd.key_bytes().is_ok());
        assert!(kd.secret_bytes().is_err()); // encrypted key

        let mk3 = {
            let kdfmk = kdf::Builder::default()
                .try_from_multikey(&mk2)
                .unwrap()
                .try_build()
                .unwrap();
            let ciphermk = cipher::Builder::default()
                .try_from_multikey(&mk2)
                .unwrap()
                .try_build()
                .unwrap();
            // get the kdf view
            let kdf = ciphermk.kdf_view(&kdfmk).unwrap();
            // derive a key from the passphrase and add it to the cipher multikey
            let ciphermk = kdf
                .derive_key(b"for great justice, move every zig!")
                .unwrap();
            // get the cipher view
            let cipher = mk2.cipher_view(&ciphermk).unwrap();
            // decrypt the multikey using the cipher
            let mk = cipher.decrypt().unwrap();
            mk
        };

        let attr = mk3.attr_view().unwrap();
        assert_eq!(false, attr.is_encrypted());
        assert_eq!(false, attr.is_public_key());
        assert_eq!(true, attr.is_secret_key());
        let kd = mk3.key_data_view().unwrap();
        assert!(kd.key_bytes().is_ok());
        assert!(kd.secret_bytes().is_ok());

        // ensure the round trip worked
        assert_eq!(mk1, mk3);
    }

    #[test]
    fn test_ed25519_signing_detached_roundtrip() {
        let mut rng = rand::rngs::OsRng::default();
        let mk = Builder::new_from_random_bytes(Codec::Ed25519Priv, &mut rng)
            .unwrap()
            .with_comment("test key")
            .try_build()
            .unwrap();

        let attr = mk.attr_view().unwrap();
        assert!(!attr.is_encrypted());
        assert!(!attr.is_public_key());
        assert!(attr.is_secret_key());
        let kd = mk.key_data_view().unwrap();
        assert!(kd.key_bytes().is_ok());
        assert!(kd.secret_bytes().is_ok());

        let msg = hex::decode("8bb78be51ac7cc98f44e38947ff8a128764ec039b89687a790dfa8444ba97682")
            .unwrap();

        let signmk = mk.sign_view().unwrap();
        let signature = signmk.sign(msg.as_slice(), false, None).unwrap();

        let verifymk = mk.verify_view().unwrap();
        assert!(verifymk.verify(&signature, Some(&msg)).is_ok());
    }

    #[test]
    fn test_ed25519_signing_merged_roundtrip() {
        let mut rng = rand::rngs::OsRng::default();
        let mk = Builder::new_from_random_bytes(Codec::Ed25519Priv, &mut rng)
            .unwrap()
            .with_comment("test key")
            .try_build()
            .unwrap();

        let attr = mk.attr_view().unwrap();
        assert!(!attr.is_encrypted());
        assert!(!attr.is_public_key());
        assert!(attr.is_secret_key());
        let kd = mk.key_data_view().unwrap();
        assert!(kd.key_bytes().is_ok());
        assert!(kd.secret_bytes().is_ok());

        let msg = hex::decode("8bb78be51ac7cc98f44e38947ff8a128764ec039b89687a790dfa8444ba97682")
            .unwrap();

        let signmk = mk.sign_view().unwrap();
        let signature = signmk.sign(msg.as_slice(), true, None).unwrap();

        // make sure the message is stored correctly in the signature
        assert_eq!(signature.message, msg);

        let verifymk = mk.verify_view().unwrap();
        assert!(verifymk.verify(&signature, None).is_ok());
    }

    #[test]
    fn test_secp256k1_signing_detached_roundtrip() {
        let mut rng = rand::rngs::OsRng::default();
        let mk = Builder::new_from_random_bytes(Codec::Secp256K1Priv, &mut rng)
            .unwrap()
            .with_comment("test key")
            .try_build()
            .unwrap();

        let attr = mk.attr_view().unwrap();
        assert!(!attr.is_encrypted());
        assert!(!attr.is_public_key());
        assert!(attr.is_secret_key());
        let kd = mk.key_data_view().unwrap();
        assert!(kd.key_bytes().is_ok());
        assert!(kd.secret_bytes().is_ok());

        let msg = hex::decode("8bb78be51ac7cc98f44e38947ff8a128764ec039b89687a790dfa8444ba97682")
            .unwrap();

        let signmk = mk.sign_view().unwrap();
        let signature = signmk.sign(msg.as_slice(), false, None).unwrap();

        let verifymk = mk.verify_view().unwrap();
        assert!(verifymk.verify(&signature, Some(&msg)).is_ok());
    }

    #[test]
    fn test_secp256k1_signing_merged_roundtrip() {
        let mut rng = rand::rngs::OsRng::default();
        let mk = Builder::new_from_random_bytes(Codec::Secp256K1Priv, &mut rng)
            .unwrap()
            .with_comment("test key")
            .try_build()
            .unwrap();

        let attr = mk.attr_view().unwrap();
        assert!(!attr.is_encrypted());
        assert!(!attr.is_public_key());
        assert!(attr.is_secret_key());
        let kd = mk.key_data_view().unwrap();
        assert!(kd.key_bytes().is_ok());
        assert!(kd.secret_bytes().is_ok());

        let msg = hex::decode("8bb78be51ac7cc98f44e38947ff8a128764ec039b89687a790dfa8444ba97682")
            .unwrap();

        let signmk = mk.sign_view().unwrap();
        let signature = signmk.sign(msg.as_slice(), true, None).unwrap();

        // make sure the message is stored correctly in the signature
        assert_eq!(signature.message, msg);

        let verifymk = mk.verify_view().unwrap();
        assert!(verifymk.verify(&signature, None).is_ok());
    }

    #[test]
    fn test_bls_signing_detached_roundtrip() {
        let mut rng = rand::rngs::OsRng::default();
        let mk = Builder::new_from_random_bytes(Codec::Bls12381G1Priv, &mut rng)
            .unwrap()
            .with_comment("test key")
            .try_build()
            .unwrap();

        let attr = mk.attr_view().unwrap();
        assert!(!attr.is_encrypted());
        assert!(!attr.is_public_key());
        assert!(attr.is_secret_key());
        let kd = mk.key_data_view().unwrap();
        assert!(kd.key_bytes().is_ok());
        assert!(kd.secret_bytes().is_ok());

        let msg = hex::decode("8bb78be51ac7cc98f44e38947ff8a128764ec039b89687a790dfa8444ba97682")
            .unwrap();

        let signmk = mk.sign_view().unwrap();
        let signature = signmk.sign(msg.as_slice(), false, Some(2_u8)).unwrap();

        let verifymk = mk.verify_view().unwrap();
        assert!(verifymk.verify(&signature, Some(&msg)).is_ok());
    }

    #[test]
    fn test_bls_signing_merged_roundtrip() {
        let mut rng = rand::rngs::OsRng::default();
        let mk = Builder::new_from_random_bytes(Codec::Bls12381G2Priv, &mut rng)
            .unwrap()
            .with_comment("test key")
            .try_build()
            .unwrap();

        let attr = mk.attr_view().unwrap();
        assert!(!attr.is_encrypted());
        assert!(!attr.is_public_key());
        assert!(attr.is_secret_key());
        let kd = mk.key_data_view().unwrap();
        assert!(kd.key_bytes().is_ok());
        assert!(kd.secret_bytes().is_ok());

        let msg = hex::decode("8bb78be51ac7cc98f44e38947ff8a128764ec039b89687a790dfa8444ba97682")
            .unwrap();

        let signmk = mk.sign_view().unwrap();
        let signature = signmk.sign(msg.as_slice(), true, Some(2_u8)).unwrap();

        // make sure the message is stored correctly in the signature
        assert_eq!(signature.message, msg);

        let verifymk = mk.verify_view().unwrap();
        assert!(verifymk.verify(&signature, None).is_ok());
    }

    #[test]
    fn test_from_ssh_pubkey() {
        let mut rng = rand::rngs::OsRng::default();
        let kp = ssh_key::private::KeypairData::Ed25519(ssh_key::private::Ed25519Keypair::random(
            &mut rng,
        ));
        let sk = ssh_key::private::PrivateKey::new(kp, "test key").unwrap();

        // build a multikey from the public key
        let mk = Builder::new_from_ssh_public_key(sk.public_key())
            .unwrap()
            .try_build()
            .unwrap();

        let attr = mk.attr_view().unwrap();
        assert_eq!(mk.codec, Codec::Ed25519Pub);
        assert_eq!(mk.comment, "test key".to_string());
        assert_eq!(false, attr.is_encrypted());
        assert_eq!(true, attr.is_public_key());
        assert_eq!(false, attr.is_secret_key());
        let kd = mk.key_data_view().unwrap();
        assert!(kd.key_bytes().is_ok());
        assert!(kd.secret_bytes().is_err()); // public key
    }

    #[test]
    fn test_from_ssh_privkey() {
        let mut rng = rand::rngs::OsRng::default();
        let kp = ssh_key::private::KeypairData::Ed25519(ssh_key::private::Ed25519Keypair::random(
            &mut rng,
        ));
        let sk = ssh_key::private::PrivateKey::new(kp, "test key").unwrap();

        let mk = Builder::new_from_ssh_private_key(&sk)
            .unwrap()
            .try_build()
            .unwrap();

        let attr = mk.attr_view().unwrap();
        assert_eq!(mk.codec(), Codec::Ed25519Priv);
        assert_eq!(mk.comment, "test key".to_string());
        assert_eq!(false, attr.is_encrypted());
        assert_eq!(false, attr.is_public_key());
        assert_eq!(true, attr.is_secret_key());
        let kd = mk.key_data_view().unwrap();
        assert!(kd.key_bytes().is_ok());
        assert!(kd.secret_bytes().is_ok());
    }

    #[test]
    fn test_pub_from_string() {
        let s = "zVQSE6EFkZ7inH63w9bBj9jtkj1wL8LHrQ3mW1P9db6JBLnf3aEaesMak9p8Jinmb".to_string();
        let mk = EncodedMultikey::try_from(s.as_str()).unwrap();
        let attr = mk.attr_view().unwrap();
        assert_eq!(mk.codec(), Codec::Ed25519Pub);
        assert_eq!(mk.encoding(), Base::Base58Btc);
        assert_eq!(mk.comment, "test key".to_string());
        assert_eq!(false, attr.is_encrypted());
        assert_eq!(true, attr.is_public_key());
        assert_eq!(false, attr.is_secret_key());
        let kd = mk.key_data_view().unwrap();
        assert!(kd.key_bytes().is_ok());
        assert!(kd.secret_bytes().is_err()); // public key
    }

    #[test]
    fn test_priv_from_string() {
        let s = "bhkacmcdumvzxiidlmv4qcaja5nk775jrjosqisq42b45vfsxzkah2753vhkjzzg3jdteo2zqrp2a"
            .to_string();
        let mk = EncodedMultikey::try_from(s.as_str()).unwrap();
        let attr = mk.attr_view().unwrap();
        assert_eq!(mk.codec(), Codec::Ed25519Priv);
        assert_eq!(mk.encoding(), Base::Base32Lower);
        assert_eq!(mk.comment, "test key".to_string());
        assert_eq!(false, attr.is_encrypted());
        assert_eq!(false, attr.is_public_key());
        assert_eq!(true, attr.is_secret_key());
        let kd = mk.key_data_view().unwrap();
        assert!(kd.key_bytes().is_ok());
        assert!(kd.secret_bytes().is_ok());
    }

    #[test]
    fn test_pub_from_vec() {
        let b = hex::decode("3aed010874657374206b6579010120552da9e68c94a11c75da53e66d269a992647ca6cfabca4283e1fd322cceb75d4").unwrap();
        let mk = Multikey::try_from(b.as_slice()).unwrap();
        let attr = mk.attr_view().unwrap();
        assert_eq!(mk.codec(), Codec::Ed25519Pub);
        assert_eq!(mk.comment, "test key".to_string());
        assert_eq!(false, attr.is_encrypted());
        assert_eq!(true, attr.is_public_key());
        assert_eq!(false, attr.is_secret_key());
        let kd = mk.key_data_view().unwrap();
        assert!(kd.key_bytes().is_ok());
        assert!(kd.secret_bytes().is_err()); // public key
    }

    #[test]
    fn test_priv_from_vec() {
        let b = hex::decode("3a80260874657374206b65790101201e0d7193b676e03b2ba4f329c3817d569de404eef2809b7f401111435dcf3f6b").unwrap();
        let mk = Multikey::try_from(b.as_slice()).unwrap();
        let attr = mk.attr_view().unwrap();
        assert_eq!(mk.codec(), Codec::Ed25519Priv);
        assert_eq!(mk.comment, "test key".to_string());
        assert_eq!(false, attr.is_encrypted());
        assert_eq!(false, attr.is_public_key());
        assert_eq!(true, attr.is_secret_key());
        let kd = mk.key_data_view().unwrap();
        assert!(kd.key_bytes().is_ok());
        assert!(kd.secret_bytes().is_ok());
    }
}
