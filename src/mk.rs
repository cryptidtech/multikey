use crate::{
    attributes_view,
    error::{AttributesError, ConversionsError},
    AttrId, Error,
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
        let attr = attributes_view(&self).map_err(|_| fmt::Error)?;

        write!(
            f,
            "{:?} - {:?} - Encrypted: {}",
            SIGIL,
            self.codec(),
            if attr.borrow().is_encrypted() {
                "true"
            } else {
                "false"
            }
        )
    }
}

/// Multikey builder constructs private keys only. If you need a public key you
/// must first generate a priate key and then get the public key from that.
#[derive(Clone, Debug, Default)]
pub struct Builder {
    codec: Codec,
    comment: Option<String>,
    key_bytes: Option<Zeroizing<Vec<u8>>>,
    base_encoding: Option<Base>,
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
        let key_bytes = Some(match codec {
            Codec::Ed25519Priv => Ed25519Keypair::random(rng)
                .private
                .to_bytes()
                .to_vec()
                .into(),
            Codec::P256Priv => EcdsaKeypair::random(rng, EcdsaCurve::NistP256)
                .map_err(|e| ConversionsError::SshKey(e))?
                .private_key_bytes()
                .to_vec()
                .into(),
            Codec::P384Priv => EcdsaKeypair::random(rng, EcdsaCurve::NistP384)
                .map_err(|e| ConversionsError::SshKey(e))?
                .private_key_bytes()
                .to_vec()
                .into(),
            Codec::P521Priv => EcdsaKeypair::random(rng, EcdsaCurve::NistP521)
                .map_err(|e| ConversionsError::SshKey(e))?
                .private_key_bytes()
                .to_vec()
                .into(),
            /*
            Codec::Secp256K1Priv => {}
            Codec::X25519Priv => {}
            Codec::RsaPriv => {}
            Codec::Aes128 => {}
            Codec::Aes192 => {}
            Codec::Aes256 => {}
            Codec::Chacha128 => {}
            Codec::Chacha256 => {}
            */
            _ => return Err(ConversionsError::UnsupportedCodec(codec).into()),
        });

        Ok(Builder {
            codec,
            key_bytes,
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
                            (Some(point.as_bytes().to_vec().into()), Codec::P256Pub)
                        } else {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into());
                        }
                    }
                    NistP384 => {
                        if let KeyData::Ecdsa(EcdsaPublicKey::NistP384(point)) = sshkey.key_data() {
                            (Some(point.as_bytes().to_vec().into()), Codec::P384Pub)
                        } else {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into());
                        }
                    }
                    NistP521 => {
                        if let KeyData::Ecdsa(EcdsaPublicKey::NistP521(point)) = sshkey.key_data() {
                            (Some(point.as_bytes().to_vec().into()), Codec::P521Pub)
                        } else {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into());
                        }
                    }
                };
                Ok(Builder {
                    codec,
                    comment: Some(sshkey.comment().to_string()),
                    key_bytes,
                    base_encoding: None,
                })
            }
            Ed25519 => {
                let key_bytes = match sshkey.key_data() {
                    KeyData::Ed25519(e) => Some(e.0.to_vec().into()),
                    _ => {
                        return Err(ConversionsError::UnsupportedAlgorithm(
                            sshkey.algorithm().to_string(),
                        )
                        .into())
                    }
                };
                Ok(Builder {
                    codec: Codec::Ed25519Pub,
                    comment: Some(sshkey.comment().to_string()),
                    key_bytes,
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
                            (Some(private.as_slice().to_vec().into()), Codec::P256Priv)
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
                            (Some(private.as_slice().to_vec().into()), Codec::P384Priv)
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
                            (Some(private.as_slice().to_vec().into()), Codec::P521Priv)
                        } else {
                            return Err(ConversionsError::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            )
                            .into());
                        }
                    }
                };
                Ok(Builder {
                    codec,
                    comment: Some(sshkey.comment().to_string()),
                    key_bytes,
                    base_encoding: None,
                })
            }
            Ed25519 => {
                let key_bytes = match sshkey.key_data() {
                    KeypairData::Ed25519(e) => Some(e.private.to_bytes().to_vec().into()),
                    _ => {
                        return Err(ConversionsError::UnsupportedAlgorithm(
                            sshkey.algorithm().to_string(),
                        )
                        .into())
                    }
                };
                Ok(Builder {
                    codec: Codec::Ed25519Priv,
                    comment: Some(sshkey.comment().to_string()),
                    key_bytes,
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

    /// add in the key bytes directly
    pub fn with_key_bytes(mut self, bytes: &impl AsRef<[u8]>) -> Self {
        let b: Vec<u8> = bytes.as_ref().into();
        self.key_bytes = Some(b.into());
        self
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
        let mut attributes = Attributes::new();
        let key_data = self.key_bytes.ok_or(AttributesError::MissingKey)?.to_vec();
        attributes.insert(AttrId::KeyData.into(), key_data.into());
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
    use crate::{attributes_view, cipher, cipher_view, kdf, kdf_view, key_views};

    #[test]
    fn test_simple_random() {
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
    fn test_encoded_random() {
        let mut rng = rand::rngs::OsRng::default();
        let mk = Builder::new_from_random_bytes(Codec::Ed25519Priv, &mut rng)
            .unwrap()
            .with_base_encoding(Base::Base58Btc)
            .with_comment("test key")
            .try_build_encoded()
            .unwrap();
        let s = mk.to_string();
        assert_eq!(mk, EncodedMultikey::try_from(s.as_str()).unwrap());
    }

    #[test]
    fn test_encryption_roundtrip() {
        let mut rng = rand::rngs::OsRng::default();
        let mk1 = Builder::new_from_random_bytes(Codec::Ed25519Priv, &mut rng)
            .unwrap()
            .with_comment("test key")
            .try_build()
            .unwrap();

        let attr = attributes_view(&mk1).unwrap();
        assert_eq!(false, attr.borrow().is_encrypted());
        assert_eq!(false, attr.borrow().is_public_key());
        assert_eq!(true, attr.borrow().is_secret_key());
        assert!(attr.borrow().key_bytes().is_ok());
        assert!(attr.borrow().secret_bytes().is_ok());

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

            // get the kdf view
            let kdf = kdf_view(&kdfmk).unwrap();
            // derive a key from the passphrase and add it to the cipher multikey
            let ciphermk = kdf
                .borrow()
                .derive_key(&ciphermk, b"for great justice, move every zig!")
                .unwrap();
            // get the cipher view
            let cipher = cipher_view(&ciphermk).unwrap();
            // encrypt the multikey using the cipher
            let mk = cipher.borrow().encrypt(&mk1).unwrap();
            mk
        };

        let attr = attributes_view(&mk2).unwrap();
        assert_eq!(true, attr.borrow().is_encrypted());
        assert_eq!(false, attr.borrow().is_public_key());
        assert_eq!(true, attr.borrow().is_secret_key());
        assert!(attr.borrow().key_bytes().is_ok());
        assert!(attr.borrow().secret_bytes().is_err()); // secret bytes are encrypted

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
            let kdf = kdf_view(&kdfmk).unwrap();
            // derive a key from the passphrase and add it to the cipher multikey
            let ciphermk = kdf
                .borrow()
                .derive_key(&ciphermk, b"for great justice, move every zig!")
                .unwrap();
            // get the cipher view
            let cipher = cipher_view(&ciphermk).unwrap();
            // decrypt the multikey using the cipher
            let mk = cipher.borrow().decrypt(&mk2).unwrap();
            mk
        };

        let attr = attributes_view(&mk3).unwrap();
        assert_eq!(false, attr.borrow().is_encrypted());
        assert_eq!(false, attr.borrow().is_public_key());
        assert_eq!(true, attr.borrow().is_secret_key());
        assert!(attr.borrow().key_bytes().is_ok());
        assert!(attr.borrow().secret_bytes().is_ok());

        // ensure the round trip worked
        assert_eq!(mk1, mk3);
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

        let attr = attributes_view(&mk).unwrap();
        assert_eq!(mk.codec, Codec::Ed25519Pub);
        assert_eq!(mk.comment, "test key".to_string());
        assert_eq!(false, attr.borrow().is_encrypted());
        assert_eq!(true, attr.borrow().is_public_key());
        assert_eq!(false, attr.borrow().is_secret_key());
        assert!(attr.borrow().key_bytes().is_ok());
        assert!(attr.borrow().secret_bytes().is_err());
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

        let attr = attributes_view(&mk).unwrap();
        assert_eq!(mk.codec(), Codec::Ed25519Priv);
        assert_eq!(mk.comment, "test key".to_string());
        assert_eq!(false, attr.borrow().is_encrypted());
        assert_eq!(false, attr.borrow().is_public_key());
        assert_eq!(true, attr.borrow().is_secret_key());
        assert!(attr.borrow().key_bytes().is_ok());
        assert!(attr.borrow().secret_bytes().is_ok());
    }

    #[test]
    fn test_pub_from_string() {
        let s = "zVQSE6EFkZ7inH63w9bBj9jtkj1wL8LHrQ3mW1P9db6JBLnf3aEaesMak9p8Jinmb".to_string();
        let mk = EncodedMultikey::try_from(s.as_str()).unwrap();
        let attr = attributes_view(&mk).unwrap();
        assert_eq!(mk.codec(), Codec::Ed25519Pub);
        assert_eq!(mk.encoding(), Base::Base58Btc);
        assert_eq!(mk.comment, "test key".to_string());
        assert_eq!(false, attr.borrow().is_encrypted());
        assert_eq!(true, attr.borrow().is_public_key());
        assert_eq!(false, attr.borrow().is_secret_key());
        assert!(attr.borrow().key_bytes().is_ok());
        assert!(attr.borrow().secret_bytes().is_err());
    }

    #[test]
    fn test_priv_from_string() {
        let s = "bhkacmcdumvzxiidlmv4qcaja5nk775jrjosqisq42b45vfsxzkah2753vhkjzzg3jdteo2zqrp2a"
            .to_string();
        let mk = EncodedMultikey::try_from(s.as_str()).unwrap();
        let attr = attributes_view(&mk).unwrap();
        assert_eq!(mk.codec(), Codec::Ed25519Priv);
        assert_eq!(mk.encoding(), Base::Base32Lower);
        assert_eq!(mk.comment, "test key".to_string());
        assert_eq!(false, attr.borrow().is_encrypted());
        assert_eq!(false, attr.borrow().is_public_key());
        assert_eq!(true, attr.borrow().is_secret_key());
        assert!(attr.borrow().key_bytes().is_ok());
        assert!(attr.borrow().secret_bytes().is_ok());
    }

    #[test]
    fn test_pub_from_vec() {
        let b = hex::decode("3aed010874657374206b6579010120552da9e68c94a11c75da53e66d269a992647ca6cfabca4283e1fd322cceb75d4").unwrap();
        let mk = Multikey::try_from(b.as_slice()).unwrap();
        let attr = attributes_view(&mk).unwrap();
        assert_eq!(mk.codec(), Codec::Ed25519Pub);
        assert_eq!(mk.comment, "test key".to_string());
        assert_eq!(false, attr.borrow().is_encrypted());
        assert_eq!(true, attr.borrow().is_public_key());
        assert_eq!(false, attr.borrow().is_secret_key());
        assert!(attr.borrow().key_bytes().is_ok());
        assert!(attr.borrow().secret_bytes().is_err());
    }

    #[test]
    fn test_priv_from_vec() {
        let b = hex::decode("3a80260874657374206b65790101201e0d7193b676e03b2ba4f329c3817d569de404eef2809b7f401111435dcf3f6b").unwrap();
        let mk = Multikey::try_from(b.as_slice()).unwrap();
        let attr = attributes_view(&mk).unwrap();
        assert_eq!(mk.codec(), Codec::Ed25519Priv);
        assert_eq!(mk.comment, "test key".to_string());
        assert_eq!(false, attr.borrow().is_encrypted());
        assert_eq!(false, attr.borrow().is_public_key());
        assert_eq!(true, attr.borrow().is_secret_key());
        assert!(attr.borrow().key_bytes().is_ok());
        assert!(attr.borrow().secret_bytes().is_ok());
    }
}
