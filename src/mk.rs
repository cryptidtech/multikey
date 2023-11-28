use crate::{
    encdec::{EncDec, Kdf},
    error::Error,
};
use ed25519_dalek as ed25519;
use multibase::Base;
use multicodec::Codec;
use multihash::mh::{self, Multihash};
use multitrait::TryDecodeFrom;
use multiutil::{BaseEncoded, CodecInfo, EncodingInfo, Varbytes, Varuint};
use rand::{CryptoRng, RngCore};
use sec1::point::EncodedPoint;

use ssh_key::{
    private::{EcdsaKeypair, Ed25519Keypair, Ed25519PrivateKey, KeypairData},
    public::{EcdsaPublicKey, Ed25519PublicKey, KeyData},
    EcdsaCurve, PrivateKey, PublicKey,
};
use std::fmt;
use typenum::consts::*;
use zeroize::Zeroizing;

/// the multicodec sigil for multikey
pub const SIGIL: Codec = Codec::Multikey;

// the index of the comment data unit
const COMMENT: usize = 0;

// the index of the public key data unit
const KEY: usize = 1;

/// the multikey structure
pub type EncodedMultikey = BaseEncoded<Multikey>;

/// The main multikey structure
#[derive(Clone, PartialEq)]
pub struct Multikey {
    /// The key codec
    pub(crate) codec: Codec,

    /// if the key is encrypted
    pub(crate) encrypted: u8,

    /// The codec-specific attributes
    pub(crate) attributes: Vec<u64>,

    /// The data units for the key
    pub(crate) data: Vec<Vec<u8>>,
}

impl Multikey {
    /// return an immutable reference to the attributes
    pub fn attributes(&self) -> &Vec<u64> {
        &self.attributes
    }

    /// return a mutable reference to the attributes
    pub fn attributes_mut(&mut self) -> &mut Vec<u64> {
        &mut self.attributes
    }

    /// return an immutable reference to the data
    pub fn data(&self) -> &Vec<Vec<u8>> {
        &self.data
    }

    /// return a mutable reference to the data
    pub fn data_mut(&mut self) -> &mut Vec<Vec<u8>> {
        &mut self.data
    }

    /// whether or not this is a secret key
    pub fn is_private_key(&self) -> bool {
        use multicodec::codec::Codec::*;
        match self.codec {
            Ed25519Priv | P256Priv | P384Priv | P521Priv | Secp256K1Priv | X25519Priv | RsaPriv
            | Aes128 | Aes192 | Aes256 | Chacha128 | Chacha256 => true,
            _ => false,
        }
    }

    /// wether or not this is a public key
    pub fn is_public_key(&self) -> bool {
        use multicodec::codec::Codec::*;
        match self.codec {
            Ed25519Pub | Ed448Pub | P256Pub | P384Pub | P521Pub | Secp256K1Pub | Bls12381G1Pub
            | Bls12381G2Pub | Bls12381G1G2Pub | X25519Pub | X448Pub | Sr25519Pub | RsaPub => true,
            _ => false,
        }
    }

    /// get the key comment
    pub fn comment(&self) -> Result<String, Error> {
        if self.data.len() < 1 {
            return Err(Error::MissingComment);
        }

        // try to decode the first data unit as a comment
        Ok(String::from_utf8(self.data[COMMENT].as_slice().into())?)
    }

    /// set the key comment
    pub fn set_comment(&mut self, comment: &str) -> Result<(), Error> {
        let du = comment.as_bytes().to_vec();
        match self.data.len() {
            0 => self.data.push(du),
            _ => {
                // replace the existing comment
                let dum = self.data.get_mut(COMMENT).ok_or(Error::MissingComment)?;
                *dum = du;
            }
        }
        Ok(())
    }

    /// is this multikey encrypted?
    pub fn is_encrypted(&self) -> bool {
        self.encrypted != 0u8
    }

    /// set the encryption state
    pub fn set_encrypted(&mut self, e: bool) {
        match e {
            true => self.encrypted = 1u8,
            false => self.encrypted = 0u8,
        }
    }

    /// get the figureprint of the key
    pub fn fingerprint(&self, codec: Codec) -> Result<Multihash, Error> {
        if self.is_encrypted() {
            return Err(Error::FingerprintFailed("key is encrypted".to_string()));
        }
        let key = self.data.get(KEY).ok_or(Error::MissingKey)?;
        Ok(mh::Builder::new(codec).try_build(key)?)
    }

    /// encrypt this multikey
    pub fn encrypt(
        mut mk: &mut Multikey,
        kdf: impl Kdf,
        cipher: impl EncDec,
        passphrase: impl AsRef<[u8]>,
    ) -> Result<(), Error> {
        if !mk.is_private_key() {
            return Err(Error::EncryptionFailed("must be a secret key".to_string()));
        }

        if mk.is_encrypted() {
            return Err(Error::EncryptionFailed("already encrypted".to_string()));
        }

        if mk.data.len() < 1 {
            return Err(Error::EncryptionFailed("too few data units".to_string()));
        }

        // clear out the codec-specific values and remove all data units except
        // the comment
        mk.attributes.clear();
        mk.data.truncate(1);

        // derive the key and store the parameters and data units in the multikey
        let key = kdf.derive(&mut mk, passphrase)?;

        // encrypt the multikey and store the parameters and data units in the multikey
        cipher.encrypt(&mut mk, key)?;

        Ok(())
    }

    /// decrypt this multikey
    pub fn decrypt(
        mut mk: &mut Multikey,
        kdf: impl Kdf,
        cipher: impl EncDec,
        passphrase: impl AsRef<[u8]>,
    ) -> Result<(), Error> {
        if !mk.is_private_key() {
            return Err(Error::DecryptionFailed("must be a secret key".to_string()));
        }

        if !mk.is_encrypted() {
            return Err(Error::DecryptionFailed("not encrypted".to_string()));
        }

        if mk.data.len() < 3 {
            return Err(Error::DecryptionFailed("too few data units".to_string()));
        }

        // clear out the codec-specific values and remove all data units except
        // the comment
        mk.attributes.clear();
        mk.data.truncate(1);

        // derive the key
        let key = {
            // make a temporary copy
            let mut tk = mk.clone();

            // derive the key and store the parameters and data units in the multikey
            kdf.derive(&mut tk, passphrase)?
        };

        // decrypt the multikey
        cipher.decrypt(&mut mk, key)?;

        Ok(())
    }

    /// get the public key from the private key if it is a private key
    pub fn to_public_key(&self) -> Result<Multikey, Error> {
        if !self.is_private_key() {
            return Err(Error::NotPrivateKey(self.codec));
        }
        if self.is_encrypted() {
            return Err(Error::PublicKeyFailure(
                "encrypted private key, decrypt it first".to_string(),
            ));
        }

        match self.codec {
            Codec::Ed25519Priv => {
                let du = self.data.get(KEY).ok_or(Error::MissingKey)?;
                let bytes: [u8; ed25519::SECRET_KEY_LENGTH] =
                    du.as_slice()[..ed25519::SECRET_KEY_LENGTH].try_into()?;
                let private_key = ed25519::SigningKey::from_bytes(&bytes);
                let public_key = private_key.verifying_key();
                Builder::new(Codec::Ed25519Pub)
                    .with_comment(&self.comment().unwrap_or_default())
                    .with_key_bytes(public_key.as_bytes())
                    .try_build()
            }
            /*
            Codec::P256Priv => {}
            Codec::P384Priv => {}
            Codec::P521Priv => {}
            Codec::Secp256K1Priv => {}
            Codec::X25519Priv => {}
            Codec::RsaPriv => {}
            Codec::Aes128 => {}
            Codec::Aes192 => {}
            Codec::Aes256 => {}
            Codec::Chacha128 => {}
            Codec::Chacha256 => {}
            */
            _ => Err(Error::UnsupportedCodec(self.codec)),
        }
    }

    /// try to convert this multikey to a ssh_key::PrivateKey
    pub fn to_ssh_private_key(&self) -> Result<PrivateKey, Error> {
        if !self.is_private_key() {
            return Err(Error::NotPrivateKey(self.codec));
        }

        match self.codec {
            Codec::Ed25519Priv => {
                let du = self.data.get(KEY).ok_or(Error::MissingKey)?;
                let bytes: [u8; ed25519::SECRET_KEY_LENGTH] =
                    du.as_slice()[..ed25519::SECRET_KEY_LENGTH].try_into()?;
                let private_key = Ed25519PrivateKey::from_bytes(&bytes);
                let keypair = Ed25519Keypair::from(private_key);
                let keypair_data = KeypairData::Ed25519(keypair);
                Ok(PrivateKey::new(
                    keypair_data,
                    self.comment().map_err(|_| Error::MissingComment)?,
                )
                .map_err(|_| {
                    Error::PrivateKeyFailure("failed to convert private key".to_string())
                })?)
            }
            /*
            Codec::P256Priv => {}
            Codec::P384Priv => {}
            Codec::P521Priv => {}
            Codec::Secp256K1Priv => {}
            Codec::X25519Priv => {}
            Codec::RsaPriv => {}
            Codec::Aes128 => {}
            Codec::Aes192 => {}
            Codec::Aes256 => {}
            Codec::Chacha128 => {}
            Codec::Chacha256 => {}
            */
            _ => Err(Error::UnsupportedCodec(self.codec)),
        }
    }

    /// try to convert this multikey to a ssh_key::PublicKey
    pub fn to_ssh_public_key(&self) -> Result<PublicKey, Error> {
        match self.codec {
            Codec::P256Pub => {
                if let Some(du) = self.data.get(KEY) {
                    let point = EncodedPoint::<U32>::from_bytes(du)?;
                    let p256 = EcdsaPublicKey::NistP256(point);
                    Ok(PublicKey::new(
                        KeyData::Ecdsa(p256),
                        self.comment().map_err(|_| Error::MissingComment)?,
                    ))
                } else {
                    Err(Error::MissingKey)
                }
            }
            Codec::P384Pub => {
                if let Some(du) = self.data.get(KEY) {
                    let point = EncodedPoint::<U48>::from_bytes(du)?;
                    let p384 = EcdsaPublicKey::NistP384(point);
                    Ok(PublicKey::new(
                        KeyData::Ecdsa(p384),
                        self.comment().map_err(|_| Error::MissingComment)?,
                    ))
                } else {
                    Err(Error::MissingKey)
                }
            }
            Codec::P521Pub => {
                if let Some(du) = self.data.get(KEY) {
                    let point = EncodedPoint::<U66>::from_bytes(du)?;
                    let p521 = EcdsaPublicKey::NistP521(point);
                    Ok(PublicKey::new(
                        KeyData::Ecdsa(p521),
                        self.comment().map_err(|_| Error::MissingComment)?,
                    ))
                } else {
                    Err(Error::MissingKey)
                }
            }
            Codec::Ed25519Pub => {
                let key_data = match self.data.get(KEY) {
                    Some(du) => {
                        let point: [u8; 32] = du.as_slice()[..32].try_into()?;
                        let ed25519 = Ed25519PublicKey(point);
                        KeyData::Ed25519(ed25519)
                    }
                    _ => return Err(Error::MissingKey),
                };
                Ok(PublicKey::new(
                    key_data,
                    self.comment().map_err(|_| Error::MissingComment)?,
                ))
            }
            _ => Err(Error::MissingKey),
        }
    }
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

impl Default for Multikey {
    fn default() -> Self {
        // create a vector of data units with an empty comment
        let mut data = Vec::with_capacity(1);
        data.push(Vec::default());

        Multikey {
            codec: Codec::Identity,
            encrypted: 0u8,
            attributes: Vec::default(),
            data,
        }
    }
}

impl Into<Vec<u8>> for Multikey {
    fn into(self) -> Vec<u8> {
        let mut v = Vec::default();
        // add in the multikey sigil
        v.append(&mut SIGIL.into());
        // add in the key codec
        v.append(&mut self.codec.clone().into());
        // add in the encrypted flag
        v.append(&mut Varuint(self.encrypted).into());
        // add in the number of codec-specific varuints
        v.append(&mut Varuint(self.attributes.len()).into());
        // add in the codec-specific values
        self.attributes
            .iter()
            .for_each(|cv| v.append(&mut Varuint(*cv).into()));
        // add in the number of data units
        v.append(&mut Varuint(self.data.len()).into());
        // add in the data units
        self.data
            .iter()
            .for_each(|du| v.append(&mut Varbytes(du.clone()).into()));
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

        // decode the encrypted flag
        let (encrypted, ptr) = Varuint::<u8>::try_decode_from(ptr)?;
        let encrypted = encrypted.to_inner();

        // decode the number of codec-specific values
        let (num_cv, ptr) = Varuint::<usize>::try_decode_from(ptr)?;
        let num_cv = num_cv.to_inner();

        let (attributes, ptr) = match num_cv {
            0 => (Vec::default(), ptr),
            _ => {
                // decode the codec-specific values
                let mut attributes = Vec::with_capacity(num_cv);
                let mut p = ptr;
                for _ in 0..num_cv {
                    let (cv, ptr) = Varuint::<u64>::try_decode_from(p)?;
                    attributes.push(cv.to_inner());
                    p = ptr;
                }
                (attributes, p)
            }
        };

        // decode the number of data units
        let (num_du, ptr) = Varuint::<usize>::try_decode_from(ptr)?;
        let num_du = num_du.to_inner();

        let (data, ptr) = match num_du {
            0 => (Vec::default(), ptr),
            _ => {
                // decode the data units
                let mut data = Vec::with_capacity(num_du);
                let mut p = ptr;
                for _ in 0..num_du {
                    let (du, ptr) = Varbytes::try_decode_from(p)?;
                    data.push(du.to_inner());
                    p = ptr;
                }
                (data, p)
            }
        };

        Ok((
            Self {
                codec,
                encrypted,
                attributes,
                data,
            },
            ptr,
        ))
    }
}

impl fmt::Debug for Multikey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:?} - {:?} - Encrypted: {}",
            SIGIL,
            self.codec(),
            if self.is_encrypted() { "true" } else { "false" }
        )
    }
}

/// Multikey builder constructs private keys only. If you need a public key you
/// must first generate a priate key and then get the public key from that.
#[derive(Clone, Debug, Default)]
pub struct Builder {
    codec: Codec,
    encoding: Option<Base>,
    comment: Option<String>,
    key_bytes: Option<Zeroizing<Vec<u8>>>,
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
            Codec::P256Priv => EcdsaKeypair::random(rng, EcdsaCurve::NistP256)?
                .private_key_bytes()
                .to_vec()
                .into(),
            Codec::P384Priv => EcdsaKeypair::random(rng, EcdsaCurve::NistP384)?
                .private_key_bytes()
                .to_vec()
                .into(),
            Codec::P521Priv => EcdsaKeypair::random(rng, EcdsaCurve::NistP521)?
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
            _ => return Err(Error::UnsupportedCodec(codec)),
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
                            return Err(Error::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            ));
                        }
                    }
                    NistP384 => {
                        if let KeyData::Ecdsa(EcdsaPublicKey::NistP384(point)) = sshkey.key_data() {
                            (Some(point.as_bytes().to_vec().into()), Codec::P384Pub)
                        } else {
                            return Err(Error::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            ));
                        }
                    }
                    NistP521 => {
                        if let KeyData::Ecdsa(EcdsaPublicKey::NistP521(point)) = sshkey.key_data() {
                            (Some(point.as_bytes().to_vec().into()), Codec::P521Pub)
                        } else {
                            return Err(Error::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            ));
                        }
                    }
                };
                Ok(Builder {
                    codec,
                    encoding: None,
                    comment: Some(sshkey.comment().to_string()),
                    key_bytes,
                })
            }
            Ed25519 => {
                let key_bytes = match sshkey.key_data() {
                    KeyData::Ed25519(e) => Some(e.0.to_vec().into()),
                    _ => return Err(Error::UnsupportedAlgorithm(sshkey.algorithm().to_string())),
                };
                Ok(Builder {
                    codec: Codec::Ed25519Pub,
                    encoding: None,
                    comment: Some(sshkey.comment().to_string()),
                    key_bytes,
                })
            }
            _ => Err(Error::UnsupportedAlgorithm(sshkey.algorithm().to_string())),
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
                            return Err(Error::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            ));
                        }
                    }
                    NistP384 => {
                        if let KeypairData::Ecdsa(EcdsaKeypair::NistP384 { private, .. }) =
                            sshkey.key_data()
                        {
                            (Some(private.as_slice().to_vec().into()), Codec::P384Priv)
                        } else {
                            return Err(Error::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            ));
                        }
                    }
                    NistP521 => {
                        if let KeypairData::Ecdsa(EcdsaKeypair::NistP521 { private, .. }) =
                            sshkey.key_data()
                        {
                            (Some(private.as_slice().to_vec().into()), Codec::P521Priv)
                        } else {
                            return Err(Error::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            ));
                        }
                    }
                };
                Ok(Builder {
                    codec,
                    encoding: None,
                    comment: Some(sshkey.comment().to_string()),
                    key_bytes,
                })
            }
            Ed25519 => {
                let key_bytes = match sshkey.key_data() {
                    KeypairData::Ed25519(e) => Some(e.private.to_bytes().to_vec().into()),
                    _ => return Err(Error::UnsupportedAlgorithm(sshkey.algorithm().to_string())),
                };
                Ok(Builder {
                    codec: Codec::Ed25519Priv,
                    encoding: None,
                    comment: Some(sshkey.comment().to_string()),
                    key_bytes,
                })
            }
            _ => Err(Error::UnsupportedAlgorithm(sshkey.algorithm().to_string())),
        }
    }

    /// add an encoding
    pub fn with_encoding(mut self, base: Base) -> Self {
        self.encoding = Some(base);
        self
    }

    /// add a comment
    pub fn with_comment(mut self, comment: &str) -> Self {
        self.comment = Some(comment.to_string());
        self
    }

    /// add in the key bytes directly
    pub fn with_key_bytes(mut self, bytes: &impl AsRef<[u8]>) -> Self {
        self.key_bytes = Some(bytes.as_ref().to_vec().into());
        self
    }

    /// build a base encoded multikey
    pub fn try_build_encoded(self) -> Result<EncodedMultikey, Error> {
        let mk = self.clone().try_build()?;
        if let Some(encoding) = self.encoding {
            Ok(BaseEncoded::new_base(encoding, mk))
        } else {
            Ok(mk.into())
        }
    }

    /// build a key using key bytes
    pub fn try_build(self) -> Result<Multikey, Error> {
        let mut data = Vec::with_capacity(2);
        let comment = self.comment.unwrap_or_default().as_bytes().to_vec();
        let key_data = self.key_bytes.ok_or(Error::MissingKey)?.to_vec();
        data.push(comment);
        data.push(key_data);
        Ok(Multikey {
            codec: self.codec,
            encrypted: 0u8,
            attributes: Vec::default(),
            data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encdec::{cipher, pbkdf};

    #[test]
    fn test_simple_random() {
        let mut rng = rand::rngs::OsRng::default();
        let mk = Builder::new_from_random_bytes(Codec::Ed25519Priv, &mut rng)
            .unwrap()
            .with_comment("test key")
            .try_build()
            .unwrap();
        let v: Vec<u8> = mk.into();
        assert_eq!(48, v.len());
    }

    #[test]
    fn test_encoded_random() {
        let mut rng = rand::rngs::OsRng::default();
        let mk = Builder::new_from_random_bytes(Codec::Ed25519Priv, &mut rng)
            .unwrap()
            .with_encoding(Base::Base58Btc)
            .with_comment("test key")
            .try_build_encoded()
            .unwrap();
        println!("{:?}", mk);
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

        assert_eq!(false, mk1.is_encrypted());
        assert_eq!(mk1.attributes.len(), 0);
        assert_eq!(mk1.data.len(), 2);

        let mut mk2 = {
            let kdf = pbkdf::Builder::new(Codec::BcryptPbkdf)
                .with_random_salt(&mut rng)
                .with_rounds(10)
                .try_build()
                .unwrap();

            let cipher = cipher::Builder::new(Codec::Chacha20Poly1305)
                .from_multikey(&mk1) // init the msg with the unencrypted key
                .with_random_nonce(&mut rng)
                .try_build()
                .unwrap();

            let mut mk2 = mk1.clone();
            Multikey::encrypt(&mut mk2, kdf, cipher, "for great justice, move every zig!").unwrap();
            mk2
        };

        assert_eq!(true, mk2.is_encrypted());
        assert_eq!(mk2.attributes.len(), 6);
        assert_eq!(mk2.data.len(), 4);

        let mk3 = {
            let kdf = pbkdf::Builder::default()
                .from_multikey(&mk2)
                .try_build()
                .unwrap();

            let cipher = cipher::Builder::default()
                .from_multikey(&mk2)
                .try_build()
                .unwrap();

            Multikey::decrypt(&mut mk2, kdf, cipher, "for great justice, move every zig!").unwrap();
            mk2
        };

        assert_eq!(false, mk3.is_encrypted());
        assert_eq!(mk3.attributes.len(), 0);
        assert_eq!(mk3.data.len(), 2);

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

        assert_eq!(mk.codec, Codec::Ed25519Pub);
        assert_eq!(mk.comment().unwrap(), "test key".to_string());
        assert_eq!(mk.data.len(), 2);
        assert_eq!(mk.data[1].len(), 32);
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

        assert_eq!(mk.codec, Codec::Ed25519Priv);
        assert_eq!(mk.comment().unwrap(), "test key".to_string());
        assert_eq!(mk.data.len(), 2);
        assert_eq!(mk.data[1].len(), 32);
    }

    #[test]
    fn test_pub_from_string() {
        let s = "z3ANSLZwn9GEMLp4EmVzgC5jjqPe35pxqcU5m4UE5wQ55gtXgozs5KQxjRZ8XGHZqDD".to_string();
        let mk = EncodedMultikey::try_from(s.as_str()).unwrap();
        assert_eq!(mk.codec, Codec::Ed25519Pub);
        assert_eq!(mk.encoding(), Base::Base58Btc);
        assert_eq!(mk.comment().unwrap(), "test key".to_string());
        assert_eq!(mk.data.len(), 2);
        assert_eq!(mk.data[1].len(), 32);
    }

    #[test]
    fn test_priv_from_string() {
        let s = "bhkacmaaaaiehizltoqqgwzlzebb56sjufecb4iojcvqmb7epi7rbfqufuvisdjijrjdpljkm5esnu"
            .to_string();
        let mk = EncodedMultikey::try_from(s.as_str()).unwrap();
        assert_eq!(mk.codec, Codec::Ed25519Priv);
        assert_eq!(mk.encoding(), Base::Base32Lower);
        assert_eq!(mk.comment().unwrap(), "test key".to_string());
        assert_eq!(mk.data.len(), 2);
        assert_eq!(mk.data[1].len(), 32);
    }

    #[test]
    fn test_pub_from_vec() {
        let b = hex::decode("3aed010000020874657374206b6579201cfed95aa8daba98d1a7116722bf6b3ae4c035c941c36066e246b01585e834a8").unwrap();
        let mk = Multikey::try_from(b.as_slice()).unwrap();
        assert_eq!(mk.codec, Codec::Ed25519Pub);
        assert_eq!(mk.comment().unwrap(), "test key".to_string());
        assert_eq!(mk.data.len(), 2);
        assert_eq!(mk.data[1].len(), 32);
    }

    #[test]
    fn test_priv_from_vec() {
        let b = hex::decode("3a80260000020874657374206b657920fa87fe4afd223a2560972ea13f9d6223ad955f10a334b1fb6ef5ce6bff4d9dbd").unwrap();
        let mk = Multikey::try_from(b.as_slice()).unwrap();
        assert_eq!(mk.codec, Codec::Ed25519Priv);
        assert_eq!(mk.comment().unwrap(), "test key".to_string());
        assert_eq!(mk.data.len(), 2);
        assert_eq!(mk.data[1].len(), 32);
    }
}
