use crate::{
    du::DataUnit,
    encdec::{EncDec, Kdf},
    error::Error,
    Result,
};
use ed25519_dalek as ed25519;
use multibase::Base;
use multicodec::codec::Codec;
use multihash::mh::{self, Multihash};
use multiutil::{EncodeInto, TryDecodeFrom};
use rand::{CryptoRng, RngCore};
use sec1::point::EncodedPoint;
use ssh_key::{
    private::{EcdsaKeypair, Ed25519Keypair, KeypairData},
    public::{EcdsaPublicKey, Ed25519PublicKey, KeyData},
    EcdsaCurve, PrivateKey, PublicKey,
};
use std::fmt;
use typenum::consts::*;

/// the multicodec sigil for multikey
pub const SIGIL: Codec = Codec::Multikey;

// the index of the comment data unit
const COMMENT: usize = 0;

// the index of the public key data unit
const KEY: usize = 1;

/// The main multikey structure
#[derive(Clone)]
pub struct Multikey {
    /// The key codec
    codec: Codec,

    /// The multibase encoding
    string_encoding: Base,

    /// if the key is encrypted
    encrypted: u8,

    /// The codec-specific values
    codec_values: Vec<u128>,

    /// The data units for the key
    data_units: Vec<DataUnit>,
}

impl Multikey {
    /// return the key type
    pub fn codec(&self) -> Codec {
        self.codec
    }

    /// return the multibase encoding
    pub fn string_encoding(&self) -> Base {
        self.string_encoding
    }

    /// set the encoding
    pub fn set_string_encoding(&mut self, encoding: Base) {
        self.string_encoding = encoding;
    }

    /// return an immutable reference to the codec_values
    pub fn codec_values(&self) -> &Vec<u128> {
        &self.codec_values
    }

    /// return a mutable reference to the codec_values
    pub fn codec_values_mut(&mut self) -> &mut Vec<u128> {
        &mut self.codec_values
    }

    /// return an immutable reference to the data_units
    pub fn data_units(&self) -> &Vec<DataUnit> {
        &self.data_units
    }

    /// return a mutable reference to the data_units
    pub fn data_units_mut(&mut self) -> &mut Vec<DataUnit> {
        &mut self.data_units
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
    pub fn comment(&self) -> Result<String> {
        if self.data_units.len() < 1 {
            anyhow::bail!(Error::MissingComment);
        }

        // try to decode the first data unit as a comment
        Ok(String::from_utf8(self.data_units[COMMENT].as_ref().into())?)
    }

    /// set the key comment
    pub fn set_comment(&mut self, comment: &str) -> Result<()> {
        let du = DataUnit::new(&comment.as_bytes());
        match self.data_units.len() {
            0 => self.data_units.push(du),
            _ => {
                // replace the existing comment
                let dum = self
                    .data_units
                    .get_mut(COMMENT)
                    .ok_or(Error::MissingComment)?;
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
    pub fn fingerprint(&self, codec: Codec) -> Result<Multihash> {
        if self.is_encrypted() {
            anyhow::bail!(Error::FingerprintFailed("key is encrypted".to_string()));
        }
        let key = self.data_units.get(KEY).ok_or(Error::MissingKey)?;
        Ok(mh::Builder::new(codec).try_build(key)?)
    }

    /// get the public key from the private key if it is a private key
    pub fn public_key(&self) -> Result<Multikey> {
        if !self.is_private_key() {
            anyhow::bail!(Error::PublicKeyFailure("not a private key".to_string()));
        }
        if self.is_encrypted() {
            anyhow::bail!(Error::PublicKeyFailure("encrypted private key".to_string()));
        }

        let mut mk = match self.codec {
            Codec::Ed25519Priv => {
                let du = self.data_units.get(KEY).ok_or(Error::MissingKey)?;
                let bytes: [u8; ed25519::SECRET_KEY_LENGTH] =
                    du.as_ref()[..ed25519::SECRET_KEY_LENGTH].try_into()?;
                let private_key = ed25519::SigningKey::from_bytes(&bytes);
                let public_key = private_key.verifying_key();
                Builder::new(Codec::Ed25519Pub)
                    .with_string_encoding(self.string_encoding)
                    .with_comment(&self.comment().unwrap_or_default())
                    .with_key_bytes(public_key.as_bytes())
                    .try_build()?
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
            _ => anyhow::bail!(Error::UnsupportedCodec(self.codec)),
        };
        mk.set_string_encoding(self.string_encoding);
        Ok(mk)
    }

    /// encrypt this multikey
    pub fn encrypt(
        &mut self,
        kdf: impl Kdf,
        cipher: impl EncDec,
        passphrase: impl AsRef<[u8]>,
    ) -> Result<()> {
        if !self.is_private_key() {
            anyhow::bail!(Error::EncryptionFailed("must be a secret key".to_string()));
        }

        if self.is_encrypted() {
            anyhow::bail!(Error::EncryptionFailed("already encrypted".to_string()));
        }

        if self.data_units.len() < 1 {
            anyhow::bail!(Error::EncryptionFailed("too few data units".to_string()));
        }

        // clear out the codec-specific values and remove all data units except
        // the comment
        self.codec_values.clear();
        self.data_units.truncate(1);

        // make a temporary copy
        let mut mk = self.clone();

        // derive the key and store the parameters and data units in the multikey
        let key = kdf.derive(&mut mk, passphrase)?;

        // encrypt the multikey and store the parameters and data units in the multikey
        cipher.encrypt(&mut mk, key)?;

        // overwrite self
        *self = mk;

        Ok(())
    }

    /// decrypt this multikey
    pub fn decrypt(
        &mut self,
        kdf: impl Kdf,
        cipher: impl EncDec,
        passphrase: impl AsRef<[u8]>,
    ) -> Result<()> {
        if !self.is_private_key() {
            anyhow::bail!(Error::DecryptionFailed("must be a secret key".to_string()));
        }

        if !self.is_encrypted() {
            anyhow::bail!(Error::DecryptionFailed("not encrypted".to_string()));
        }

        if self.data_units.len() < 3 {
            anyhow::bail!(Error::DecryptionFailed("too few data units".to_string()));
        }

        // clear out the codec-specific values and remove all data units except
        // the comment
        self.codec_values.clear();
        self.data_units.truncate(1);

        // derive the key
        let key = {
            // make a temporary copy
            let mut mk = self.clone();

            // derive the key and store the parameters and data units in teh multikey
            kdf.derive(&mut mk, passphrase)?
        };

        // make another temporary copy
        let mut mk = self.clone();

        // decrypt the multikey
        cipher.decrypt(&mut mk, key)?;

        //overwrite self
        *self = mk;

        Ok(())
    }
}

impl fmt::Debug for Multikey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "{}:", SIGIL)?;
        writeln!(f, "\tKey Codec: {}", self.codec)?;
        writeln!(f, "\tEncrypted: {}", self.is_encrypted())?;
        writeln!(f, "\tCodec-specific Values: [")?;
        for cv in &self.codec_values {
            writeln!(f, "\t\t0x{:x}", cv)?;
        }
        writeln!(f, "\t]")?;
        writeln!(
            f,
            "\tComment: {}",
            self.comment().map_err(|_| std::fmt::Error)?
        )?;
        writeln!(f, "\tData Units: [")?;
        if self.data_units.len() > 1 {
            for du in &self.data_units[1..] {
                writeln!(f, "\t\t({}): {}", du.len(), hex::encode(du.as_ref()))?;
            }
        }
        writeln!(f, "\t]")
    }
}

impl PartialEq for Multikey {
    fn eq(&self, rhs: &Self) -> bool {
        self.codec == rhs.codec
            && self.encrypted == rhs.encrypted
            && self.codec_values == rhs.codec_values
            && self.data_units == rhs.data_units
    }
}

impl Default for Multikey {
    fn default() -> Self {
        // create a vector of data units with an empty comment
        let mut data_units = Vec::with_capacity(1);
        data_units.push(DataUnit::default());

        Multikey {
            codec: Codec::Ed25519Pub,
            string_encoding: Base::Base16Lower,
            encrypted: 0u8,
            codec_values: Vec::default(),
            data_units,
        }
    }
}

impl EncodeInto for Multikey {
    fn encode_into(&self) -> Vec<u8> {
        // start with the sigil
        let mut v = SIGIL.encode_into();

        // add the key codec
        v.append(&mut self.codec.encode_into());

        // add the encrypted flag
        v.append(&mut self.encrypted.encode_into());

        // add in the number of codec-specific varuints
        v.append(&mut self.codec_values.len().encode_into());

        // add in the codec-specific values
        for cv in &self.codec_values {
            v.append(&mut cv.encode_into());
        }

        // add in the number of data units
        v.append(&mut self.data_units.len().encode_into());

        // add in the data units
        for du in &self.data_units {
            let mut duv = du.encode_into();
            v.append(&mut duv);
        }

        v
    }
}

impl ToString for Multikey {
    fn to_string(&self) -> String {
        let v = self.encode_into();
        multibase::encode(self.string_encoding, &v)
    }
}

impl TryFrom<String> for Multikey {
    type Error = Error;

    fn try_from(s: String) -> std::result::Result<Self, Self::Error> {
        Self::try_from(s.as_str())
    }
}

impl TryFrom<&str> for Multikey {
    type Error = Error;

    fn try_from(s: &str) -> std::result::Result<Self, Self::Error> {
        match multibase::decode(s) {
            Ok((base, v)) => {
                let (mut mk, _) = Self::try_decode_from(v.as_slice())?;
                mk.string_encoding = base;
                Ok(mk)
            }
            Err(e) => Err(Error::Multibase(e)),
        }
    }
}

impl TryFrom<Vec<u8>> for Multikey {
    type Error = Error;

    fn try_from(v: Vec<u8>) -> std::result::Result<Self, Self::Error> {
        let (mk, _) = Self::try_decode_from(v.as_slice())?;
        Ok(mk)
    }
}

impl<'a> TryDecodeFrom<'a> for Multikey {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> std::result::Result<(Self, &'a [u8]), Self::Error> {
        // ensure the first varuint is the multikey sigil
        let (sigil, ptr) = Codec::try_decode_from(bytes)?;
        if sigil != SIGIL {
            return Err(Error::MissingSigil);
        }

        // decode the key codec
        let (codec, ptr) = Codec::try_decode_from(ptr)?;

        // decode the encrypted flag
        let (encrypted, ptr) = u8::try_decode_from(ptr)?;

        // decode the number of codec-specific values
        let (num_cv, ptr) = usize::try_decode_from(ptr)?;

        let (codec_values, ptr) = match num_cv {
            0 => (Vec::default(), ptr),
            _ => {
                // decode the codec-specific values
                let mut codec_values = Vec::with_capacity(num_cv);
                let mut p = ptr;
                for _ in 0..num_cv {
                    let (cv, ptr) = u128::try_decode_from(p)?;
                    codec_values.push(cv);
                    p = ptr;
                }
                (codec_values, p)
            }
        };

        // decode the number of data units
        let (num_du, ptr) = usize::try_decode_from(ptr)?;

        let (data_units, ptr) = match num_du {
            0 => (Vec::default(), ptr),
            _ => {
                // decode the data units
                let mut data_units = Vec::with_capacity(num_du);
                let mut p = ptr;
                for _ in 0..num_du {
                    let (du, ptr) = DataUnit::try_decode_from(p)?;
                    data_units.push(du);
                    p = ptr;
                }
                (data_units, p)
            }
        };

        Ok((
            Self {
                codec,
                string_encoding: Base::Base16Lower,
                encrypted,
                codec_values,
                data_units,
            },
            ptr,
        ))
    }
}

impl TryFrom<&PublicKey> for Multikey {
    type Error = Error;

    fn try_from(sshkey: &PublicKey) -> std::result::Result<Self, Self::Error> {
        use ssh_key::Algorithm::*;
        match sshkey.algorithm() {
            Ecdsa { curve } => {
                use EcdsaCurve::*;
                let (bytes, codec) = match curve {
                    NistP256 => {
                        if let KeyData::Ecdsa(EcdsaPublicKey::NistP256(point)) = sshkey.key_data() {
                            (point.as_bytes(), Codec::P256Pub)
                        } else {
                            return Err(Error::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            ));
                        }
                    }
                    NistP384 => {
                        if let KeyData::Ecdsa(EcdsaPublicKey::NistP384(point)) = sshkey.key_data() {
                            (point.as_bytes(), Codec::P384Pub)
                        } else {
                            return Err(Error::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            ));
                        }
                    }
                    NistP521 => {
                        if let KeyData::Ecdsa(EcdsaPublicKey::NistP521(point)) = sshkey.key_data() {
                            (point.as_bytes(), Codec::P521Pub)
                        } else {
                            return Err(Error::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            ));
                        }
                    }
                };
                Ok(Builder::new(codec)
                    .with_comment(sshkey.comment())
                    .with_string_encoding(Base::Base16Lower)
                    .with_key_bytes(&bytes)
                    .try_build()
                    .map_err(|_| {
                        Error::PublicKeyFailure("failed to build public key".to_string())
                    })?)
            }
            Ed25519 => {
                let bytes = match sshkey.key_data() {
                    KeyData::Ed25519(e) => e.0,
                    _ => return Err(Error::UnsupportedAlgorithm(sshkey.algorithm().to_string())),
                };
                Ok(Builder::new(Codec::Ed25519Pub)
                    .with_comment(sshkey.comment())
                    .with_string_encoding(Base::Base16Lower)
                    .with_key_bytes(&bytes)
                    .try_build()
                    .map_err(|_| {
                        Error::PublicKeyFailure("failed to build public key".to_string())
                    })?)
            }
            _ => Err(Error::UnsupportedAlgorithm(sshkey.algorithm().to_string())),
        }
    }
}

impl TryInto<PublicKey> for Multikey {
    type Error = Error;

    fn try_into(self) -> std::result::Result<PublicKey, Self::Error> {
        match self.codec {
            Codec::P256Pub => {
                if let Some(du) = self.data_units.get(KEY) {
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
                if let Some(du) = self.data_units.get(KEY) {
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
                if let Some(du) = self.data_units.get(KEY) {
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
                let key_data = match self.data_units.get(KEY) {
                    Some(du) => {
                        let point: [u8; 32] = du.as_ref()[..32].try_into()?;
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

impl TryFrom<&PrivateKey> for Multikey {
    type Error = Error;

    fn try_from(sshkey: &PrivateKey) -> std::result::Result<Self, Self::Error> {
        use ssh_key::Algorithm::*;
        match sshkey.algorithm() {
            Ecdsa { curve } => {
                use EcdsaCurve::*;
                let (bytes, codec) = match curve {
                    NistP256 => {
                        if let KeypairData::Ecdsa(EcdsaKeypair::NistP256 { private, .. }) =
                            sshkey.key_data()
                        {
                            (private.as_slice(), Codec::P256Priv)
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
                            (private.as_slice(), Codec::P384Priv)
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
                            (private.as_slice(), Codec::P521Priv)
                        } else {
                            return Err(Error::UnsupportedAlgorithm(
                                sshkey.algorithm().to_string(),
                            ));
                        }
                    }
                };
                Ok(Builder::new(codec)
                    .with_comment(sshkey.comment())
                    .with_string_encoding(Base::Base16Lower)
                    .with_key_bytes(&bytes)
                    .try_build()
                    .map_err(|_| {
                        Error::PrivateKeyFailure("failed to build private key".to_string())
                    })?)
            }
            Ed25519 => {
                let bytes = match sshkey.key_data() {
                    KeypairData::Ed25519(e) => e.private.to_bytes(),
                    _ => return Err(Error::UnsupportedAlgorithm(sshkey.algorithm().to_string())),
                };
                Ok(Builder::new(Codec::Ed25519Priv)
                    .with_comment(sshkey.comment())
                    .with_string_encoding(Base::Base16Lower)
                    .with_key_bytes(&bytes)
                    .try_build()
                    .map_err(|_| {
                        Error::PrivateKeyFailure("failed to build private key".to_string())
                    })?)
            }
            _ => Err(Error::UnsupportedAlgorithm(sshkey.algorithm().to_string())),
        }
    }
}

/// Multikey builder constructs private keys only. If you need a public key you
/// must first generate a priate key and then get the public key from that.
#[derive(Clone, Debug, Default)]
pub struct Builder {
    codec: Codec,
    string_encoding: Option<Base>,
    comment: Option<String>,
    key_bytes: Option<Vec<u8>>,
}

impl Builder {
    /// create a new multikey with the given codec
    pub fn new(codec: Codec) -> Self {
        Builder {
            codec,
            ..Default::default()
        }
    }

    /// add an encoding
    pub fn with_string_encoding(mut self, base: Base) -> Self {
        self.string_encoding = Some(base);
        self
    }

    /// add a comment
    pub fn with_comment(mut self, comment: &str) -> Self {
        self.comment = Some(comment.to_string());
        self
    }

    /// add key bytes
    pub fn with_key_bytes(mut self, bytes: &impl AsRef<[u8]>) -> Self {
        self.key_bytes = Some(bytes.as_ref().to_vec());
        self
    }

    /// build a key using key bytes
    pub fn try_build(self) -> Result<Multikey> {
        let comment = DataUnit::new(&self.comment.unwrap_or_default());
        let key_data = DataUnit::new(&self.key_bytes.ok_or(Error::MissingKey)?);
        let mut data_units = Vec::with_capacity(2);
        data_units.push(comment);
        data_units.push(key_data);

        Ok(Multikey {
            codec: self.codec,
            string_encoding: Base::Base16Lower,
            encrypted: 0u8,
            codec_values: Vec::default(),
            data_units,
        })
    }

    /// build a random private key
    pub fn try_build_random(self, rng: &mut (impl RngCore + CryptoRng)) -> Result<Multikey> {
        let mut mk = match self.codec {
            Codec::Ed25519Priv => {
                let key_pair = Ed25519Keypair::random(rng);
                let key_data = KeypairData::Ed25519(key_pair);
                let sshkey = PrivateKey::new(key_data, self.comment.unwrap_or_default())?;
                Multikey::try_from(&sshkey)?
            }
            Codec::P256Priv => {
                let key_pair = EcdsaKeypair::random(rng, EcdsaCurve::NistP256)?;
                let key_data = KeypairData::Ecdsa(key_pair);
                let sshkey = PrivateKey::new(key_data, self.comment.unwrap_or_default())?;
                Multikey::try_from(&sshkey)?
            }
            Codec::P384Priv => {
                let key_pair = EcdsaKeypair::random(rng, EcdsaCurve::NistP384)?;
                let key_data = KeypairData::Ecdsa(key_pair);
                let sshkey = PrivateKey::new(key_data, self.comment.unwrap_or_default())?;
                Multikey::try_from(&sshkey)?
            }
            Codec::P521Priv => {
                let key_pair = EcdsaKeypair::random(rng, EcdsaCurve::NistP521)?;
                let key_data = KeypairData::Ecdsa(key_pair);
                let sshkey = PrivateKey::new(key_data, self.comment.unwrap_or_default())?;
                Multikey::try_from(&sshkey)?
            }
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
            _ => anyhow::bail!(Error::UnsupportedCodec(self.codec)),
        };
        mk.set_string_encoding(self.string_encoding.unwrap_or(Base::Base16Lower));
        Ok(mk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encdec::{cipher, pbkdf};

    #[test]
    fn test_simple() {
        let mk = Multikey::default();
        let v = mk.encode_into();
        assert_eq!(7, v.len());
    }

    #[test]
    fn test_encryption_roundtrip() {
        let mut rng = rand::rngs::OsRng::default();
        let mk1 = Builder::new(Codec::Ed25519Priv)
            .with_comment("test key")
            .try_build_random(&mut rng)
            .unwrap();

        assert_eq!(false, mk1.is_encrypted());
        assert_eq!(mk1.codec_values.len(), 0);
        assert_eq!(mk1.data_units.len(), 2);

        let mk2 = {
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
            mk2.encrypt(kdf, cipher, "for great justice, move every zig!")
                .unwrap();
            mk2
        };

        assert_eq!(true, mk2.is_encrypted());
        assert_eq!(mk2.codec_values.len(), 6);
        assert_eq!(mk2.data_units.len(), 4);

        let mk3 = {
            let kdf = pbkdf::Builder::default()
                .from_multikey(&mk2)
                .try_build()
                .unwrap();

            let cipher = cipher::Builder::default()
                .from_multikey(&mk2)
                .try_build()
                .unwrap();

            let mut mk3 = mk2.clone();
            mk3.decrypt(kdf, cipher, "for great justice, move every zig!")
                .unwrap();
            mk3
        };

        assert_eq!(false, mk3.is_encrypted());
        assert_eq!(mk3.codec_values.len(), 0);
        assert_eq!(mk3.data_units.len(), 2);

        // ensure the round trip worked
        assert_eq!(mk1, mk3);
    }

    #[test]
    fn test_from_ssh_pubkey() {
        let mut rng = rand::rngs::OsRng::default();
        let pk = Builder::new(Codec::Ed25519Priv)
            .with_comment("test key")
            .with_string_encoding(Base::Base16Lower)
            .try_build_random(&mut rng)
            .unwrap();

        // try to get the associated public key
        let mk = pk.public_key().unwrap();

        assert_eq!(mk.codec, Codec::Ed25519Pub);
        assert_eq!(mk.comment().unwrap(), "test key".to_string());
        assert_eq!(mk.data_units.len(), 2);
        assert_eq!(mk.data_units[1].len(), 32);
    }

    #[test]
    fn test_from_ssh_privkey() {
        let mut rng = rand::rngs::OsRng::default();
        let mk = Builder::new(Codec::Ed25519Priv)
            .with_comment("test key")
            .try_build_random(&mut rng)
            .unwrap();

        assert_eq!(mk.codec, Codec::Ed25519Priv);
        assert_eq!(mk.comment().unwrap(), "test key".to_string());
        assert_eq!(mk.data_units.len(), 2);
        assert_eq!(mk.data_units[1].len(), 32);
    }

    #[test]
    fn test_pub_from_string() {
        let s = "z3ANSLZwn9GEMLp4EmVzgC5jjqPe35pxqcU5m4UE5wQ55gtXgozs5KQxjRZ8XGHZqDD".to_string();
        let mk = Multikey::try_from(s).unwrap();
        assert_eq!(mk.codec, Codec::Ed25519Pub);
        assert_eq!(mk.string_encoding(), Base::Base58Btc);
        assert_eq!(mk.comment().unwrap(), "test key".to_string());
        assert_eq!(mk.data_units.len(), 2);
        assert_eq!(mk.data_units[1].len(), 32);
    }

    #[test]
    fn test_priv_from_string() {
        let s = "bhkacmaaaaiehizltoqqgwzlzebb56sjufecb4iojcvqmb7epi7rbfqufuvisdjijrjdpljkm5esnu"
            .to_string();
        let mk = Multikey::try_from(s).unwrap();
        assert_eq!(mk.codec, Codec::Ed25519Priv);
        assert_eq!(mk.string_encoding(), Base::Base32Lower);
        assert_eq!(mk.comment().unwrap(), "test key".to_string());
        assert_eq!(mk.data_units.len(), 2);
        assert_eq!(mk.data_units[1].len(), 32);
    }

    #[test]
    fn test_pub_from_vec() {
        let b = hex::decode("3aed010000020874657374206b6579201cfed95aa8daba98d1a7116722bf6b3ae4c035c941c36066e246b01585e834a8").unwrap();
        let mk = Multikey::try_from(b).unwrap();
        assert_eq!(mk.codec, Codec::Ed25519Pub);
        assert_eq!(mk.string_encoding(), Base::Base16Lower);
        assert_eq!(mk.comment().unwrap(), "test key".to_string());
        assert_eq!(mk.data_units.len(), 2);
        assert_eq!(mk.data_units[1].len(), 32);
    }

    #[test]
    fn test_priv_from_vec() {
        let b = hex::decode("3a80260000020874657374206b657920fa87fe4afd223a2560972ea13f9d6223ad955f10a334b1fb6ef5ce6bff4d9dbd").unwrap();
        let mk = Multikey::try_from(b).unwrap();
        assert_eq!(mk.codec, Codec::Ed25519Priv);
        assert_eq!(mk.string_encoding(), Base::Base16Lower);
        assert_eq!(mk.comment().unwrap(), "test key".to_string());
        assert_eq!(mk.data_units.len(), 2);
        assert_eq!(mk.data_units[1].len(), 32);
    }
}
