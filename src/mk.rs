use crate::{
    du::DataUnit,
    encdec::{EncDec, Kdf},
    error::Error,
    Result,
};
use multicodec::codec::Codec;
use multiutil::{EncodeInto, TryDecodeFrom};
use std::fmt;

/// the multicodec sigil for multikey
pub const SIGIL: Codec = Codec::Multikey;

// the index of the comment data unit
const COMMENT: usize = 0;

/// The main multikey structure
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Multikey {
    /// The key codec
    pub codec: Codec,

    /// if the key is encrypted
    pub encrypted: u8,

    /// The codec-specific values
    pub codec_values: Vec<u128>,

    /// The data units for the key
    pub data_units: Vec<DataUnit>,
}

impl Multikey {
    /// whether or not this is a secret key
    pub fn is_secret_key(&self) -> bool {
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

    /// is this multikey encrypted?
    pub fn is_encrypted(&self) -> bool {
        self.encrypted != 0u8
    }

    /// encrypt this multikey
    pub fn encrypt(
        &mut self,
        kdf: impl Kdf,
        cipher: impl EncDec,
        passphrase: impl AsRef<[u8]>,
    ) -> Result<()> {
        if !self.is_secret_key() {
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
        if !self.is_secret_key() {
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

impl fmt::Display for Multikey {
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

impl Into<Vec<u8>> for Multikey {
    fn into(self) -> Vec<u8> {
        self.encode_into()
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
            Ok((_, v)) => {
                let (mk, _) = Self::try_decode_from(v.as_slice())?;
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
                encrypted,
                codec_values,
                data_units,
            },
            ptr,
        ))
    }
}

impl TryFrom<&ssh_key::PublicKey> for Multikey {
    type Error = Error;

    fn try_from(sshkey: &ssh_key::PublicKey) -> std::result::Result<Self, Self::Error> {
        use ssh_key::Algorithm::*;
        match sshkey.algorithm() {
            Ecdsa { curve } => {
                use ssh_key::EcdsaCurve::*;

                let encrypted = 0u8;
                let mut data_units = Vec::with_capacity(2);
                data_units.push(DataUnit::new(&sshkey.comment().as_bytes()));

                let codec = match curve {
                    NistP256 => {
                        data_units.push(match sshkey.key_data() {
                            ssh_key::public::KeyData::Ecdsa(e) => {
                                use ssh_key::public::EcdsaPublicKey::*;
                                match e {
                                    NistP256(point) => DataUnit::new(&point.as_bytes()),
                                    _ => {
                                        return Err(Error::UnsupportedAlgorithm(
                                            sshkey.algorithm().to_string(),
                                        ))
                                    }
                                }
                            }
                            _ => {
                                return Err(Error::UnsupportedAlgorithm(
                                    sshkey.algorithm().to_string(),
                                ))
                            }
                        });
                        Codec::P256Pub
                    }
                    NistP384 => {
                        data_units.push(match sshkey.key_data() {
                            ssh_key::public::KeyData::Ecdsa(e) => {
                                use ssh_key::public::EcdsaPublicKey::*;
                                match e {
                                    NistP384(point) => DataUnit::new(&point.as_bytes()),
                                    _ => {
                                        return Err(Error::UnsupportedAlgorithm(
                                            sshkey.algorithm().to_string(),
                                        ))
                                    }
                                }
                            }
                            _ => {
                                return Err(Error::UnsupportedAlgorithm(
                                    sshkey.algorithm().to_string(),
                                ))
                            }
                        });
                        Codec::P384Pub
                    }
                    NistP521 => {
                        data_units.push(match sshkey.key_data() {
                            ssh_key::public::KeyData::Ecdsa(e) => {
                                use ssh_key::public::EcdsaPublicKey::*;
                                match e {
                                    NistP521(point) => DataUnit::new(&point.as_bytes()),
                                    _ => {
                                        return Err(Error::UnsupportedAlgorithm(
                                            sshkey.algorithm().to_string(),
                                        ))
                                    }
                                }
                            }
                            _ => {
                                return Err(Error::UnsupportedAlgorithm(
                                    sshkey.algorithm().to_string(),
                                ))
                            }
                        });
                        Codec::P521Pub
                    }
                };
                let codec_values = Vec::default();
                Ok(Self {
                    codec,
                    encrypted,
                    codec_values,
                    data_units,
                })
            }
            Ed25519 => {
                let codec = Codec::Ed25519Pub;
                let encrypted = 0u8;
                let codec_values = Vec::default();
                let mut data_units = Vec::with_capacity(2);
                data_units.push(DataUnit::new(&sshkey.comment().as_bytes()));
                data_units.push(match sshkey.key_data() {
                    ssh_key::public::KeyData::Ed25519(e) => DataUnit::new(&e.0),
                    _ => return Err(Error::UnsupportedAlgorithm(sshkey.algorithm().to_string())),
                });

                Ok(Self {
                    codec,
                    encrypted,
                    codec_values,
                    data_units,
                })
            }
            _ => Err(Error::UnsupportedAlgorithm(sshkey.algorithm().to_string())),
        }
    }
}

impl TryFrom<&ssh_key::PrivateKey> for Multikey {
    type Error = Error;

    fn try_from(sshkey: &ssh_key::PrivateKey) -> std::result::Result<Self, Self::Error> {
        use ssh_key::Algorithm::*;
        match sshkey.algorithm() {
            Ecdsa { curve } => {
                use ssh_key::EcdsaCurve::*;

                let encrypted = 0u8;
                let mut data_units = Vec::with_capacity(2);
                data_units.push(DataUnit::new(&sshkey.comment().as_bytes()));

                let codec = match curve {
                    NistP256 => {
                        data_units.push(match sshkey.key_data() {
                            ssh_key::private::KeypairData::Ecdsa(e) => {
                                use ssh_key::private::EcdsaKeypair::*;
                                match e {
                                    NistP256 { public: _, private } => {
                                        DataUnit::new(&private.as_slice())
                                    }
                                    _ => {
                                        return Err(Error::UnsupportedAlgorithm(
                                            sshkey.algorithm().to_string(),
                                        ))
                                    }
                                }
                            }
                            _ => {
                                return Err(Error::UnsupportedAlgorithm(
                                    sshkey.algorithm().to_string(),
                                ))
                            }
                        });
                        Codec::P256Priv
                    }
                    NistP384 => {
                        data_units.push(match sshkey.key_data() {
                            ssh_key::private::KeypairData::Ecdsa(e) => {
                                use ssh_key::private::EcdsaKeypair::*;
                                match e {
                                    NistP384 { public: _, private } => {
                                        DataUnit::new(&private.as_slice())
                                    }
                                    _ => {
                                        return Err(Error::UnsupportedAlgorithm(
                                            sshkey.algorithm().to_string(),
                                        ))
                                    }
                                }
                            }
                            _ => {
                                return Err(Error::UnsupportedAlgorithm(
                                    sshkey.algorithm().to_string(),
                                ))
                            }
                        });
                        Codec::P384Priv
                    }
                    NistP521 => {
                        data_units.push(match sshkey.key_data() {
                            ssh_key::private::KeypairData::Ecdsa(e) => {
                                use ssh_key::private::EcdsaKeypair::*;
                                match e {
                                    NistP521 { public: _, private } => {
                                        DataUnit::new(&private.as_slice())
                                    }
                                    _ => {
                                        return Err(Error::UnsupportedAlgorithm(
                                            sshkey.algorithm().to_string(),
                                        ))
                                    }
                                }
                            }
                            _ => {
                                return Err(Error::UnsupportedAlgorithm(
                                    sshkey.algorithm().to_string(),
                                ))
                            }
                        });
                        Codec::P521Priv
                    }
                };
                let codec_values = Vec::default();
                Ok(Self {
                    codec,
                    encrypted,
                    codec_values,
                    data_units,
                })
            }
            Ed25519 => {
                let codec = Codec::Ed25519Priv;
                let encrypted = 0u8;
                let codec_values = Vec::default();
                let mut data_units = Vec::with_capacity(2);
                data_units.push(DataUnit::new(&sshkey.comment().as_bytes()));
                data_units.push(match sshkey.key_data() {
                    ssh_key::private::KeypairData::Ed25519(e) => {
                        DataUnit::new(&e.private.to_bytes())
                    }
                    _ => return Err(Error::UnsupportedAlgorithm(sshkey.algorithm().to_string())),
                });

                Ok(Self {
                    codec,
                    encrypted,
                    codec_values,
                    data_units,
                })
            }
            _ => Err(Error::UnsupportedAlgorithm(sshkey.algorithm().to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encdec::{cipher, pbkdf};

    #[test]
    fn test_simple() {
        let mk = Multikey {
            codec: Codec::Ed25519Pub,
            ..Default::default()
        };
        let v = mk.encode_into();
        assert_eq!(6, v.len());
    }

    #[test]
    fn test_encryption_roundtrip() {
        let private = ssh_key::private::Ed25519PrivateKey::random(&mut rand::rngs::OsRng);
        let public = ssh_key::public::Ed25519PublicKey::from(&private);
        let key_pair = ssh_key::private::Ed25519Keypair { public, private };
        let key_data = ssh_key::private::KeypairData::Ed25519(key_pair);
        let sshkey = ssh_key::PrivateKey::new(key_data, "test key").unwrap();
        let mk1 = Multikey::try_from(&sshkey).unwrap();

        assert_eq!(false, mk1.is_encrypted());
        assert_eq!(mk1.codec_values.len(), 0);
        assert_eq!(mk1.data_units.len(), 2);

        let mut rng = rand::rngs::OsRng::default();

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
        let private_key = ssh_key::private::Ed25519PrivateKey::random(&mut rand::rngs::OsRng);
        let public_key = ssh_key::public::Ed25519PublicKey::from(private_key);
        let key_data = ssh_key::public::KeyData::Ed25519(public_key);
        let sshkey = ssh_key::PublicKey::new(key_data, "test key");
        let mk = Multikey::try_from(&sshkey).unwrap();

        assert_eq!(mk.codec, Codec::Ed25519Pub);
        assert_eq!(mk.comment().unwrap(), "test key".to_string());
        assert_eq!(mk.data_units.len(), 2);
        assert_eq!(mk.data_units[1].len(), 32);
    }

    #[test]
    fn test_from_ssh_privkey() {
        let private = ssh_key::private::Ed25519PrivateKey::random(&mut rand::rngs::OsRng);
        let public = ssh_key::public::Ed25519PublicKey::from(&private);
        let key_pair = ssh_key::private::Ed25519Keypair { public, private };
        let key_data = ssh_key::private::KeypairData::Ed25519(key_pair);
        let sshkey = ssh_key::PrivateKey::new(key_data, "test key").unwrap();
        let mk = Multikey::try_from(&sshkey).unwrap();

        assert_eq!(mk.codec, Codec::Ed25519Priv);
        assert_eq!(mk.comment().unwrap(), "test key".to_string());
        assert_eq!(mk.data_units.len(), 2);
        assert_eq!(mk.data_units[1].len(), 32);
    }

    #[test]
    fn test_pub_from_string() {
        /*
        let key = hex::decode("0a497dbeb4e1c683d0814dd9c0251526c39ee14fb9e340853197beaf6db96233")
            .unwrap();
        let mut data_units = Vec::with_capacity(2);
        let du = DataUnit::new(&"test key");
        data_units.push(du);
        data_units.push(DataUnit::new(&key));

        let mk = Multikey {
            codec: Codec::Ed25519Pub,
            encrypted: 0u8,
            codec_values: Vec::default(),
            data_units,
        };

        let data = mk.encode_into();
        let s = multibase::encode(multibase::Base::Base16Lower, data.clone());
        println!("len: {}", s.len());
        println!("{}", s);
        println!("{:x?}", data.as_slice());
        */

        let s = "z3ANSLZwn9GEMLp4EmVzgC5UJSowrdWRcX8KLQXm6b87FXia5Aco478QTgxsPp6oRVU".to_string();
        let mk = Multikey::try_from(s).unwrap();
        assert_eq!(mk.codec, Codec::Ed25519Pub);
        assert_eq!(mk.comment().unwrap(), "test key".to_string());
        assert_eq!(mk.data_units.len(), 2);
        assert_eq!(mk.data_units[1].len(), 32);
    }

    #[test]
    fn test_priv_from_string() {
        /*
        let key = hex::decode("40d42aa5fd7cd7322a194af532dc9cff594c56c487f84cfa589143d7d8ede996")
            .unwrap();
        let mut data_units = Vec::with_capacity(2);
        let du = DataUnit::new(&"test key");
        data_units.push(du);
        data_units.push(DataUnit::new(&key));

        let mk = Multikey {
            codec: Codec::Ed25519Priv,
            encrypted: 0u8,
            codec_values: Vec::default(),
            data_units,
        };

        let data = mk.encode_into();
        let s = multibase::encode(multibase::Base::Base16Lower, data.clone());
        println!("len: {}", s.len());
        println!("{}", s);
        println!("{:x?}", data.as_slice());
        */

        let s = "z39TxyoL2wjMbcVuaxduRsCaDfQzcgdMScps6kcGLUct6pF4wKvLQz3Jh5S4FkubWmT".to_string();
        let mk = Multikey::try_from(s).unwrap();
        assert_eq!(mk.codec, Codec::Ed25519Priv);
        assert_eq!(mk.comment().unwrap(), "test key".to_string());
        assert_eq!(mk.data_units.len(), 2);
        assert_eq!(mk.data_units[1].len(), 32);
    }

    #[test]
    fn test_pub_from_vec() {
        let b = hex::decode("3aed010000020874657374206b6579200a497dbeb4e1c683d0814dd9c0251526c39ee14fb9e340853197beaf6db96233").unwrap();
        let mk = Multikey::try_from(b).unwrap();
        assert_eq!(mk.codec, Codec::Ed25519Pub);
        assert_eq!(mk.comment().unwrap(), "test key".to_string());
        assert_eq!(mk.data_units.len(), 2);
        assert_eq!(mk.data_units[1].len(), 32);
    }

    #[test]
    fn test_priv_from_vec() {
        let b = hex::decode("3a80260000020874657374206b6579200a497dbeb4e1c683d0814dd9c0251526c39ee14fb9e340853197beaf6db96233").unwrap();
        let mk = Multikey::try_from(b).unwrap();
        assert_eq!(mk.codec, Codec::Ed25519Priv);
        assert_eq!(mk.comment().unwrap(), "test key".to_string());
        assert_eq!(mk.data_units.len(), 2);
        assert_eq!(mk.data_units[1].len(), 32);
    }
}
