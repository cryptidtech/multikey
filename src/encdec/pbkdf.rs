use crate::{du::DataUnit, encdec::Kdf, error::Error, mk::Multikey, Result};
use multicodec::codec::Codec;
use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;

/// Several useful KDF methods
#[non_exhaustive]
pub enum Pbkdf {
    /// Bcrypt KDF parameters
    Bcrypt {
        /// the rounds for the key derivation
        rounds: u32,
        /// the salt index
        salt: Vec<u8>,
    },
}

impl Kdf for Pbkdf {
    fn derive(
        &self,
        mk: &mut Multikey,
        passphrase: impl AsRef<[u8]>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        match self {
            Pbkdf::Bcrypt { rounds, salt } => {
                let mut out = [0u8; 32];
                bcrypt_pbkdf::bcrypt_pbkdf(passphrase, salt, *rounds, &mut out)?;
                mk.codec_values.push(Codec::BcryptPbkdf.into());
                mk.codec_values.push(*rounds as u128); // rounds
                mk.codec_values.push(mk.data_units.len() as u128); // index of the salt data unit
                mk.data_units.push(DataUnit::new(salt));
                Ok(out.to_vec().into())
            }
        }
    }
}

/// Builder for Pbkdf impl
///
/// There are two ways to use this Builder:
/// 1. When deriving a key for an unencrypted Multikey:
///
///    let rng = rand::rngs::OsRng::default()
///    let kdf = pbkdf::Builder::new(Codec::BcryptPbkdf)
///        .with_random_salt(&rng)
///        .with_rounds(10)
///        .try_build()?;
///
/// 2. When deriving a key for an encrypted Multikey:
///
///    let rng = rand::rngs::OsRng::default()
///    let cipher = Builder::default()
///        .from_multikey(&mk) // init codec, rounds and salt
///        .try_build()?;
///
#[derive(Clone, Debug, Default)]
pub struct Builder {
    codec: Codec,
    rounds: Option<u32>,
    salt: Option<Vec<u8>>,
}

impl Builder {
    /// create the builder with the codec
    pub fn new(codec: Codec) -> Self {
        Builder {
            codec,
            ..Default::default()
        }
    }

    /// initialize the builder from the Multikey
    pub fn from_multikey(mut self, mk: &Multikey) -> Self {
        if mk.is_encrypted() {
            // go through the codec values looking for an encryption codec and its
            // cipher parameters
            'values: for i in 0..mk.codec_values.len() {
                let codec = match Codec::try_from(mk.codec_values[i]) {
                    Ok(c) => c,
                    Err(_) => continue 'values,
                };
                match codec {
                    Codec::BcryptPbkdf => {
                        // set the codec
                        self.codec = codec;

                        // i + 1 is the number of rounds
                        if let Some(rounds) = mk.codec_values.get(i + 1) {
                            self.rounds = Some(*rounds as u32);
                        }

                        // i + 2 is the index of the salt data
                        if let Some(salt_idx) = mk.codec_values.get(i + 2) {
                            if let Some(salt) = mk.data_units.get(*salt_idx as usize) {
                                self.salt = Some(salt.as_ref().to_vec());
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        self
    }

    /// add a random salt for the kdf
    pub fn with_random_salt(mut self, rng: &mut (impl RngCore + CryptoRng)) -> Self {
        match self.codec {
            Codec::BcryptPbkdf => {
                let mut buf = [0u8; 32];
                rng.fill_bytes(&mut buf);
                self.salt = Some(buf.to_vec());
            }
            _ => self.salt = None,
        }
        self
    }

    /// add the salt for the kdf
    pub fn with_salt(mut self, salt: impl AsRef<[u8]>) -> Self {
        self.salt = Some(salt.as_ref().to_vec());
        self
    }

    /// add the number of rounds if needed
    pub fn with_rounds(mut self, rounds: u32) -> Self {
        self.rounds = Some(rounds);
        self
    }

    /// build the pbkdf
    pub fn try_build(self) -> Result<Pbkdf> {
        Ok(match self.codec {
            Codec::BcryptPbkdf => Pbkdf::Bcrypt {
                rounds: self
                    .rounds
                    .ok_or(Error::PbkdfFailed("missing rounds".to_string()))?,
                salt: self
                    .salt
                    .ok_or(Error::PbkdfFailed("missing salt".to_string()))?,
            },
            _ => anyhow::bail!(Error::UnsupportedKdf(self.codec)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bcrypt() {
        let kdf = Builder::new(Codec::BcryptPbkdf)
            .with_rounds(10)
            .with_salt(
                hex::decode("8bb78be51ac7cc98f44e38947ff8a128764ec039b89687a790dfa8444ba97682")
                    .unwrap(),
            )
            .try_build()
            .unwrap();
        let mut mk = Multikey {
            codec: Codec::Ed25519Pub,
            ..Default::default()
        };
        let key = kdf
            .derive(&mut mk, "for great justice, move every zig!")
            .unwrap();
        assert_eq!(
            hex::encode(&key),
            "776d0ddd8c1a58b387117719b0630502cb195210a1f6b08b0865ae07f043ed6b"
        );
        assert_eq!(mk.codec_values.len(), 3);
        assert_eq!(mk.data_units.len(), 1);
    }
}
