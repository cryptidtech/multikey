use crate::{du::DataUnit, encdec::EncDec, error::Error, mk::Multikey, Result};
use multicodec::codec::Codec;
use rand::{CryptoRng, RngCore};
use sodiumoxide::crypto::aead::chacha20poly1305;
use zeroize::Zeroizing;

// the index of the public key or the unencrypted private key
const KEY: usize = 1;

/// Implementations of specific encrypters
#[non_exhaustive]
pub enum Cipher {
    /// Implements the libsodium secret box encryption scheme
    ChaCha20Poly1305 {
        /// the nonce
        nonce: Vec<u8>,
        /// the message to enc/dec
        msg: Vec<u8>,
    },
}

impl EncDec for Cipher {
    fn decrypt(&self, mk: &mut Multikey, key: Zeroizing<Vec<u8>>) -> Result<()> {
        if !mk.is_encrypted() {
            anyhow::bail!(Error::DecryptionFailed(
                "multikey is not encrypted".to_string()
            ));
        }
        match self {
            Cipher::ChaCha20Poly1305 { nonce, msg } => {
                if nonce.len() != chacha20poly1305::NONCEBYTES {
                    anyhow::bail!(Error::NonceError("invalid length".to_string()));
                }
                if key.len() != chacha20poly1305::KEYBYTES {
                    anyhow::bail!(Error::KeyError("invalid length".to_string()));
                }
                let n = chacha20poly1305::Nonce::from_slice(nonce.as_slice())
                    .ok_or(Error::NonceError("from_slice failure".to_string()))?;
                let k = chacha20poly1305::Key::from_slice(key.as_slice())
                    .ok_or(Error::KeyError("from_slice failure".to_string()))?;
                let dec = chacha20poly1305::open(msg.as_slice(), None, &n, &k).map_err(|_| {
                    Error::DecryptionFailed("chacha20poly1305 decryption failed".to_string())
                })?;

                mk.data_units.push(DataUnit::new(&dec));
                mk.encrypted = 0u8;

                Ok(())
            }
        }
    }

    fn encrypt(&self, mk: &mut Multikey, key: Zeroizing<Vec<u8>>) -> Result<()> {
        if mk.is_encrypted() {
            anyhow::bail!(Error::EncryptionFailed(
                "multikey is encrypted alread".to_string()
            ))
        }
        match self {
            Cipher::ChaCha20Poly1305 { nonce, msg } => {
                if nonce.len() != chacha20poly1305::NONCEBYTES {
                    anyhow::bail!(Error::NonceError("invalid length".to_string()));
                }
                if key.len() != chacha20poly1305::KEYBYTES {
                    anyhow::bail!(Error::KeyError("invalid length".to_string()));
                }
                let n = chacha20poly1305::Nonce::from_slice(nonce.as_slice())
                    .ok_or(Error::NonceError("from_slice failure".to_string()))?;
                let k = chacha20poly1305::Key::from_slice(key.as_slice())
                    .ok_or(Error::KeyError("from_slice failure".to_string()))?;
                let enc = chacha20poly1305::seal(msg.as_slice(), None, &n, &k);

                mk.codec_values.push(Codec::Chacha20Poly1305.into());
                mk.codec_values.push(mk.data_units.len() as u128); // index of the nonce data unit
                mk.data_units.push(DataUnit::new(nonce));
                mk.codec_values.push(mk.data_units.len() as u128); // index of the nonce data unit
                mk.data_units.push(DataUnit::new(&enc));
                mk.encrypted = 1u8;

                Ok(())
            }
        }
    }
}

/// Builder for EncDec impl
///
/// There are two ways to use this Builder:
/// 1. When encrypting an unencrypted Multikey, you create the cipher object
///    from the existing Multikey like so:
///
///    let rng = rand::rngs::OsRng::default()
///    let mk = Multikey { codec: Codec::Ed25519Pub, ..Default::default() };
///    let cipher = Builder::new(Codec::Chacha20Poly1305)
///        .from_multikey(&mk) // init the msg with the unencrypted key
///        .with_random_nonce(&rng)
///        .with_key(&key)
///        .try_build()?;
///
/// 2. When decrypting an encrypted Multikey, you create the cipher object
///    from the existing Multikey like so:
///
///    let rng = rand::rngs::OsRng::default()
///    let cipher = Builder::default()
///        .from_multikey(&mk) // init codec, nonce, and msg
///        .try_build()?;
///
#[derive(Clone, Debug, Default)]
pub struct Builder {
    codec: Codec,
    nonce: Option<Vec<u8>>,
    msg: Option<Vec<u8>>,
}

impl Builder {
    /// create a new builder with the codec
    pub fn new(codec: Codec) -> Self {
        Builder {
            codec,
            ..Default::default()
        }
    }

    /// create a new builder from an existing multikey
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
                    Codec::Chacha20Poly1305 => {
                        // set the codec
                        self.codec = codec;

                        // i + 1 is the index of the nonce
                        if let Some(nonce_idx) = mk.codec_values.get(i + 1) {
                            if let Some(nonce) = mk.data_units.get(*nonce_idx as usize) {
                                self.nonce = Some(nonce.as_ref().to_vec());
                            }
                        }

                        // i + 2 is the index of the encrypted key
                        if let Some(msg_idx) = mk.codec_values.get(i + 2) {
                            if let Some(msg) = mk.data_units.get(*msg_idx as usize) {
                                self.msg = Some(msg.as_ref().to_vec());
                            }
                        }
                    }
                    _ => {}
                }
            }
        } else {
            // for unencrypted multikeys we just need to initialize the msg with
            // the unencrypted key data unit
            if let Some(msg) = mk.data_units.get(KEY) {
                self.msg = Some(msg.as_ref().to_vec());
            }
        }
        self
    }

    /// add a random nonce for cipher
    pub fn with_random_nonce(mut self, rng: &mut (impl RngCore + CryptoRng)) -> Self {
        match self.codec {
            Codec::Chacha20Poly1305 => {
                let mut buf = [0u8; chacha20poly1305::NONCEBYTES];
                rng.fill_bytes(&mut buf);
                self.nonce = Some(buf.to_vec());
            }
            _ => self.nonce = None,
        }
        self
    }

    /// add in a pre-determined nonce
    pub fn with_nonce(mut self, nonce: impl AsRef<[u8]>) -> Self {
        self.nonce = Some(nonce.as_ref().to_vec());
        self
    }

    /// build with ciphertext
    pub fn try_build(self) -> Result<Cipher> {
        Ok(match self.codec {
            Codec::Chacha20Poly1305 => Cipher::ChaCha20Poly1305 {
                nonce: self
                    .nonce
                    .ok_or(Error::CipherFailed("missing nonce".to_string()))?,
                msg: self
                    .msg
                    .ok_or(Error::CipherFailed("missing msg".to_string()))?,
            },
            _ => anyhow::bail!(Error::UnsupportedEncryption(self.codec)),
        })
    }
}
