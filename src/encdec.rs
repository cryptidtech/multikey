/// cipher implementations
pub mod cipher;
pub use cipher::Cipher;

/// key derivation function implementations
pub mod pbkdf;
pub use pbkdf::Pbkdf;

use crate::{mk::Multikey, Result};
use zeroize::Zeroizing;

/// Trait for abstracting private key encryption/decryption. The protocol is
/// that for Multkey's, the codec_values encodes the encryption parameters. The
/// first value in codec_values is the codec for the secret key encryption
/// algorithm ad the rest specify the algorithm specific parameters.
pub trait EncDec {
    /// Decrypt the data unit and return the decrypted data unit.
    fn decrypt(&self, mk: &mut Multikey, key: Zeroizing<Vec<u8>>) -> Result<()>;

    /// Encrypt the data unit and return the encrypted data unit.
    fn encrypt(&self, mk: &mut Multikey, key: Zeroizing<Vec<u8>>) -> Result<()>;
}

/// Trait for abstracting key derivation functions.
pub trait Kdf {
    /// Derive a key from a passphrase, return the salt as a DataUnit and the
    /// key as a zeroizing vector of bytes
    fn derive(&self, mk: &mut Multikey, passphrase: impl AsRef<[u8]>)
        -> Result<Zeroizing<Vec<u8>>>;
}
