#![allow(dead_code)]

use chacha20poly1305::{
    aead::{AeadCore, AeadInPlace, KeyInit},
    ChaCha20Poly1305,
};
use rand::{rngs::OsRng, RngCore};

fn main() -> anyhow::Result<()> {
    let key = ChaCha20Poly1305::generate_key(&mut OsRng);
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let mut pkey = [0u8; 32];
    OsRng.fill_bytes(&mut pkey);
    let mut buffer = Vec::with_capacity(32);
    buffer.extend_from_slice(&pkey);
    if cipher.encrypt_in_place(&nonce, b"", &mut buffer).is_err() {
        anyhow::bail!("failed to encrypt!");
    }
    println!("ciphertext: ({}) {}", buffer.len(), hex::encode(&buffer));
    Ok(())
}
