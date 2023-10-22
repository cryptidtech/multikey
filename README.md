# Multikey

A rust implementation of a
[multiformats](https://github.com/multiformats/multiformats) cryptographic key
library.

## Multikey v1 Format 

```
multikey     X number of codec-      Y number of key       variable number
sigil        specific varuints         data units        of data unit octets 
|                  |                      |                     |
v                  v                      v                     v
0x3a <varuint> <varuint> X(<varuint>) <varuint> Y(<varuint> Z(OCTET))
         ^                    ^                      ^
         |                    |                      |
      key codec        variable number        Z number of data
                      of codec-specific        unit octets
                            values
```

The multicodec varuint sigil for a multikey encoded key is `0x3a`. Immediately
following the sigil is a varuint encoded multicodec value for the encryption
key codec (e.g. `0xed` for an Ed25519 public key). Following the key codec is a
varuint number signifying the number of codec specific values. These contain
things like key encryption or key derivation parameters. After the codec-
specific values is a varuint specifying the number of key "data units" in this
multikey. Each data unit is a piece of key data. For instance an RSA public key
contains two data units, one is the RSA public exponent and the other is the
RSA modulus. Each data unit then consists of a varuint encoded octet count
followed by the octets of the data.

## Private Keys

Private keys are sensitive and should always be kept encrypted when at rest,
the codec-specific varuint values specify the key encryption algorithm and any 
other related parameters such as a key derivation function and its parameters.

### An example of storing an encrypted Ed25519 private key

In this example we will show how to safely store an Ed25519 private key 
encrypted using the ChaCha20-Poly1305 AEAD symmetric encryption algorith using 
a key derived using the Bcrypt PBKDF function with 10 rounds and a 32-byte 
salt value. Here is how the multikey is encoded:

```
0x3a                -- varuint, multikey sigil 
0x1300              -- varuint, Ed25519 private key codec 
0x03                -- varuint, 3 codec-specific varuint values 
    0xa5            -- varuint, ChaCha20-Poly1305 symmetric key encryption
    0xd00d          -- varuint, Bcrypt PBKDF key derivation function
        0x0a        -- varuint, Bcrypt PBKDF rounds
0x03                -- varuint, 3 data units
    0x20            -- varuint, 32 octets of Bcrypt PBKDF salt data
        [32 octets] -- Bcrypt PBKDF salt data
    0x0c            -- varuint, 12 octets of the ChaCha20-Poly1305 nonce
        [12 octets] -- ChaCha20-Poly1305 nonce bytes
    0x30            -- varuint, 48 octets of ciphertext
        [48 octets] -- ciphertext
```

In this example the encoding starts off with the multikey sigil (`0x3a`)
followed by the varuint codec value for an Ed25519 private key (`0x1300`).
There are three codec-specific values (`0x03`) specifying the key encryption
algorithm is ChaCha20-Poly1305 (`0xa5`) and that the key is derived from a
passphrase using the Bcrypt PBKDF algorithm (`0xd00d`) with 10 rounds (`0x0a`).

The encoding has three data units (`0x03`), the Bcrypt PBKDF salt, the
ChaCha20-Poly1305 nonce and the ciphertext itself. With all of this data, any
consuming tool can ask the user for the passphrase, run it through a 10 round
Bcrypt PBKDF algorithm with the given salt to recreate the ChaCha20-Poly1305
encryption key. Then using the encryption key and the nonce, the ciphertext can
be decrypted to the private key data.
