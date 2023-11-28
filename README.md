# Multikey

A rust implementation of a
[multiformats](https://github.com/multiformats/multiformats) cryptographic key
library.

## Current Status

This version of the mulikey specification supports both public key and secret
key cryptography keys. For public key cryptography, it supports public and
private keys for Ed25519, and Ecdsa using the Nist P256, Nist P384, and Nist
P521 curves. Adding more will require adding sigils to multicodec for the
codecs. For secret key cryptography, it supports AES128, AES192, AES256,
ChaCha-128, and ChaCha-256 keys.

## Multikey v1 Format 

```
multikey   encrypted   count of codec-         count of key         variable number
sigil       boolean   specific varuints         data units        of data unit octets 
|                 \          |                      |                     |
v                  v         v                      v                  /-----\
0x3a <varuint> <varuint> <varuint> N(<varuint>) <varuint> N(<varuint> N(OCTET))
         ^                          \---------/            \-- ^ -------------/
         |                              |                      |            |
      key codec                  variable number        count of data   variable number
                                of codec-specific        unit octets    of data units
                                      values
```

The multicodec varuint sigil for a multikey encoded key is `0x3a`. Immediately
following the sigil is a varuint encoded multicodec value for the encryption
key codec (e.g. `0xed` for an Ed25519 public key). Following the key codec is a
varuint number signifying the number of codec specific values. These contain
things like key encryption or key derivation parameters. After the codec-
specific values is a varuint specifying the number of key "data units" in this
multikey. Each data unit is a piece of key data. For instance an RSA public key
contains two data units: the RSA public exponent and the RSA modulus. Each data
unit consists of a varuint encoded octet count followed by the octets of the
data.

### Key Comments

By convention, the first data unit of every multikey contains the comment 
associated with the key. If there is no comment set, the data unit has a 
count varuint of 0 and no octets following the count.

## Private Keys

Private keys are sensitive and should always be kept encrypted when at rest,
the codec-specific varuint values specify the key encryption algorithm and any 
other related parameters such as a key derivation function and its parameters.

### An example of storing an encrypted Ed25519 private key

In this example we will show how to safely store an Ed25519 private key 
encrypted using the ChaCha20-Poly1305 AEAD symmetric encryption algorithm using
a key derived using the Bcrypt PBKDF function with 10 rounds and a 32-byte 
salt value. Here is how the multikey is encoded:

```
0x3a                -- varuint, multikey sigil 
0x1300              -- varuint, Ed25519 private key codec 
0x01                -- varuint, boolean if it is encrypted or not
0x06                -- varuint, 6 codec-specific varuint values 
    0xd00d          -- varuint, Bcrypt PBKDF key derivation function
        0x0a        -- varuint, Bcrypt PBKDF rounds
        0x03        -- varuint, data unit index of salt
    0xa5            -- varuint, ChaCha20-Poly1305 symmetric key encryption
        0x01        -- varuint, data unit index of nonce
        0x02        -- varuint, data unit index of ciphertext
0x04                -- varuint, 4 data units
    0x09            -- varuint, 9 bytes of comment data
        "multikey!" -- 9 octets of utf-8 comment data
    0x20            -- varuint, 32 octets of Bcrypt PBKDF salt data
        [32 octets] -- Bcrypt PBKDF salt data
    0x08            -- varuint, 12 octets of the ChaCha20-Poly1305 nonce
        [8 octets]  -- ChaCha20-Poly1305 nonce bytes
    0x30            -- varuint, 48 octets of ciphertext
        [48 octets] -- ciphertext
```

In this example the encoding starts off with the multikey sigil (`0x3a`)
followed by the varuint codec value for an Ed25519 private key (`0x1300`).
There are six codec-specific values (`0x06`) specifying the key encryption
algorithm as ChaCha20-Poly1305 (`0xa5`) and that the key is derived from a
passphrase using the Bcrypt PBKDF algorithm (`0xd00d`) with 10 rounds (`0x0a`).
The extra values are for specifying the indices in the list of data units for 
the various values needed for the key derivation and the decryption.

The encoding has three data units (`0x03`), the Bcrypt PBKDF salt, the
ChaCha20-Poly1305 nonce and the ciphertext itself. With all of this data, any
consuming tool can ask the user for the passphrase, run it through a 10 round
Bcrypt PBKDF algorithm with the given salt to recreate the ChaCha20-Poly1305
encryption key. Then using the encryption key and the nonce, the ciphertext can
be decrypted to the private key data.
