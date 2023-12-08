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
multikey
sigil         key comment
|                  |
v                  v
0x3a <varuint> <comment> <attributes>
         ^                    ^
         |                    |
      key codec         key attributes


<comment> ::= <varbytes>

                         variable number of attributes
                                       |
                            ______________________
                           /                      \
<attributes> ::= <varuint> N(<varuint>, <varbytes>)
                     ^           ^          ^
                    /           /           |
            count of      attribute     attribute
          attributes     identifier       value


<varbytes> ::= <varuint> N(OCTET)
                   ^        ^
                  /          \
          count of            variable number
            octets            of octets
``` 

The multicodec varuint sigil for a multikey encoded key is `0x3a`. Immediately
following the sigil is a varuint encoded key codec (e.g. `0xed` for an Ed25519
public key). Following the key codec the key commment, and finally a variable
number of key attributes. The attributes consist of a variable number of 
identifier and value tuples. Think of this like a map with numerical keys. Each
key codec has a codec-specific set of identifiers for attributes.

This format is designed to support any kind of arbitrarily complex key data in
such a way that tools are able to know exactly how many octets are in the
Multikey data so that it can skip over it if they don't support the key codec.

### Key Comments

By convention, every key has a comment that is easy to extract from the Multikey
data structure by any tool even if they do not support a specific key codec.

## Private Keys

Private keys are sensitive and should always be kept encrypted when at rest.
The attributes in the key specify whether the key is encrypted and which 
encryption method was used as well as the key derivation method and parameters.

### An example of storing an encrypted Ed25519 private key

In this example we will show how a Multikey stores an Ed25519 private key
encrypted using the ChaCha20-Poly1305 AEAD symmetric encryption algorithm using
a key derived using the Bcrypt PBKDF function with 10 rounds and a 32-byte salt
value:

```
3a                  -- varuint, multikey sigil 
[80 26]             -- varuint, Ed25519 private key codec 
08                  -- varuint, length of comment 
  "test key"        -- 8 octets of utf-8 comment data
0a                  -- varuint, 10 attributes
  00                -- varuint, AttrId::KeyIsEncrypted
    01              -- varuint, attribute length
      [01]          -- true, it is encrypted!
  01                -- varuint, AttrId::KeyData
    30              -- varuint, attribute length
      [48 octets]   -- ciphertext
  02                -- varuint, AttrId::CipherCodec
    02              -- varuint, attribute length
      [a5 01]       -- varuint, ChaCha20-Poly1305 codec
  03                -- varuint, AttrId::CipherKeyLen
    01              -- varuint, attribute length
      [20]          -- 32 byte key length
  04                -- varuint, AttrId::CipherNonceLen
    01              -- varuint, attribute length
      [08]          -- 1 octet, 8 byte nonce length
  05                -- varuint, AttrId::CipherNonce
    08              -- varuint, attribute length
      [8 octets]    -- nonce
  06                -- varuint, AttrId::KdfCodec
    03              -- varuint, attribute length
      [8d a0 03]    -- varuint, Bcrypt KDF codec
  07                -- varuint, AttrId::KdfSaltLen
    01              -- varuint, attribute length
      [20]          -- varuint, 32 byte salt length
  08                -- varuint, AttrId::KdfSalt
    20              -- varuint, attribute length
      [32 octets]   -- salt
  09                -- varuint, AttrId::KdfRounds
    01              -- varuint, attribute length
      [0a]          -- varuint, 10 kdf rounds
```

In this example the encoding starts off with the multikey sigil (`0x3a`)
followed by the varuint codec value for an Ed25519 private key (`0x8026`).
Following that there is the key comment encoded as varbytes with a varuint 
length value followed by that number of octets of utf-8 string data. The rest
of the encoded Multikey is the attributes table. All attributes are optional.
Each attribute has an attribute ID followed by the varuint encoded length of 
the attribute data followed by that number of octets of attribute data. In this
case of an encrypted Ed25519 secret key, there are attributes for the flag
showing it is encrypted, the encrypted key bytes, the encryption codec, the 
encryption key length, the nonce length, the nonce data, the kdf codec, the kdf
salt length, the kdf salt, and the kdf rounds.

This format is designed to be a flexible container for any kind of key. The 
design of the attribute store leaves room for new attributes in the future.
