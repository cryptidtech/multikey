# Multikey

[![](https://img.shields.io/badge/made%20by-Cryptid%20Technologies-gold.svg?style=flat-square)][0]
[![](https://img.shields.io/badge/project-multiformats-blue.svg?style=flat-square)][1]

A Rust implementation of the [multiformats][1] [multikey specification][2].

## Current Status

This implementation of the Multikey specification supports both public key and
secret key cryptography keys. For public key cryptography, it supports public
and secret keys for EdDSA, and ECDSA using the Nist P256, P384, and P521
curves. For secret key cryptography it supports ChaCha-256 keys and encryption 
and decryption using ChaCha20-Poly1305.

This implementation also supports encrypting keys—usually secret keys—using the
ChaCha20-Poly1305 AEAD with keys derived using Bcrypt KDF.

This implementation also supports BLS12381 G1/G2 public key cryptography with 
key splitting and combining as well as threshold signing and verifying.

For the technical details of the design of Multikey, please refer to the
[specification][2].

## Introduction

This is a Rust implementation of a multicodec format for encryption keys. The 
design of the format is intentionally abstract to support any kind of
encryption key in any state (e.g. encrypted or unencrypted). This format should
be best thought of as a container of key material with abstract, algorithm-
specific views and a generic and self-describing data storage format.

Every piece of data in the serialized Multikey object either has a known-fixed
size or a self-describing variable size such that software processing these
objects do not need to support all encryption algorithms to be able to 
accurately calculate the size of the serialized object and skip over it if 
needed.

## Views on the Multikey Data 

To provide an abstract interface to encryption keys for all algorithms, this 
Multikey crate provides "views" on the Multikey data. These are read-only 
abstract interfaces to the Multikey attributes with implementations for 
different supporting encryption algorithms.

Currently the set of views provide generic access to the general attributes 
(`multikey::AttrView`) of the Multikey, the key data (`multikey::DataView`),
as well as views on the KDF attributes (`multikey::KdfAttrView`), and cipher
attributes (`multikey::CipherAttrView`) for encrypted Multikeys. For encryption
algorithms that support threshold operations there is a threshold attributes 
view (`multikey::ThresholdAttrView`).

For operations you can do with a Multikey, there is a cipher view
(`multikey::CipherView`) for encrypting/decrypting a Multikey, a conversion
view (`multikey::ConvView`) for converting the Multikey to other formats (e.g.
to ssh key format and secret keys to public keys), a fingerprint view
(`multikey::FingerprintView`) for getting a key fingerprint, a KDF view
(`multikey::KdfView`) for generating cipher keys for use by a cipher view to
encrypt/decrypt the Multikey, a threshold view (`multikey::ThresholdView`) for 
key splitting and combining, and lastly a sign view (`multikey::SignView`) and 
verify view (`multikey::VerifyView`) for creating and verifying [`Multisig`][3]
digital signatures.

It is important to note that the operations that seem to mutate the Multikey 
(e.g. encrypt, decrypt, convert, etc) in fact do a copy-on-write (CoW)
operation and return a new Multikey with the mutation applied.

[0]: https://cryptid.tech
[1]: https://github.com/multiformats/multiformats
[2]: https://github.com/cryptidtech/provenance-specifications/blob/main/specifications/multikey.made
[3]: https://github.com/cryptidtech/multisig

