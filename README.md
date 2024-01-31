# Multikey

[![](https://img.shields.io/badge/made%20by-Cryptid%20Technologies-gold.svg?style=flat-square)][0]
[![](https://img.shields.io/badge/project-multiformats-blue.svg?style=flat-square)][1]

A Rust implementation of the [multiformats][0] [multikey specification][1].

## Current Status

This implementation of the multikey specification supports both public key and
secret key cryptography keys. For public key cryptography, it supports public
and secret keys for EdDSA, and ECDSA using the Nist P256, P384, and P521
curves. For secret key cryptography it supports ChaCha-256 keys.

This implementation also supports encrypting keys—usually secret keys—using the
ChaCha20-Poly1305 AEAD with keys derived using Bcrypt KDF.

For the technical details of the design of multikey, please refer to the
[specification][2].

[0]: https://cryptid.tech
[1]: https://github.com/multiformats/multiformats
[2]: https://github.com/cryptidtech/provenance-specifications/blob/main/specifications/multikey.made

