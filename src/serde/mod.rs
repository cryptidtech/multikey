//! Serde (de)serialization for [`crate::Multikey`].
mod de;
mod ser;

#[cfg(test)]
mod tests {
    use crate::{cipher, kdf, nonce, Builder, EncodedMultikey, Multikey, Views};
    use multibase::Base;
    use multicodec::Codec;
    use multihash::EncodedMultihash;
    use multitrait::Null;
    use multiutil::BaseEncoded;
    use serde::{Deserialize, Serialize};
    use serde_test::{assert_tokens, Configure, Token};
    use std::collections::BTreeMap;

    #[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
    struct Wrapper {
        pub map: BTreeMap<EncodedMultihash, Multikey>,
    }

    #[test]
    fn test_serde_macros() {
        let bytes = hex::decode("7e48467029ffb9f6282b56e9ce131cead6e4bd061a3500697c57ac7034cf86f2")
            .unwrap();
        let sk = Builder::new(Codec::Ed25519Priv)
            .with_comment("test key")
            .with_key_bytes(&bytes)
            .try_build()
            .unwrap();
        let skh = {
            let fv = sk.fingerprint_view().unwrap();
            EncodedMultihash::new(Base::Base58Btc, fv.fingerprint(Codec::Blake2S256).unwrap())
        };
        let pk = {
            let cv = sk.conv_view().unwrap();
            cv.to_public_key().unwrap()
        };
        let pkh = {
            let fv = sk.fingerprint_view().unwrap();
            EncodedMultihash::new(Base::Base58Btc, fv.fingerprint(Codec::Blake2S256).unwrap())
        };

        let mut w1 = Wrapper::default();
        w1.map.insert(skh, sk);
        w1.map.insert(pkh, pk);

        let b = serde_cbor::to_vec(&w1).unwrap();
        let w2 = serde_cbor::from_slice(b.as_slice()).unwrap();
        assert_eq!(w1, w2);
        let s = serde_json::to_string(&w1).unwrap();
        let w3 = serde_json::from_str(&s).unwrap();
        assert_eq!(w1, w3);
    }

    #[test]
    fn test_serde_compact() {
        let bytes = hex::decode("7e48467029ffb9f6282b56e9ce131cead6e4bd061a3500697c57ac7034cf86f2")
            .unwrap();
        let sk = Builder::new(Codec::Ed25519Priv)
            .with_comment("test key")
            .with_key_bytes(&bytes)
            .try_build()
            .unwrap();

        // try to get the associated public key
        let mk = {
            let conv = sk.conv_view().unwrap();
            let mk = conv.to_public_key().unwrap();
            mk
        };

        assert_tokens(
            &mk.compact(),
            &[
                Token::Tuple { len: 4 },
                Token::BorrowedBytes(&[0x3a]), // Multikey sigil as varuint
                Token::BorrowedBytes(&[0xed, 0x01]), // Ed25519Pub codec as varuint
                Token::BorrowedBytes(&[8, 116, 101, 115, 116, 32, 107, 101, 121]), // "test key"
                Token::Seq { len: Some(1) },   // attributes array of (varuint, varbytes)
                Token::Tuple { len: 2 },
                Token::U8(1), // AttrId::KeyData
                Token::BorrowedBytes(&[
                    // public key bytes
                    32, 19, 225, 230, 232, 195, 83, 103, 43, 117, 156, 147, 195, 151, 149, 105, 39,
                    225, 80, 60, 110, 221, 115, 242, 64, 204, 255, 43, 125, 208, 69, 88, 182,
                ]),
                Token::TupleEnd,
                Token::SeqEnd,
                Token::TupleEnd,
            ],
        );
    }

    #[test]
    fn test_serde_encoded_string() {
        let bytes = hex::decode("7e48467029ffb9f6282b56e9ce131cead6e4bd061a3500697c57ac7034cf86f2")
            .unwrap();
        let pk = Builder::new(Codec::Ed25519Priv)
            .with_comment("test key")
            .with_key_bytes(&bytes)
            .with_base_encoding(Base::Base58Btc)
            .try_build_encoded()
            .unwrap();

        assert_tokens(
            &pk.readable(),
            &[Token::BorrowedStr(
                "zVCYiTqf3RfiqqE4RxExy5XEvCWJKnHH4P67PLC1VuAuA1N8X1qQhM3Y3Bp1xmTQ5",
            )],
        );
    }

    #[test]
    fn test_serde_readable() {
        let bytes = hex::decode("7e48467029ffb9f6282b56e9ce131cead6e4bd061a3500697c57ac7034cf86f2")
            .unwrap();
        let sk = Builder::new(Codec::Ed25519Priv)
            .with_comment("test key")
            .with_key_bytes(&bytes)
            .try_build()
            .unwrap();

        let mk = {
            let conv = sk.conv_view().unwrap();
            let mk = conv.to_public_key().unwrap();
            mk
        };

        assert_tokens(
            &mk.readable(),
            &[
                Token::Struct {
                    name: "multikey",
                    len: 3,
                },
                Token::BorrowedStr("codec"),
                Token::BorrowedStr("ed25519-pub"),
                Token::BorrowedStr("comment"),
                Token::BorrowedStr("test key"),
                Token::BorrowedStr("attributes"),
                Token::Seq { len: Some(1) },
                Token::Tuple { len: 2 },
                Token::BorrowedStr("key-data"), // AttrId::KeyData
                Token::BorrowedStr(
                    "f2013e1e6e8c353672b759c93c397956927e1503c6edd73f240ccff2b7dd04558b6",
                ),
                Token::TupleEnd,
                Token::SeqEnd,
                Token::StructEnd,
            ],
        );
    }

    #[test]
    fn test_serde_encrypted_secret_key_compact() {
        let bytes = hex::decode("7e48467029ffb9f6282b56e9ce131cead6e4bd061a3500697c57ac7034cf86f2")
            .unwrap();
        let mk1 = Builder::new(Codec::Ed25519Priv)
            .with_comment("test key")
            .with_key_bytes(&bytes)
            .try_build()
            .unwrap();

        let attr = mk1.attr_view().unwrap();
        assert_eq!(false, attr.is_encrypted());
        assert_eq!(false, attr.is_public_key());
        assert_eq!(true, attr.is_secret_key());
        let kd = mk1.data_view().unwrap();
        assert!(kd.key_bytes().is_ok());
        assert!(kd.secret_bytes().is_ok());

        let mk2 = {
            let salt =
                hex::decode("621f20cfda140bd8bf83a899167428462929a41e9b68a8467bfc2455e9f98406")
                    .unwrap();
            let kdfmk = kdf::Builder::new(Codec::BcryptPbkdf)
                .with_salt(&salt)
                .with_rounds(10)
                .try_build()
                .unwrap();

            let nonce = hex::decode("714e5abf0f7beae8").unwrap();
            let ciphermk = cipher::Builder::new(Codec::Chacha20Poly1305)
                .with_nonce(&nonce)
                .try_build()
                .unwrap();

            // get the kdf view
            let kdf = ciphermk.kdf_view(&kdfmk).unwrap();
            // derive a key from the passphrase and add it to the cipher multikey
            let ciphermk = kdf
                .derive_key(b"for great justice, move every zig!")
                .unwrap();
            // get the cipher view
            let cipher = mk1.cipher_view(&ciphermk).unwrap();
            // encrypt the multikey using the cipher
            let mk = cipher.encrypt().unwrap();
            mk
        };

        assert_tokens(
            &mk2.compact(),
            &[
                Token::Tuple { len: 4 },
                Token::BorrowedBytes(&[0x3a]), // Multikey sigil as varuint
                Token::BorrowedBytes(&[0x80, 0x26]), // Ed25519Priv codec as varuint
                Token::BorrowedBytes(&[8, 116, 101, 115, 116, 32, 107, 101, 121]), // "test key"
                Token::Seq { len: Some(8) },
                Token::Tuple { len: 2 },
                Token::U8(0), // AttrId::KeyIsEncrypted
                Token::BorrowedBytes(&[1, 1]),
                Token::TupleEnd,
                Token::Tuple { len: 2 },
                Token::U8(1), // AttrId::KeyData
                Token::BorrowedBytes(&[
                    48, 183, 169, 40, 223, 101, 104, 191, 108, 190, 204, 46, 30, 154, 254, 184, 53,
                    190, 105, 8, 62, 63, 226, 95, 87, 56, 173, 22, 87, 84, 53, 180, 171, 106, 103,
                    158, 8, 105, 107, 31, 196, 99, 127, 187, 173, 133, 208, 82, 154,
                ]),
                Token::TupleEnd,
                Token::Tuple { len: 2 },
                Token::U8(2), // AttrId::CipherCodec
                Token::BorrowedBytes(&[2, 165, 1]),
                Token::TupleEnd,
                Token::Tuple { len: 2 },
                Token::U8(3), // AttrId::CipherKeyLen
                Token::BorrowedBytes(&[1, 32]),
                Token::TupleEnd,
                Token::Tuple { len: 2 },
                Token::U8(4), // AttrId::CipherNonce
                Token::BorrowedBytes(&[8, 113, 78, 90, 191, 15, 123, 234, 232]),
                Token::TupleEnd,
                Token::Tuple { len: 2 },
                Token::U8(5), // AttrId::KdfCodec
                Token::BorrowedBytes(&[3, 141, 160, 3]),
                Token::TupleEnd,
                Token::Tuple { len: 2 },
                Token::U8(6), // AttrId::KdfSalt
                Token::BorrowedBytes(&[
                    32, 98, 31, 32, 207, 218, 20, 11, 216, 191, 131, 168, 153, 22, 116, 40, 70, 41,
                    41, 164, 30, 155, 104, 168, 70, 123, 252, 36, 85, 233, 249, 132, 6,
                ]),
                Token::TupleEnd,
                Token::Tuple { len: 2 },
                Token::U8(7), // AttrId::KdfRounds
                Token::BorrowedBytes(&[1, 10]),
                Token::TupleEnd,
                Token::SeqEnd,
                Token::TupleEnd,
            ],
        );
    }

    #[test]
    fn test_serde_encrypted_secret_key_readable() {
        let bytes = hex::decode("7e48467029ffb9f6282b56e9ce131cead6e4bd061a3500697c57ac7034cf86f2")
            .unwrap();
        let mk1 = Builder::new(Codec::Ed25519Priv)
            .with_comment("test key")
            .with_key_bytes(&bytes)
            .try_build()
            .unwrap();

        let attr = mk1.attr_view().unwrap();
        assert_eq!(false, attr.is_encrypted());
        assert_eq!(false, attr.is_public_key());
        assert_eq!(true, attr.is_secret_key());
        let kd = mk1.data_view().unwrap();
        assert!(kd.key_bytes().is_ok());
        assert!(kd.secret_bytes().is_ok());

        let mk2 = {
            let salt =
                hex::decode("621f20cfda140bd8bf83a899167428462929a41e9b68a8467bfc2455e9f98406")
                    .unwrap();
            let kdfmk = kdf::Builder::new(Codec::BcryptPbkdf)
                .with_salt(&salt)
                .with_rounds(10)
                .try_build()
                .unwrap();
            let nonce = hex::decode("714e5abf0f7beae8").unwrap();
            let ciphermk = cipher::Builder::new(Codec::Chacha20Poly1305)
                .with_nonce(&nonce)
                .try_build()
                .unwrap();

            // get the kdf view
            let kdf = ciphermk.kdf_view(&kdfmk).unwrap();
            // derive a key from the passphrase and add it to the cipher multikey
            let ciphermk = kdf
                .derive_key(b"for great justice, move every zig!")
                .unwrap();
            // get the cipher view
            let cipher = mk1.cipher_view(&ciphermk).unwrap();
            // encrypt the multikey using the cipher
            let mk = cipher.encrypt().unwrap();
            mk
        };

        assert_tokens(
            &mk2.readable(),
            &[
                Token::Struct {
                    name: "multikey",
                    len: 3,
                },
                Token::BorrowedStr("codec"),
                Token::BorrowedStr("ed25519-priv"),
                Token::BorrowedStr("comment"),
                Token::BorrowedStr("test key"),
                Token::BorrowedStr("attributes"),
                Token::Seq { len: Some(8) },
                Token::Tuple { len: 2 },
                Token::BorrowedStr("key-is-encrypted"),
                Token::BorrowedStr("f0101"),
                Token::TupleEnd,
                Token::Tuple { len: 2 },
                Token::BorrowedStr("key-data"),
                Token::BorrowedStr("f30b7a928df6568bf6cbecc2e1e9afeb835be69083e3fe25f5738ad16575435b4ab6a679e08696b1fc4637fbbad85d0529a"),
                Token::TupleEnd,
                Token::Tuple { len: 2 },
                Token::BorrowedStr("cipher-codec"),
                Token::BorrowedStr("f02a501"),
                Token::TupleEnd,
                Token::Tuple { len: 2 },
                Token::BorrowedStr("cipher-key-len"),
                Token::BorrowedStr("f0120"),
                Token::TupleEnd,
                Token::Tuple { len: 2 },
                Token::BorrowedStr("cipher-nonce"),
                Token::BorrowedStr("f08714e5abf0f7beae8"),
                Token::TupleEnd,
                Token::Tuple { len: 2 },
                Token::BorrowedStr("kdf-codec"),
                Token::BorrowedStr("f038da003"),
                Token::TupleEnd,
                Token::Tuple { len: 2 },
                Token::BorrowedStr("kdf-salt"),
                Token::BorrowedStr("f20621f20cfda140bd8bf83a899167428462929a41e9b68a8467bfc2455e9f98406"),
                Token::TupleEnd,
                Token::Tuple { len: 2 },
                Token::BorrowedStr("kdf-rounds"),
                Token::BorrowedStr("f010a"),
                Token::TupleEnd,
                Token::SeqEnd,
                Token::StructEnd,
            ],
        );
    }

    #[test]
    fn test_serde_encrypted_secret_key_json() {
        let bytes = hex::decode("7e48467029ffb9f6282b56e9ce131cead6e4bd061a3500697c57ac7034cf86f2")
            .unwrap();
        let mk1 = Builder::new(Codec::Ed25519Priv)
            .with_comment("test key")
            .with_key_bytes(&bytes)
            .try_build()
            .unwrap();

        let attr = mk1.attr_view().unwrap();
        assert_eq!(false, attr.is_encrypted());
        assert_eq!(false, attr.is_public_key());
        assert_eq!(true, attr.is_secret_key());
        let kd = mk1.data_view().unwrap();
        assert!(kd.key_bytes().is_ok());
        assert!(kd.secret_bytes().is_ok());

        let mk2 = {
            let salt =
                hex::decode("621f20cfda140bd8bf83a899167428462929a41e9b68a8467bfc2455e9f98406")
                    .unwrap();
            let kdfmk = kdf::Builder::new(Codec::BcryptPbkdf)
                .with_salt(&salt)
                .with_rounds(10)
                .try_build()
                .unwrap();

            let nonce = hex::decode("714e5abf0f7beae8").unwrap();
            let ciphermk = cipher::Builder::new(Codec::Chacha20Poly1305)
                .with_nonce(&nonce)
                .try_build()
                .unwrap();

            // get the kdf view
            let kdf = ciphermk.kdf_view(&kdfmk).unwrap();
            // derive a key from the passphrase and add it to the cipher multikey
            let ciphermk = kdf
                .derive_key(b"for great justice, move every zig!")
                .unwrap();
            // get the cipher view
            let cipher = mk1.cipher_view(&ciphermk).unwrap();
            // encrypt the multikey using the cipher
            let mk = cipher.encrypt().unwrap();
            mk
        };

        let s = serde_json::to_string(&mk2).unwrap();
        assert_eq!(s, "{\"codec\":\"ed25519-priv\",\"comment\":\"test key\",\"attributes\":[[\"key-is-encrypted\",\"f0101\"],[\"key-data\",\"f30b7a928df6568bf6cbecc2e1e9afeb835be69083e3fe25f5738ad16575435b4ab6a679e08696b1fc4637fbbad85d0529a\"],[\"cipher-codec\",\"f02a501\"],[\"cipher-key-len\",\"f0120\"],[\"cipher-nonce\",\"f08714e5abf0f7beae8\"],[\"kdf-codec\",\"f038da003\"],[\"kdf-salt\",\"f20621f20cfda140bd8bf83a899167428462929a41e9b68a8467bfc2455e9f98406\"],[\"kdf-rounds\",\"f010a\"]]}".to_string());

        let mk3: Multikey = serde_json::from_str(&s).unwrap();
        assert_eq!(mk2, mk3);
    }

    #[test]
    fn test_serde_encrypted_bls_secret_key_share_json() {
        /*
        let bytes = hex::decode("4b79b6a7da7cdc9fe17e368450f08ae5a5f42347f4863f2ee23404f99aa62147")
            .unwrap();
        let emk = Builder::new(Codec::Bls12381G1Priv)
            .with_comment("test key")
            .with_base_encoding(Base::Base58Btc)
            .with_key_bytes(&bytes)
            .try_build_encoded()
            .unwrap();
        println!("{}", emk);
        */

        // build a secret key share multikey
        let emk = EncodedMultikey::try_from(
            "zVDXiufT1nH3FWqLCAq9zvngU8nLUv1jvrkp8hGajy38caidL18ML9E5fYYfJkXQJ",
        )
        .unwrap();
        let mk1 = emk.to_inner();

        let attr = mk1.attr_view().unwrap();
        assert_eq!(false, attr.is_encrypted());
        assert_eq!(false, attr.is_public_key());
        assert_eq!(true, attr.is_secret_key());
        let kd = mk1.data_view().unwrap();
        assert!(kd.key_bytes().is_ok());
        assert!(kd.secret_bytes().is_ok());

        let mk2 = {
            let salt =
                hex::decode("621f20cfda140bd8bf83a899167428462929a41e9b68a8467bfc2455e9f98406")
                    .unwrap();
            let kdfmk = kdf::Builder::new(Codec::BcryptPbkdf)
                .with_salt(&salt)
                .with_rounds(10)
                .try_build()
                .unwrap();

            let nonce = hex::decode("714e5abf0f7beae8").unwrap();
            let ciphermk = cipher::Builder::new(Codec::Chacha20Poly1305)
                .with_nonce(&nonce)
                .try_build()
                .unwrap();

            // get the kdf view
            let kdf = ciphermk.kdf_view(&kdfmk).unwrap();
            // derive a key from the passphrase and add it to the cipher multikey
            let ciphermk = kdf
                .derive_key(b"for great justice, move every zig!")
                .unwrap();
            // get the cipher view
            let cipher = mk1.cipher_view(&ciphermk).unwrap();
            // encrypt the multikey using the cipher
            let mk = cipher.encrypt().unwrap();
            mk
        };

        let s = serde_json::to_string(&mk2).unwrap();
        assert_eq!(s, "{\"codec\":\"bls12_381-g1-priv\",\"comment\":\"test key\",\"attributes\":[[\"key-is-encrypted\",\"f0101\"],[\"key-data\",\"f308298d80896ebda0577994e73041d2e3acd79967fd1516010a6cebedefa5c131e200bab3d620a17940f758191742f2deb\"],[\"cipher-codec\",\"f02a501\"],[\"cipher-key-len\",\"f0120\"],[\"cipher-nonce\",\"f08714e5abf0f7beae8\"],[\"kdf-codec\",\"f038da003\"],[\"kdf-salt\",\"f20621f20cfda140bd8bf83a899167428462929a41e9b68a8467bfc2455e9f98406\"],[\"kdf-rounds\",\"f010a\"]]}".to_string());

        let mk3: Multikey = serde_json::from_str(&s).unwrap();
        assert_eq!(mk2, mk3);
    }

    #[test]
    fn test_encoded_public_key() {
        let bytes = hex::decode("7e48467029ffb9f6282b56e9ce131cead6e4bd061a3500697c57ac7034cf86f2")
            .unwrap();
        let sk = Builder::new(Codec::Ed25519Priv)
            .with_comment("test key")
            .with_key_bytes(&bytes)
            .try_build()
            .unwrap();

        // try to get the associated public key
        let pk = {
            let conv = sk.conv_view().unwrap();
            let pk = conv.to_public_key().unwrap();
            pk
        };

        // try to get the associated public key
        let mk1 = BaseEncoded::new(Base::Base58Btc, pk);
        let mk2 = EncodedMultikey::try_from(mk1.to_string().as_str()).unwrap();

        assert_eq!(mk1, mk2);
    }

    #[test]
    fn test_nonce_serde_compact() {
        let bytes = hex::decode("76895272c5ce5c0c72b5ec54944ead739482f87048dbbfc13b873008b31d5995")
            .unwrap();
        let n = nonce::Builder::new_from_bytes(&bytes).try_build().unwrap();

        assert_tokens(
            &n.compact(),
            &[
                Token::Tuple { len: 2 },
                Token::BorrowedBytes(&[0x3b]), // Nonce sigil as varuint
                Token::BorrowedBytes(&[
                    // Nonce data as varbytes
                    32, 118, 137, 82, 114, 197, 206, 92, 12, 114, 181, 236, 84, 148, 78, 173, 115,
                    148, 130, 248, 112, 72, 219, 191, 193, 59, 135, 48, 8, 179, 29, 89, 149,
                ]),
                Token::TupleEnd,
            ],
        );
    }

    #[test]
    fn test_nonce_serde_encoded_string() {
        let bytes = hex::decode("76895272c5ce5c0c72b5ec54944ead739482f87048dbbfc13b873008b31d5995")
            .unwrap();
        let n = nonce::Builder::new_from_bytes(&bytes)
            .try_build_encoded()
            .unwrap();

        assert_tokens(
            &n.readable(),
            &[Token::BorrowedStr(
                "f3b2076895272c5ce5c0c72b5ec54944ead739482f87048dbbfc13b873008b31d5995",
            )],
        );
    }

    #[test]
    fn test_nonce_serde_readable() {
        let bytes = hex::decode("76895272c5ce5c0c72b5ec54944ead739482f87048dbbfc13b873008b31d5995")
            .unwrap();
        let n = nonce::Builder::new_from_bytes(&bytes).try_build().unwrap();

        assert_tokens(
            &n.readable(),
            &[
                Token::Struct {
                    name: "nonce",
                    len: 1,
                },
                Token::BorrowedStr("nonce"),
                Token::BorrowedStr(
                    "f2076895272c5ce5c0c72b5ec54944ead739482f87048dbbfc13b873008b31d5995",
                ),
                Token::StructEnd,
            ],
        );
    }

    #[test]
    fn test_null_multikey_serde_compact() {
        let mk = Multikey::null();
        assert_tokens(
            &mk.compact(),
            &[
                Token::Tuple { len: 4 },
                Token::BorrowedBytes(&[0x3a]),
                Token::BorrowedBytes(&[0x0]),
                Token::BorrowedBytes(&[0x0]),
                Token::Seq { len: Some(0), },
                Token::SeqEnd,
                Token::TupleEnd,
            ]
        );
    }

    #[test]
    fn test_null_multikey_serde_readable() {
        let mk = Multikey::null();
        assert_tokens(
            &mk.readable(),
            &[
                Token::Struct { name: "multikey", len: 3, },
                Token::BorrowedStr("codec"),
                Token::BorrowedStr("identity"),
                Token::BorrowedStr("comment"),
                Token::BorrowedStr(""),
                Token::BorrowedStr("attributes"),
                Token::Seq { len: Some(0), },
                Token::SeqEnd,
                Token::StructEnd,
            ]
        );
    }

    #[test]
    fn test_encoded_null_multikey_serde_readable() {
        let mk: EncodedMultikey = Multikey::null().into();
        assert_tokens(
            &mk.readable(),
            &[
                Token::BorrowedStr("f3a000000"),
            ]
        );
    }

    #[test]
    fn test_null_nonce_serde_compact() {
        let n = nonce::Nonce::null();
        assert_tokens(
            &n.compact(),
            &[
                Token::Tuple { len: 2 },
                Token::BorrowedBytes(&[0x3b]),
                Token::BorrowedBytes(&[0x0]),
                Token::TupleEnd,
            ]
        );
    }

    #[test]
    fn test_null_nonce_serde_readable() {
        let n = nonce::Nonce::null();
        assert_tokens(
            &n.readable(),
            &[
                Token::Struct { name: "nonce", len: 1, },
                Token::BorrowedStr("nonce"),
                Token::BorrowedStr("f00"),
                Token::StructEnd,
            ]
        );
    }

    #[test]
    fn test_encoded_null_nonce_serde_readable() {
        let n: nonce::EncodedNonce = nonce::Nonce::null().into();
        assert_tokens(
            &n.readable(),
            &[
                Token::BorrowedStr("f3b00"),
            ]
        );
    }
}
