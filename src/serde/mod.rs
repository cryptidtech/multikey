//! Serde (de)serialization for [`crate::Multikey`].
mod de;
mod ser;

#[cfg(test)]
mod tests {
    use crate::{
        attributes_view, cipher, cipher_view, conversions_view, kdf, kdf_view, Builder,
        EncodedMultikey, Multikey,
    };
    use multibase::Base;
    use multicodec::Codec;
    use multiutil::BaseEncoded;
    use serde_test::{assert_tokens, Configure, Token};

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
            let conv = conversions_view(&sk).unwrap();
            let mk = conv.borrow().to_public_key().unwrap();
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
                Token::BorrowedBytes(&[1]), // AttrId::KeyData
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
            let conv = conversions_view(&sk).unwrap();
            let mk = conv.borrow().to_public_key().unwrap();
            mk
        };

        assert_tokens(
            &mk.readable(),
            &[
                Token::Struct {
                    name: "multikey",
                    len: 4,
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

        let attr = attributes_view(&mk1).unwrap();
        assert_eq!(false, attr.borrow().is_encrypted());
        assert_eq!(false, attr.borrow().is_public_key());
        assert_eq!(true, attr.borrow().is_secret_key());
        assert!(attr.borrow().key_bytes().is_ok());
        assert!(attr.borrow().secret_bytes().is_ok());

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
            let kdf = kdf_view(&kdfmk).unwrap();
            // derive a key from the passphrase and add it to the cipher multikey
            let ciphermk = kdf
                .borrow()
                .derive_key(&ciphermk, b"for great justice, move every zig!")
                .unwrap();
            // get the cipher view
            let cipher = cipher_view(&ciphermk).unwrap();
            // encrypt the multikey using the cipher
            let mk = cipher.borrow().encrypt(&mk1).unwrap();
            mk
        };

        assert_tokens(
            &mk2.compact(),
            &[
                Token::Tuple { len: 4 },
                Token::BorrowedBytes(&[0x3a]), // Multikey sigil as varuint
                Token::BorrowedBytes(&[0x80, 0x26]), // Ed25519Priv codec as varuint
                Token::BorrowedBytes(&[8, 116, 101, 115, 116, 32, 107, 101, 121]), // "test key"
                Token::Seq { len: Some(10) },
                Token::Tuple { len: 2 },
                Token::BorrowedBytes(&[0]), // AttrId::KeyIsEncrypted
                Token::BorrowedBytes(&[1, 1]),
                Token::TupleEnd,
                Token::Tuple { len: 2 },
                Token::BorrowedBytes(&[1]), // AttrId::KeyData
                Token::BorrowedBytes(&[
                    48, 183, 169, 40, 223, 101, 104, 191, 108, 190, 204, 46, 30, 154, 254, 184, 53,
                    190, 105, 8, 62, 63, 226, 95, 87, 56, 173, 22, 87, 84, 53, 180, 171, 106, 103,
                    158, 8, 105, 107, 31, 196, 99, 127, 187, 173, 133, 208, 82, 154,
                ]),
                Token::TupleEnd,
                Token::Tuple { len: 2 },
                Token::BorrowedBytes(&[2]), // AttrId::CipherCodec
                Token::BorrowedBytes(&[2, 165, 1]),
                Token::TupleEnd,
                Token::Tuple { len: 2 },
                Token::BorrowedBytes(&[3]), // AttrId::CipherKeyLen
                Token::BorrowedBytes(&[1, 32]),
                Token::TupleEnd,
                Token::Tuple { len: 2 },
                Token::BorrowedBytes(&[4]), // AttrId::CipherNonceLen
                Token::BorrowedBytes(&[1, 8]),
                Token::TupleEnd,
                Token::Tuple { len: 2 },
                Token::BorrowedBytes(&[5]), // AttrId::CipherNonce
                Token::BorrowedBytes(&[8, 113, 78, 90, 191, 15, 123, 234, 232]),
                Token::TupleEnd,
                Token::Tuple { len: 2 },
                Token::BorrowedBytes(&[6]), // AttrId::KdfCodec
                Token::BorrowedBytes(&[3, 141, 160, 3]),
                Token::TupleEnd,
                Token::Tuple { len: 2 },
                Token::BorrowedBytes(&[7]), // AttrId::KdfSaltLen
                Token::BorrowedBytes(&[1, 32]),
                Token::TupleEnd,
                Token::Tuple { len: 2 },
                Token::BorrowedBytes(&[8]), // AttrId::KdfSalt
                Token::BorrowedBytes(&[
                    32, 98, 31, 32, 207, 218, 20, 11, 216, 191, 131, 168, 153, 22, 116, 40, 70, 41,
                    41, 164, 30, 155, 104, 168, 70, 123, 252, 36, 85, 233, 249, 132, 6,
                ]),
                Token::TupleEnd,
                Token::Tuple { len: 2 },
                Token::BorrowedBytes(&[9]), // AttrId::KdfRounds
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

        let attr = attributes_view(&mk1).unwrap();
        assert_eq!(false, attr.borrow().is_encrypted());
        assert_eq!(false, attr.borrow().is_public_key());
        assert_eq!(true, attr.borrow().is_secret_key());
        assert!(attr.borrow().key_bytes().is_ok());
        assert!(attr.borrow().secret_bytes().is_ok());

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
            let kdf = kdf_view(&kdfmk).unwrap();
            // derive a key from the passphrase and add it to the cipher multikey
            let ciphermk = kdf
                .borrow()
                .derive_key(&ciphermk, b"for great justice, move every zig!")
                .unwrap();
            // get the cipher view
            let cipher = cipher_view(&ciphermk).unwrap();
            // encrypt the multikey using the cipher
            let mk = cipher.borrow().encrypt(&mk1).unwrap();
            mk
        };

        assert_tokens(
            &mk2.readable(),
            &[
                Token::Struct {
                    name: "multikey",
                    len: 4,
                },
                Token::BorrowedStr("codec"),
                Token::BorrowedStr("ed25519-priv"),
                Token::BorrowedStr("comment"),
                Token::BorrowedStr("test key"),
                Token::BorrowedStr("attributes"),
                Token::Seq { len: Some(10) },
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
                Token::BorrowedStr("cipher-nonce-len"),
                Token::BorrowedStr("f0108"),
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
                Token::BorrowedStr("kdf-salt-len"),
                Token::BorrowedStr("f0120"),
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

        let attr = attributes_view(&mk1).unwrap();
        assert_eq!(false, attr.borrow().is_encrypted());
        assert_eq!(false, attr.borrow().is_public_key());
        assert_eq!(true, attr.borrow().is_secret_key());
        assert!(attr.borrow().key_bytes().is_ok());
        assert!(attr.borrow().secret_bytes().is_ok());

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
            let kdf = kdf_view(&kdfmk).unwrap();
            // derive a key from the passphrase and add it to the cipher multikey
            let ciphermk = kdf
                .borrow()
                .derive_key(&ciphermk, b"for great justice, move every zig!")
                .unwrap();
            // get the cipher view
            let cipher = cipher_view(&ciphermk).unwrap();
            // encrypt the multikey using the cipher
            let mk = cipher.borrow().encrypt(&mk1).unwrap();
            mk
        };

        let s = serde_json::to_string(&mk2).unwrap();
        assert_eq!(s, "{\"codec\":\"ed25519-priv\",\"comment\":\"test key\",\"attributes\":[[\"key-is-encrypted\",\"f0101\"],[\"key-data\",\"f30b7a928df6568bf6cbecc2e1e9afeb835be69083e3fe25f5738ad16575435b4ab6a679e08696b1fc4637fbbad85d0529a\"],[\"cipher-codec\",\"f02a501\"],[\"cipher-key-len\",\"f0120\"],[\"cipher-nonce-len\",\"f0108\"],[\"cipher-nonce\",\"f08714e5abf0f7beae8\"],[\"kdf-codec\",\"f038da003\"],[\"kdf-salt-len\",\"f0120\"],[\"kdf-salt\",\"f20621f20cfda140bd8bf83a899167428462929a41e9b68a8467bfc2455e9f98406\"],[\"kdf-rounds\",\"f010a\"]]}".to_string());

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
            let conv = conversions_view(&sk).unwrap();
            let pk = conv.borrow().to_public_key().unwrap();
            pk
        };

        // try to get the associated public key
        let mk1 = BaseEncoded::new(Base::Base58Btc, pk);
        let mk2 = EncodedMultikey::try_from(mk1.to_string().as_str()).unwrap();

        assert_eq!(mk1, mk2);
    }
}
