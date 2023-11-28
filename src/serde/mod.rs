//! Serde (de)serialization for [`crate::Multikey`].
mod de;
mod ser;

#[cfg(test)]
mod tests {
    use crate::{
        encdec::{cipher, pbkdf},
        prelude::BaseEncoded,
        Builder, EncodedMultikey, Multikey,
    };
    use multibase::Base;
    use multicodec::Codec;
    use serde_test::{assert_tokens, Configure, Token};

    #[test]
    fn test_serde_compact() {
        let bytes = hex::decode("3a80260000020874657374206b657920fa87fe4afd223a2560972ea13f9d6223ad955f10a334b1fb6ef5ce6bff4d9dbd").unwrap();
        let pk = Builder::new(Codec::Ed25519Priv)
            .with_comment("test key")
            .with_key_bytes(&bytes)
            .try_build()
            .unwrap();

        // try to get the associated public key
        let mk = pk.to_public_key().unwrap();

        assert_tokens(
            &mk.compact(),
            &[
                Token::Tuple { len: 5 },
                Token::Bytes(&[0x3a]),       // Multikey sigil as varuint
                Token::Bytes(&[0xed, 0x01]), // Ed25519Pub codec as varuint
                Token::Bytes(&[0x00]),       // encrypted flag as varuint
                Token::Seq { len: Some(0) }, // attributes array of varuints
                Token::SeqEnd,
                Token::Seq { len: Some(2) }, // data array of DataUnits
                Token::Bytes(&[8, 116, 101, 115, 116, 32, 107, 101, 121]), // comment data unit
                Token::Bytes(&[
                    32, 62, 102, 130, 63, 172, 211, 84, 197, 123, 199, 162, 193, 229, 147, 156,
                    143, 179, 98, 26, 216, 202, 232, 167, 194, 234, 228, 168, 22, 121, 106, 131,
                    58,
                ]), // key data unit
                Token::SeqEnd,
                Token::TupleEnd,
            ],
        );
    }

    #[test]
    fn test_serde_encoded_string() {
        let bytes = hex::decode("3a80260000020874657374206b657920fa87fe4afd223a2560972ea13f9d6223ad955f10a334b1fb6ef5ce6bff4d9dbd").unwrap();
        let pk = Builder::new(Codec::Ed25519Priv)
            .with_comment("test key")
            .with_key_bytes(&bytes)
            .with_encoding(Base::Base58Btc)
            .try_build_encoded()
            .unwrap();

        assert_tokens(
            &pk.readable(),
            &[Token::String(
                "z2AqaimMwoBVjEBeeJjHtE3D2FZjPwtvnHMC4xBXoEN5uNvciUBLRKxfVnzm14deWEUqsoheRGYwHcKkEAPn5eoPa",
            )],
        );
    }

    #[test]
    fn test_serde_readable() {
        let bytes = hex::decode("3a80260000020874657374206b657920fa87fe4afd223a2560972ea13f9d6223ad955f10a334b1fb6ef5ce6bff4d9dbd").unwrap();
        let pk = Builder::new(Codec::Ed25519Priv)
            .with_comment("test key")
            .with_key_bytes(&bytes)
            .try_build()
            .unwrap();

        // try to get the associated public key
        let mk = pk.to_public_key().unwrap();

        assert_tokens(
            &mk.readable(),
            &[
                Token::Struct {
                    name: "Multikey",
                    len: 4,
                },
                Token::Str("codec"),
                Token::U64(0xed_u64),
                Token::Str("encrypted"),
                Token::Bool(false),
                Token::Str("attributes"),
                Token::Seq { len: Some(0) },
                Token::SeqEnd,
                Token::Str("data"),
                Token::Seq { len: Some(2) },
                Token::Str("f0874657374206b6579"),
                Token::Str("f203e66823facd354c57bc7a2c1e5939c8fb3621ad8cae8a7c2eae4a816796a833a"),
                Token::SeqEnd,
                Token::StructEnd,
            ],
        );
    }

    #[test]
    fn test_serde_encrypted_secret_key_compact() {
        let bytes = hex::decode("3a80260000020874657374206b657920fa87fe4afd223a2560972ea13f9d6223ad955f10a334b1fb6ef5ce6bff4d9dbd").unwrap();
        let mk1 = Builder::new(Codec::Ed25519Priv)
            .with_comment("test key")
            .with_key_bytes(&bytes)
            .try_build()
            .unwrap();

        assert_eq!(false, mk1.is_encrypted());
        assert_eq!(mk1.attributes.len(), 0);
        assert_eq!(mk1.data.len(), 2);

        let mk2 = {
            let salt =
                hex::decode("621f20cfda140bd8bf83a899167428462929a41e9b68a8467bfc2455e9f98406")
                    .unwrap();
            let kdf = pbkdf::Builder::new(Codec::BcryptPbkdf)
                .with_salt(&salt)
                .with_rounds(10)
                .try_build()
                .unwrap();

            let nonce = hex::decode("714e5abf0f7beae8").unwrap();
            let cipher = cipher::Builder::new(Codec::Chacha20Poly1305)
                .from_multikey(&mk1) // init the msg with the unencrypted key
                .with_nonce(&nonce)
                .try_build()
                .unwrap();

            let mut mk2 = mk1.clone();
            Multikey::encrypt(&mut mk2, kdf, cipher, "for great justice, move every zig!").unwrap();
            mk2
        };
        assert_tokens(
            &mk2.compact(),
            &[
                Token::Tuple { len: 5 },
                Token::Bytes(&[0x3a]),       // Multikey sigil as varuint
                Token::Bytes(&[0x80, 0x26]), // Ed25519Priv codec as varuint
                Token::Bytes(&[0x01]),       // encrypted flag as varuint
                Token::Seq { len: Some(6) }, // attributes array of varuints
                Token::Bytes(&[141, 160, 3]),
                Token::Bytes(&[10]),
                Token::Bytes(&[1]),
                Token::Bytes(&[165, 1]),
                Token::Bytes(&[2]),
                Token::Bytes(&[3]),
                Token::SeqEnd,
                Token::Seq { len: Some(4) }, // data array of DataUnits
                Token::Bytes(&[8, 116, 101, 115, 116, 32, 107, 101, 121]),
                Token::Bytes(&[
                    32, 98, 31, 32, 207, 218, 20, 11, 216, 191, 131, 168, 153, 22, 116, 40, 70, 41,
                    41, 164, 30, 155, 104, 168, 70, 123, 252, 36, 85, 233, 249, 132, 6,
                ]),
                Token::Bytes(&[8, 113, 78, 90, 191, 15, 123, 234, 232]),
                Token::Bytes(&[
                    64, 243, 97, 72, 175, 76, 149, 14, 238, 243, 148, 12, 215, 63, 136, 221, 255,
                    146, 10, 75, 114, 216, 245, 101, 27, 36, 109, 148, 134, 95, 103, 80, 122, 21,
                    141, 216, 46, 205, 183, 163, 76, 10, 125, 156, 69, 138, 131, 165, 216, 153,
                    254, 147, 252, 249, 206, 55, 227, 55, 250, 178, 29, 173, 164, 139, 137,
                ]),
                Token::SeqEnd,
                Token::TupleEnd,
            ],
        );
    }

    #[test]
    fn test_serde_encrypted_secret_key_readable() {
        let bytes = hex::decode("3a80260000020874657374206b657920fa87fe4afd223a2560972ea13f9d6223ad955f10a334b1fb6ef5ce6bff4d9dbd").unwrap();
        let mk1 = Builder::new(Codec::Ed25519Priv)
            .with_comment("test key")
            .with_key_bytes(&bytes)
            .try_build()
            .unwrap();

        assert_eq!(false, mk1.is_encrypted());
        assert_eq!(mk1.attributes.len(), 0);
        assert_eq!(mk1.data.len(), 2);

        let mk2 = {
            let salt =
                hex::decode("621f20cfda140bd8bf83a899167428462929a41e9b68a8467bfc2455e9f98406")
                    .unwrap();
            let kdf = pbkdf::Builder::new(Codec::BcryptPbkdf)
                .with_salt(&salt)
                .with_rounds(10)
                .try_build()
                .unwrap();

            let nonce = hex::decode("714e5abf0f7beae8").unwrap();
            let cipher = cipher::Builder::new(Codec::Chacha20Poly1305)
                .from_multikey(&mk1) // init the msg with the unencrypted key
                .with_nonce(&nonce)
                .try_build()
                .unwrap();

            let mut mk2 = mk1.clone();
            Multikey::encrypt(&mut mk2, kdf, cipher, "for great justice, move every zig!").unwrap();
            mk2
        };
        assert_tokens(
            &mk2.readable(),
            &[
                Token::Struct {
                    name: "Multikey",
                    len: 4,
                },
                Token::Str("codec"),
                Token::U64(4864_u64),
                Token::Str("encrypted"),
                Token::Bool(true),
                Token::Str("attributes"),
                Token::Seq { len: Some(6) },
                Token::Str("f8da003"),
                Token::Str("f0a"),
                Token::Str("f01"),
                Token::Str("fa501"),
                Token::Str("f02"),
                Token::Str("f03"),
                Token::SeqEnd,
                Token::Str("data"),
                Token::Seq { len: Some(4) },
                Token::Str("f0874657374206b6579"),
                Token::Str("f20621f20cfda140bd8bf83a899167428462929a41e9b68a8467bfc2455e9f98406"),
                Token::Str("f08714e5abf0f7beae8"),
                Token::Str("f40f36148af4c950eeef3940cd73f88ddff920a4b72d8f5651b246d94865f67507a158dd82ecdb7a34c0a7d9c458a83a5d899fe93fcf9ce37e337fab21dada48b89"),
                Token::SeqEnd,
                Token::StructEnd,
            ],
        );
    }

    #[test]
    fn test_serde_encrypted_secret_key_json() {
        let bytes = hex::decode("3a80260000020874657374206b657920fa87fe4afd223a2560972ea13f9d6223ad955f10a334b1fb6ef5ce6bff4d9dbd").unwrap();
        let mk1 = Builder::new(Codec::Ed25519Priv)
            .with_comment("test key")
            .with_key_bytes(&bytes)
            .try_build()
            .unwrap();

        assert_eq!(false, mk1.is_encrypted());
        assert_eq!(mk1.attributes.len(), 0);
        assert_eq!(mk1.data.len(), 2);

        let mk2 = {
            let salt =
                hex::decode("621f20cfda140bd8bf83a899167428462929a41e9b68a8467bfc2455e9f98406")
                    .unwrap();
            let kdf = pbkdf::Builder::new(Codec::BcryptPbkdf)
                .with_salt(&salt)
                .with_rounds(10)
                .try_build()
                .unwrap();

            let nonce = hex::decode("714e5abf0f7beae8").unwrap();
            let cipher = cipher::Builder::new(Codec::Chacha20Poly1305)
                .from_multikey(&mk1) // init the msg with the unencrypted key
                .with_nonce(&nonce)
                .try_build()
                .unwrap();

            let mut mk2 = mk1.clone();
            Multikey::encrypt(&mut mk2, kdf, cipher, "for great justice, move every zig!").unwrap();
            mk2
        };

        let s = serde_json::to_string(&mk2).unwrap();
        assert_eq!(s, "{\"codec\":4864,\"encrypted\":true,\"attributes\":[\"f8da003\",\"f0a\",\"f01\",\"fa501\",\"f02\",\"f03\"],\"data\":[\"f0874657374206b6579\",\"f20621f20cfda140bd8bf83a899167428462929a41e9b68a8467bfc2455e9f98406\",\"f08714e5abf0f7beae8\",\"f40f36148af4c950eeef3940cd73f88ddff920a4b72d8f5651b246d94865f67507a158dd82ecdb7a34c0a7d9c458a83a5d899fe93fcf9ce37e337fab21dada48b89\"]}".to_string());

        let mk3: Multikey = serde_json::from_str(&s).unwrap();
        assert_eq!(mk2, mk3);
    }

    #[test]
    fn test_encoded_public_key() {
        let bytes = hex::decode("3a80260000020874657374206b657920fa87fe4afd223a2560972ea13f9d6223ad955f10a334b1fb6ef5ce6bff4d9dbd").unwrap();
        let pk = Builder::new(Codec::Ed25519Priv)
            .with_comment("test key")
            .with_key_bytes(&bytes)
            .try_build()
            .unwrap();

        // try to get the associated public key
        let mk1 = BaseEncoded::new_base(Base::Base58Btc, pk.to_public_key().unwrap());
        let mk2 = EncodedMultikey::try_from(mk1.to_string().as_str()).unwrap();

        assert_eq!(mk1, mk2);
    }
}
