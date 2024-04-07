// SPDX-License-Idnetifier: Apache-2.0
use crate::{
    mk::{self, Attributes},
    nonce, AttrId, Multikey, Nonce,
};
use core::fmt;
use multicodec::Codec;
use multiutil::{EncodedVarbytes, Varbytes};
use serde::{
    de::{Error, MapAccess, Visitor},
    Deserialize, Deserializer,
};
use zeroize::Zeroizing;

/// Deserialize instance of [`crate::Nonce`]
impl<'de> Deserialize<'de> for Nonce {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        const FIELDS: &'static [&'static str] = &["nonce"];

        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Nonce,
        }

        struct NonceVisitor;

        impl<'de> Visitor<'de> for NonceVisitor {
            type Value = Nonce;

            fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
                write!(fmt, "struct Nonce")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Nonce, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut nonce = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Nonce => {
                            if nonce.is_some() {
                                return Err(Error::duplicate_field("nonce"));
                            }
                            let vb: EncodedVarbytes = map.next_value()?;
                            nonce = Some(vb.to_inner().to_inner());
                        }
                    }
                }
                let nonce = nonce.ok_or_else(|| Error::missing_field("hash"))?;
                Ok(Self::Value { nonce })
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_struct(nonce::SIGIL.as_str(), FIELDS, NonceVisitor)
        } else {
            let (sigil, nonce): (Codec, Varbytes) = Deserialize::deserialize(deserializer)?;

            if sigil != nonce::SIGIL {
                return Err(Error::custom("deserialized sigil is not a Nonce sigil"));
            }
            let nonce = nonce.to_inner();

            Ok(Self { nonce })
        }
    }
}

/// Deserialize instance of [`crate::AttrId`]
impl<'de> Deserialize<'de> for AttrId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AttrVisitor;

        impl<'de> Visitor<'de> for AttrVisitor {
            type Value = AttrId;

            fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
                write!(fmt, "borrowed str, str, String, or u8")
            }

            fn visit_u8<E>(self, c: u8) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Ok(AttrId::try_from(c).map_err(|e| Error::custom(e.to_string()))?)
            }

            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Ok(AttrId::try_from(s).map_err(|e| Error::custom(e.to_string()))?)
            }

            fn visit_borrowed_str<E>(self, s: &'de str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Ok(AttrId::try_from(s).map_err(|e| Error::custom(e.to_string()))?)
            }

            fn visit_string<E>(self, s: String) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Ok(AttrId::try_from(s.as_str()).map_err(|e| Error::custom(e.to_string()))?)
            }
        }

        deserializer.deserialize_any(AttrVisitor)
    }
}

/// Deserialize instance of [`crate::Multikey`]
impl<'de> Deserialize<'de> for Multikey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        const FIELDS: &'static [&'static str] = &["codec", "comment", "attributes"];

        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Codec,
            Comment,
            Attributes,
        }

        struct MultikeyVisitor;

        impl<'de> Visitor<'de> for MultikeyVisitor {
            type Value = Multikey;

            fn expecting(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt.write_str("struct Multikey")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut codec = None;
                let mut comment = None;
                let mut attributes = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Codec => {
                            if codec.is_some() {
                                return Err(Error::duplicate_field("codec"));
                            }
                            let c: Codec = map.next_value()?;
                            codec = Some(c);
                        }
                        Field::Comment => {
                            if comment.is_some() {
                                return Err(Error::duplicate_field("comment"));
                            }
                            let c: String = map.next_value()?;
                            comment = Some(c);
                        }
                        Field::Attributes => {
                            if attributes.is_some() {
                                return Err(Error::duplicate_field("attributes"));
                            }
                            let attr: Vec<(AttrId, EncodedVarbytes)> = map.next_value()?;
                            let mut a = Attributes::new();
                            attr.iter()
                                .try_for_each(|(id, attr)| -> Result<(), V::Error> {
                                    let i = *id;
                                    let v: Zeroizing<Vec<u8>> = (***attr).clone().into();
                                    if a.insert(i, v).is_some() {
                                        return Err(Error::duplicate_field(
                                            "duplicate attribute id",
                                        ));
                                    }
                                    Ok(())
                                })?;
                            attributes = Some(a);
                        }
                    }
                }
                let codec = codec.ok_or_else(|| Error::missing_field("codec"))?;
                let comment = comment.ok_or_else(|| Error::missing_field("comment"))?;
                let attributes = attributes.ok_or_else(|| Error::missing_field("attributes"))?;

                Ok(Self::Value {
                    codec,
                    comment,
                    attributes,
                })
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_struct(mk::SIGIL.as_str(), FIELDS, MultikeyVisitor)
        } else {
            let (sigil, codec, comment, attr): (Codec, Codec, Varbytes, Vec<(AttrId, Varbytes)>) =
                Deserialize::deserialize(deserializer)?;

            if sigil != mk::SIGIL {
                return Err(Error::custom("deserialized sigil is not a Multikey sigil"));
            }
            let comment = String::from_utf8(comment.to_inner())
                .map_err(|_| Error::custom("failed to decode comment"))?;
            let mut attributes = Attributes::new();
            attr.iter()
                .try_for_each(|(id, attr)| -> Result<(), D::Error> {
                    let i = *id;
                    let a: Zeroizing<Vec<u8>> = attr.to_vec().into();
                    if attributes.insert(i, a).is_some() {
                        return Err(Error::duplicate_field("duplicate attribute id"));
                    }
                    Ok(())
                })?;

            Ok(Self {
                codec,
                comment,
                attributes,
            })
        }
    }
}
