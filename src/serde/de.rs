use crate::{
    mk::{Attributes, SIGIL},
    AttrId, Multikey,
};
use core::fmt;
use multicodec::Codec;
use multiutil::{EncodedVarbytes, Varbytes};
use serde::{
    de::{Error, MapAccess, Visitor},
    Deserialize, Deserializer,
};
use zeroize::Zeroizing;

/// Deserialize instance of [`crate::AttrId`]
impl<'de> Deserialize<'de> for AttrId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s: &str = Deserialize::deserialize(deserializer)?;
            Ok(AttrId::try_from(s).map_err(|e| Error::custom(e.to_string()))?)
        } else {
            let b: &[u8] = Deserialize::deserialize(deserializer)?;
            Ok(AttrId::try_from(b).map_err(|e| Error::custom(e.to_string()))?)
        }
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

            fn visit_map<V>(self, mut map: V) -> Result<Multikey, V::Error>
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

                Ok(Multikey {
                    codec,
                    comment,
                    attributes,
                })
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_struct(SIGIL.as_str(), FIELDS, MultikeyVisitor)
        } else {
            let (sigil, codec, comment, attr): (Codec, Codec, Varbytes, Vec<(AttrId, Varbytes)>) =
                Deserialize::deserialize(deserializer)?;

            if sigil != SIGIL {
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
