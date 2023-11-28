use crate::mk::{Multikey, SIGIL};
use core::fmt;
use multicodec::Codec;
use multiutil::{EncodedVarbytes, EncodedVaruint, Varbytes, Varuint};
use serde::{
    de::{Error, MapAccess, Visitor},
    Deserialize, Deserializer,
};

/// Deserialize instance of [`crate::Multikey`]
impl<'de> Deserialize<'de> for Multikey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        const FIELDS: &'static [&'static str] = &["codec", "encrypted", "attributes", "data"];

        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Codec,
            Encrypted,
            Attributes,
            Data,
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
                let mut encrypted = None;
                let mut attributes = None;
                let mut data = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Codec => {
                            if codec.is_some() {
                                return Err(Error::duplicate_field("codec"));
                            }
                            let c: u64 = map.next_value()?;
                            codec = Some(
                                Codec::try_from(c)
                                    .map_err(|_| Error::custom("invalid multikey codec"))?,
                            );
                        }
                        Field::Encrypted => {
                            if encrypted.is_some() {
                                return Err(Error::duplicate_field("encrypted"));
                            }
                            let e: bool = map.next_value()?;
                            encrypted = Some(e as u8);
                        }
                        Field::Attributes => {
                            if attributes.is_some() {
                                return Err(Error::duplicate_field("attributes"));
                            }
                            let cv: Vec<EncodedVaruint<u64>> = map.next_value()?;
                            attributes = Some(cv);
                        }
                        Field::Data => {
                            if data.is_some() {
                                return Err(Error::duplicate_field("data"));
                            }
                            let du: Vec<EncodedVarbytes> = map.next_value()?;
                            data = Some(du);
                        }
                    }
                }
                let codec = codec.ok_or_else(|| Error::missing_field("codec"))?;
                let encrypted = encrypted.ok_or_else(|| Error::missing_field("encrypted"))?;
                let attributes: Vec<u64> = attributes
                    .ok_or_else(|| Error::missing_field("attributes"))?
                    .iter()
                    .map(|v| v.clone().to_inner().to_inner())
                    .collect();
                let data = data
                    .ok_or_else(|| Error::missing_field("data"))?
                    .iter()
                    .map(|du| du.clone().to_inner().to_inner())
                    .collect();
                Ok(Multikey {
                    codec,
                    encrypted,
                    attributes,
                    data,
                })
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_struct(SIGIL.as_str(), FIELDS, MultikeyVisitor)
        } else {
            let (sigil, codec, encrypted, attributes, data): (
                Codec,
                Codec,
                Varuint<u8>,
                Vec<Varuint<u64>>,
                Vec<Varbytes>,
            ) = Deserialize::deserialize(deserializer)?;

            if sigil != SIGIL {
                return Err(Error::custom("deserialized sigil is not a Multikey sigil"));
            }
            let encrypted = encrypted.to_inner();
            let attributes = attributes.iter().map(|v| v.clone().to_inner()).collect();
            let data = data.iter().map(|du| du.clone().to_inner()).collect();
            Ok(Self {
                codec,
                encrypted,
                attributes,
                data,
            })
        }
    }
}
