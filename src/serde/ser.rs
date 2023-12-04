use crate::{mk::SIGIL, AttrId, Multikey};
use multiutil::{BaseEncoded, EncodedVarbytes, EncodingInfo, Varbytes};
use serde::ser::{self, SerializeStruct};

/// Serialize instance of [`crate::AttrId`]
impl ser::Serialize for AttrId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(self.as_str())
        } else {
            let v: Vec<u8> = self.clone().into();
            serializer.serialize_bytes(v.as_slice())
        }
    }
}

/// Serialize instance of [`crate::Multikey`]
impl ser::Serialize for Multikey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        if serializer.is_human_readable() {
            let attributes: Vec<(String, EncodedVarbytes)> = self
                .attributes
                .iter()
                .map(|(id, attr)| {
                    (
                        id.to_string(),
                        BaseEncoded::new_base(self.encoding(), Varbytes(attr.to_vec())),
                    )
                })
                .collect();

            let mut ss = serializer.serialize_struct(SIGIL.as_str(), 4)?;
            ss.serialize_field("codec", &self.codec)?;
            ss.serialize_field("comment", &self.comment)?;
            ss.serialize_field("attributes", &attributes)?;
            ss.end()
        } else {
            let attributes: Vec<(AttrId, Varbytes)> = self
                .attributes
                .iter()
                .map(|(id, attr)| (*id, Varbytes(attr.to_vec())))
                .collect();

            (
                SIGIL,
                self.codec,
                Varbytes(self.comment.as_bytes().to_vec()),
                attributes,
            )
                .serialize(serializer)
        }
    }
}
