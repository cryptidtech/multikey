use crate::mk::{Multikey, SIGIL};
use multiutil::{EncodedVarbytes, EncodedVaruint, Varbytes, Varuint};
use serde::ser::{self, SerializeStruct};

/// Serialize instance of [`crate::mh::Multikey`]
impl ser::Serialize for Multikey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        if serializer.is_human_readable() {
            let cv: Vec<EncodedVaruint<u64>> = self
                .attributes
                .iter()
                .map(|v| Varuint::<u64>::encoded_new(*v))
                .collect();
            let du: Vec<EncodedVarbytes> = self
                .data
                .iter()
                .map(|du| Varbytes::encoded_new(du.clone()))
                .collect();

            let mut ss = serializer.serialize_struct(SIGIL.as_str(), 4)?;
            ss.serialize_field("codec", &self.codec.code())?;
            ss.serialize_field("encrypted", &(self.encrypted != 0))?;
            ss.serialize_field("attributes", &cv)?;
            ss.serialize_field("data", &du)?;
            ss.end()
        } else {
            let cv: Vec<Varuint<u64>> = self.attributes.iter().map(|v| Varuint(*v)).collect();
            let du: Vec<Varbytes> = self.data.iter().map(|du| Varbytes(du.clone())).collect();

            (SIGIL, self.codec, Varuint(self.encrypted), cv, du).serialize(serializer)
        }
    }
}
