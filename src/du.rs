use crate::error::Error;
use multiutil::{EncodeInto, TryDecodeFrom};

/// The data unit in a multikey
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DataUnit(Vec<u8>);

impl DataUnit {
    /// create a new data unit containing the slice of bytes
    pub fn new(bytes: &impl AsRef<[u8]>) -> Self {
        Self(bytes.as_ref().to_vec())
    }

    /// returns the number of bytes in the data unit
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

/// Give access to the inner slice
impl AsRef<[u8]> for DataUnit {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl EncodeInto for DataUnit {
    fn encode_into(&self) -> Vec<u8> {
        let mut v = self.0.len().encode_into();
        v.append(&mut self.0.clone());
        v
    }
}

/// Try to decode from a Vec
impl TryFrom<Vec<u8>> for DataUnit {
    type Error = Error;

    fn try_from(v: Vec<u8>) -> Result<Self, Self::Error> {
        let (du, _) = Self::try_decode_from(v.as_slice())?;
        Ok(du)
    }
}

impl<'a> TryDecodeFrom<'a> for DataUnit {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        // decode the size of the data unit
        let (len, ptr) = usize::try_decode_from(bytes)?;

        let mut v = Vec::with_capacity(len);
        v.extend_from_slice(&ptr[..len]);
        Ok((Self(v), &ptr[len..]))
    }
}
