use crate::error::Error;
use multicodec::{codec::Codec, mc::MultiCodec};
use std::fmt;
use unsigned_varint::{decode, encode};

/// the multicodec sigil for multikey
pub const SIGIL: Codec = Codec::Multikey;

/// The data unit in a multikey
#[derive(Clone, Debug, PartialEq)]
pub struct DataUnit(Vec<u8>);

/// Give access to the inner slice
impl AsRef<[u8]> for DataUnit {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl DataUnit {
    /// returns the number of bytes in the data unit
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// encodes the data unit into a Vec<u8>
    pub fn to_vec(&self) -> Vec<u8> {
        let mut v = Vec::default();
        v.append(&mut encode_usize_to_vec(self.0.len()));
        v.extend_from_slice(self.0.as_slice());
        v
    }

    /// tries to decode a DataUnit from a slice
    pub fn decode_from_slice(bytes: &[u8]) -> Result<(Self, &[u8]), Error> {
        let mut ptr = bytes;
        let (len, p) = decode_usize_from_slice(ptr)?;
        ptr = p;
        let mut v = Vec::with_capacity(len);
        if len > 0 {
            v.extend_from_slice(&ptr[..len]);
        }
        Ok((Self(v), &ptr[len..]))
    }
}

impl From<&[u8]> for DataUnit {
    fn from(bytes: &[u8]) -> Self {
        let mut v = Vec::with_capacity(bytes.len());
        v.extend_from_slice(bytes);
        Self(v)
    }
}

/// The main multikey structure
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Multikey {
    /// The key codec
    pub key: Codec,

    /// The codec-specific values
    pub codec_values: Vec<u128>,

    /// The comment associated with the key
    pub comment: String,

    /// The data units for the key
    pub data_units: Vec<DataUnit>,
}

impl Multikey {
    /// encodes the multikey to a Vec<u8>
    pub fn to_vec(&self) -> Vec<u8> {
        let mut v = Vec::default();

        // start with the sigil
        v.append(&mut SIGIL.to_vec());

        // add the key codec
        v.extend_from_slice(self.key.to_vec().as_slice());

        // add in the number of codec-specific varuints
        v.append(&mut encode_usize_to_vec(self.codec_values.len()));

        // add in the codec-specific values
        for cv in &self.codec_values {
            v.append(&mut encode_u128_to_vec(*cv));
        }

        // add in the number of data data units
        v.append(&mut encode_usize_to_vec(self.data_units.len() + 1));

        // add in the comment as a data unit
        v.append(&mut encode_usize_to_vec(self.comment.as_bytes().len()));
        v.extend_from_slice(self.comment.as_bytes());

        // add in the data units
        for du in &self.data_units {
            v.append(&mut du.to_vec());
        }

        v
    }
}

impl fmt::Display for Multikey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "{}:", SIGIL)?;
        writeln!(f, "\tKey Codec: {}", self.key)?;
        writeln!(f, "\tCodec-specific Values: [")?;
        for cv in &self.codec_values {
            writeln!(f, "\t\t0x{:x}", cv)?;
        }
        writeln!(f, "\t]")?;
        writeln!(f, "\tData Units: [")?;
        for du in &self.data_units {
            writeln!(f, "\t\t({}): {}", du.len(), hex::encode(du.as_ref()))?;
        }
        writeln!(f, "\t]")
    }
}

fn encode_u128_to_vec(n: u128) -> Vec<u8> {
    let mut buf = encode::u128_buffer();
    encode::u128(n, &mut buf);

    let mut v = Vec::default();
    for b in buf {
        v.push(b);
        if decode::is_last(b) {
            break;
        }
    }

    v
}

fn decode_u128_from_slice(b: &[u8]) -> Result<(u128, &[u8]), Error> {
    Ok(decode::u128(b).map_err(|e| Error::UnsignedVarintDecode(e))?)
}

fn decode_usize_from_slice(b: &[u8]) -> Result<(usize, &[u8]), Error> {
    Ok(decode::usize(b).map_err(|e| Error::UnsignedVarintDecode(e))?)
}

fn encode_usize_to_vec(n: usize) -> Vec<u8> {
    let mut buf = encode::usize_buffer();
    encode::usize(n, &mut buf);

    let mut v = Vec::default();
    for b in buf {
        v.push(b);
        if decode::is_last(b) {
            break;
        }
    }

    v
}

impl TryFrom<String> for Multikey {
    type Error = Error;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::try_from(s.as_str())
    }
}

impl TryFrom<&str> for Multikey {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match multibase::decode(s) {
            Ok((_, v)) => Self::try_from(v.as_slice()),
            Err(e) => Err(Error::Multibase(e)),
        }
    }
}

impl TryFrom<Vec<u8>> for Multikey {
    type Error = Error;

    fn try_from(v: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(v.as_slice())
    }
}

impl TryFrom<&[u8]> for Multikey {
    type Error = Error;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        // ensure the first varuint is the sigil
        let sigil = MultiCodec::try_from(data)?;
        if sigil.codec() != SIGIL {
            return Err(Error::MissingSigil);
        }
        let mut ptr = sigil.data();

        // decode the key codec varuint
        let key = MultiCodec::try_from(ptr)?;
        ptr = key.data();

        // decode the number of codec-specific values
        let (num_cv, p) = decode_usize_from_slice(ptr)?;
        ptr = p;

        let codec_values = match num_cv {
            0 => Vec::default(),
            _ => {
                // decode the codec-specific values
                let mut codec_values = Vec::with_capacity(num_cv);
                for _ in 0..num_cv {
                    let (cv, p) = decode_u128_from_slice(ptr)?;
                    ptr = p;
                    codec_values.push(cv);
                }
                codec_values
            }
        };

        // decode the number of data units
        let (num_du, p) = decode_usize_from_slice(ptr)?;
        ptr = p;

        let (comment, data_units) = match num_du {
            0 => (String::default(), Vec::default()),
            _ => {
                // decode the first data unit as the comment
                let (c_len, p) = decode_usize_from_slice(ptr)?;
                ptr = p;
                let comment = String::from_utf8(ptr[..c_len].to_vec())?;
                ptr = &ptr[c_len..];

                // decode the data units
                let mut data_units = Vec::with_capacity(num_du - 1);
                for _ in 0..num_du - 1 {
                    let (cv, p) = DataUnit::decode_from_slice(ptr)?;
                    ptr = p;
                    data_units.push(cv);
                }

                (comment, data_units)
            }
        };

        Ok(Self {
            key: key.codec(),
            codec_values,
            comment,
            data_units,
        })
    }
}

impl TryFrom<&ssh_key::PublicKey> for Multikey {
    type Error = Error;

    fn try_from(sshkey: &ssh_key::PublicKey) -> Result<Self, Self::Error> {
        use ssh_key::Algorithm::*;
        match sshkey.algorithm() {
            Ed25519 => {
                let key = Codec::Ed25519Pub;
                let codec_values = Vec::default();
                let comment = sshkey.comment().to_string();
                let mut data_units = Vec::with_capacity(1);
                data_units.push(match sshkey.key_data() {
                    ssh_key::public::KeyData::Ed25519(e) => DataUnit::from(&e.0[..]),
                    _ => return Err(Error::UnsupportedAlgorithm(sshkey.algorithm().to_string())),
                });

                Ok(Self {
                    key,
                    codec_values,
                    comment,
                    data_units,
                })
            }
            _ => Err(Error::UnsupportedAlgorithm(sshkey.algorithm().to_string())),
        }
    }
}

impl TryFrom<&ssh_key::PrivateKey> for Multikey {
    type Error = Error;

    fn try_from(sshkey: &ssh_key::PrivateKey) -> Result<Self, Self::Error> {
        use ssh_key::Algorithm::*;
        match sshkey.algorithm() {
            Ed25519 => {
                let key = Codec::Ed25519Priv;
                let codec_values = Vec::default();
                let comment = sshkey.comment().to_string();
                let mut data_units = Vec::with_capacity(1);
                data_units.push(match sshkey.key_data() {
                    ssh_key::private::KeypairData::Ed25519(e) => {
                        DataUnit::from(&e.private.to_bytes()[..])
                    }
                    _ => return Err(Error::UnsupportedAlgorithm(sshkey.algorithm().to_string())),
                });

                Ok(Self {
                    key,
                    codec_values,
                    comment,
                    data_units,
                })
            }
            _ => Err(Error::UnsupportedAlgorithm(sshkey.algorithm().to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple() {
        let mk = Multikey {
            key: Codec::Ed25519Pub,
            ..Default::default()
        };
        let v = mk.to_vec();
        assert_eq!(6, v.len());
    }

    #[test]
    fn test_from_ssh_pubkey() {
        let private_key = ssh_key::private::Ed25519PrivateKey::random(&mut rand::rngs::OsRng);
        let public_key = ssh_key::public::Ed25519PublicKey::from(private_key);
        let key_data = ssh_key::public::KeyData::Ed25519(public_key);
        let sshkey = ssh_key::PublicKey::new(key_data, "test key");
        let mk = Multikey::try_from(&sshkey).unwrap();

        assert_eq!(mk.key, Codec::Ed25518Pub);
        assert_eq!(mk.comment, "test key".to_string());
        assert_eq!(mk.data_units[0].len(), 32);
    }

    #[test]
    fn test_from_ssh_privkey() {
        let private = ssh_key::private::Ed25519PrivateKey::random(&mut rand::rngs::OsRng);
        let public = ssh_key::public::Ed25519PublicKey::from(&private);
        let key_pair = ssh_key::private::Ed25519Keypair { public, private };
        let key_data = ssh_key::private::KeypairData::Ed25519(key_pair);
        let sshkey = ssh_key::PrivateKey::new(key_data, "test key").unwrap();
        let mk = Multikey::try_from(&sshkey).unwrap();

        assert_eq!(mk.key, Codec::Ed25519Priv);
        assert_eq!(mk.comment, "test key".to_string());
        assert_eq!(mk.data_units[0].len(), 32);
    }

    #[test]
    fn test_pub_from_string() {
        let s = "zVQSE3Uy36Cdu74JC1HUDUwD99bRDrTwjigpLKNJQw6qY9rvuYDwRX1Bw3J7u8G5x".to_string();
        let mk = Multikey::try_from(s).unwrap();
        assert_eq!(mk.key, Codec::Ed25519Pub);
        assert_eq!(mk.comment, "test key".to_string());
        assert_eq!(mk.data_units[0].len(), 32);
    }

    #[test]
    fn test_priv_from_string() {
        let s = "zVCYiR6NKxkdxfCJgowFTECSr6Tm7Fdq5PMJWyXfkQRJ4upc9PKvRUNk9kSkAvj3f".to_string();
        let mk = Multikey::try_from(s).unwrap();
        assert_eq!(mk.key, Codec::Ed25519Priv);
        assert_eq!(mk.comment, "test key".to_string());
        assert_eq!(mk.data_units[0].len(), 32);
    }

    #[test]
    fn test_pub_from_vec() {
        let b = hex::decode("3aed0100020874657374206b657920c3bc684b917a04898bd80608873910247f6278bc64dc05a0463aa470e7bda169").unwrap();
        let mk = Multikey::try_from(b).unwrap();
        assert_eq!(mk.key, Codec::Ed25519Pub);
        assert_eq!(mk.comment, "test key".to_string());
        assert_eq!(mk.data_units[0].len(), 32);
    }

    #[test]
    fn test_priv_from_vec() {
        let b = hex::decode("3a802600020874657374206b65792062c31d5c05250d9c6f02ba7bb4f0b4a0adf79481ba183039a7d015e2fe7c8b66").unwrap();
        let mk = Multikey::try_from(b).unwrap();
        assert_eq!(mk.key, Codec::Ed25519Priv);
        assert_eq!(mk.comment, "test key".to_string());
        assert_eq!(mk.data_units[0].len(), 32);
    }
}
