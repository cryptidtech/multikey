use crate::{error::KdfError, AttrId, Error, KdfAttrView, KdfView, KeyViews, Multikey};
use multicodec::Codec;
use multiutil::Varuint;
use zeroize::Zeroizing;

/// constants for Bcrypt
pub const SALT_LENGTH: usize = 32;

pub(crate) struct View<'a> {
    mk: &'a Multikey,
    kdf: Option<&'a Multikey>,
}

impl<'a> View<'a> {
    pub fn new(mk: &'a Multikey, kdf: &'a Multikey) -> Self {
        Self { mk, kdf: Some(kdf) }
    }
}

impl<'a> TryFrom<&'a Multikey> for View<'a> {
    type Error = Error;

    fn try_from(mk: &'a Multikey) -> Result<Self, Self::Error> {
        Ok(Self { mk, kdf: None })
    }
}

impl<'a> KdfView for View<'a> {
    /// this takes the kdf attributes and data from the passed-in Multikey and
    /// generates a new Multikey by copying the viewed Multikey (self) and
    /// storing the derived key and attributes in the new Multikey
    fn derive_key(&self, passphrase: &[u8]) -> Result<Multikey, Error> {
        let kdf = self.kdf.ok_or_else(|| KdfError::MissingCodec)?;

        // get the salt data and rounds attribute
        let (salt, salt_length, rounds) = {
            let kattr = kdf.kdf_attr_view()?;
            let salt = kattr.borrow().salt_bytes()?;
            let salt_length = kattr.borrow().salt_length()?;
            let rounds = kattr.borrow().rounds()?;
            (salt, salt_length, rounds)
        };

        // get the key length from the viewed Multikey
        let key_length = {
            let cattr = self.mk.cipher_attr_view()?;
            let key_length = cattr.borrow().key_length()?;
            key_length
        };

        // heap allocate a buffer to receive the derived key
        let mut key: Zeroizing<Vec<u8>> = vec![0; key_length].into();

        // derive the key
        bcrypt_pbkdf::bcrypt_pbkdf(
            passphrase.as_ref(),
            &salt,
            rounds as u32,
            key.as_mut_slice(),
        )
        .map_err(|e| KdfError::Bcrypt(e))?;

        // prepare the attributes
        let kdf_codec: Vec<u8> = kdf.codec.into();
        let rounds: Vec<u8> = Varuint(rounds).into();
        let salt_length: Vec<u8> = Varuint(salt_length).into();

        // create a new Multikey from the viewed Multikey (self) and store the
        // kdf parameters along with the derived key
        let mut res = self.mk.clone();
        res.attributes.insert(AttrId::KeyData, key.clone());
        let _ = res.attributes.remove(&AttrId::KeyIsEncrypted);
        res.attributes.insert(AttrId::KdfCodec, kdf_codec.into());
        res.attributes.insert(AttrId::KdfSalt, salt.clone());
        res.attributes
            .insert(AttrId::KdfSaltLen, salt_length.into());
        res.attributes.insert(AttrId::KdfRounds, rounds.into());
        Ok(res)
    }
}

impl<'a> KdfAttrView for View<'a> {
    fn kdf_codec(&self) -> Result<Codec, Error> {
        Ok(Codec::BcryptPbkdf)
    }

    fn salt_bytes(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        // try to look up the salt in the multikey attributes
        self.mk
            .attributes
            .get(&AttrId::KdfSalt)
            .ok_or(KdfError::MissingSalt.into())
            .cloned()
    }

    fn salt_length(&self) -> Result<usize, Error> {
        Ok(SALT_LENGTH)
    }

    fn rounds(&self) -> Result<usize, Error> {
        // try to look up the rounds in the multikey attributes
        let rounds = self
            .mk
            .attributes
            .get(&AttrId::KdfRounds)
            .ok_or(KdfError::MissingRounds)?;
        Ok(Varuint::<usize>::try_from(rounds.as_slice())?.to_inner())
    }
}
