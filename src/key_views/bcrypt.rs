use crate::{
    cipher_attributes_view, error::KdfError, kdf_attributes_view, AttrId, Error, KdfAttributesView,
    KdfView, Multikey,
};
use multicodec::Codec;
use multiutil::Varuint;
use zeroize::Zeroizing;

/// constants for Bcrypt
pub const SALT_LENGTH: usize = 32;

pub(crate) struct View<'a> {
    mk: &'a Multikey,
}

impl<'a> TryFrom<&'a Multikey> for View<'a> {
    type Error = Error;

    fn try_from(mk: &'a Multikey) -> Result<Self, Self::Error> {
        Ok(Self { mk })
    }
}

impl<'a> KdfView for View<'a> {
    fn derive_key(&self, mk: &Multikey, passphrase: &[u8]) -> Result<Multikey, Error> {
        // get a view on our kdf attributes
        let kattr = kdf_attributes_view(&self.mk)?;
        // get the salt bytes
        let salt = kattr.borrow().salt_bytes()?;
        // get the rounds
        let rounds = kattr.borrow().rounds()?;

        // get a cipher view on the passed-in Multikey to get the key length
        let cattr = cipher_attributes_view(mk)?;

        // heap allocate a buffer to receive the derived key
        let mut key: Zeroizing<Vec<u8>> = vec![0; cattr.borrow().key_length()?].into();

        // derive the key
        bcrypt_pbkdf::bcrypt_pbkdf(
            passphrase.as_ref(),
            &salt,
            rounds as u32,
            key.as_mut_slice(),
        )
        .map_err(|e| KdfError::Bcrypt(e))?;

        // prepare the codec
        let codec: Vec<u8> = self.mk.codec.into();
        let rounds: Vec<u8> = Varuint(rounds).into();
        let salt_length: Vec<u8> = Varuint(self.salt_length()?).into();

        // create a new multikey from the passed-in multikey with the kdf
        // parameters added along with the derived key
        let mut res = mk.clone();
        res.attributes.insert(AttrId::KeyData, key.clone());
        let _ = res.attributes.remove(&AttrId::KeyIsEncrypted);
        res.attributes.insert(AttrId::KdfCodec, codec.into());
        res.attributes.insert(AttrId::KdfSalt, salt.clone());
        res.attributes
            .insert(AttrId::KdfSaltLen, salt_length.into());
        res.attributes.insert(AttrId::KdfRounds, rounds.into());
        Ok(res)
    }
}

impl<'a> KdfAttributesView for View<'a> {
    fn kdf_codec(&self) -> Result<Codec, Error> {
        Ok(self.mk.codec)
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
