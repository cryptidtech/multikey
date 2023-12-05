//!
#![warn(missing_docs)]
#![deny(
    trivial_casts,
    trivial_numeric_casts,
    unused_import_braces,
    unused_qualifications
)]

/// Errors produced by this library
pub mod error;
pub use error::Error;

/// Cipher function builder
pub mod cipher;

/// Key derivation function builder
pub mod kdf;

/// Key views
pub mod key_views;
pub use key_views::{
    attributes_view, cipher_attributes_view, cipher_view, conversions_view, kdf_attributes_view,
    kdf_view, AttrId, AttributesView, CipherAttributesView, CipherView, ConversionsView,
    KdfAttributesView, KdfView,
};

/// Multikey type and functions
pub mod mk;
pub use mk::{Builder, EncodedMultikey, Multikey};

/// Nonce type
pub mod nonce;
pub use nonce::{EncodedNonce, Nonce};

/// Serde serialization
#[cfg(feature = "serde")]
pub mod serde;

/// ...and in the darkness bind them
pub mod prelude {
    pub use super::*;
    /// re-exports
    pub use multibase::Base;
    pub use multicodec::Codec;
    pub use multiutil::BaseEncoded;
}
