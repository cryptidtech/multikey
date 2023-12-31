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

/// Multikey attribute IDs
pub mod attrid;
pub use attrid::AttrId;

/// Cipher function builder
pub mod cipher;

/// Key derivation function builder
pub mod kdf;

/// Key views
pub mod key_views;
pub use key_views::{
    AttrView, CipherAttrView, CipherView, FingerprintView, KdfAttrView, KdfView, KeyConvView,
    KeyDataView, KeyViews, SignView, ThresholdAttrView, ThresholdView, VerifyView,
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
