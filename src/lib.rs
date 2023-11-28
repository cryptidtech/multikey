//!
#![warn(missing_docs)]
#![deny(
    trivial_casts,
    trivial_numeric_casts,
    unused_import_braces,
    unused_qualifications
)]

/// encryption/decryption trait
pub mod encdec;
pub use encdec::{EncDec, Kdf};

/// Errors produced by this library
pub mod error;
pub use error::Error;

/// Multikey type and functions
pub mod mk;
pub use mk::{Builder, EncodedMultikey, Multikey};

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
