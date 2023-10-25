//!
#![warn(missing_docs)]
#![deny(
    trivial_casts,
    trivial_numeric_casts,
    unused_import_braces,
    unused_qualifications
)]

/// The result type for this crate
pub type Result<T> = anyhow::Result<T>;

/// Errors produced by this library
pub mod error;

/// Multikey type and functions
pub mod mk;

/// ...and in the darkness bind them
pub mod prelude {
    use super::*;

    pub use super::Result;
    pub use error::*;
    pub use mk::*;
}
