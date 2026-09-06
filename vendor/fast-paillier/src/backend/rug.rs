#![allow(missing_docs)]

/// Big integer type used in this crate.
///
/// A plain re-export of [`rug::Integer`] rather than a newtype, so the whole
/// workspace shares one big-integer type. The helper methods that used to be
/// inherent on the newtype now live on `tecdsa_bigint::BigIntExt`.
pub use rug::Integer;
pub use tecdsa_bigint::{BigIntExt, Sign};
