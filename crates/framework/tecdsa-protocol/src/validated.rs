// SPDX-License-Identifier: MIT OR Apache-2.0
//! `Validated<T>` wrapper that guarantees a key share has passed validation.

use tecdsa_core::TecdsaError;
use zeroize::Zeroize;

/// Trait for key share types that support post-construction validation.
///
/// Implementors define what it means for a key share to be structurally valid
/// (correct index bounds, non-identity public key, consistent lengths, etc.).
pub trait KeyShareValidation: Sized {
    /// Check internal consistency of this key share.
    ///
    /// Returns `Ok(())` if the share is valid, or a [`TecdsaError`] describing
    /// the first violation found.
    fn validate(&self) -> Result<(), TecdsaError>;
}

/// Wrapper guaranteeing a key share has passed validation.
///
/// Construction is only possible through [`Validated::new`], which calls
/// [`KeyShareValidation::validate`] and returns `Err` if the share is
/// malformed.  After construction, only immutable access is provided
/// (via `AsRef` and `Deref`), so the invariant cannot be violated.
pub struct Validated<T: KeyShareValidation>(T);

impl<T: KeyShareValidation> Validated<T> {
    /// Validate `inner` and wrap it on success.
    pub fn new(inner: T) -> Result<Self, TecdsaError> {
        inner.validate()?;
        Ok(Self(inner))
    }

    /// Consume the wrapper and return the inner value.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T: KeyShareValidation> AsRef<T> for Validated<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
}

impl<T: KeyShareValidation> core::ops::Deref for Validated<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

// --- Delegated trait impls where T supports them ---

impl<T: KeyShareValidation + core::fmt::Debug> core::fmt::Debug for Validated<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Validated").field(&self.0).finish()
    }
}

impl<T: KeyShareValidation + Clone> Clone for Validated<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: KeyShareValidation + Zeroize> Zeroize for Validated<T> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

// Note: Cannot impl Drop with extra bounds not present on the struct.
// Users should wrap Validated in a type that impls ZeroizeOnDrop, or the
// inner T should implement ZeroizeOnDrop itself so secrets are cleared.

#[cfg(test)]
mod tests {
    use super::*;

    struct TestShare {
        index: u16,
        total: u16,
    }

    impl KeyShareValidation for TestShare {
        fn validate(&self) -> Result<(), TecdsaError> {
            if self.index >= self.total {
                return Err(TecdsaError::InvalidShare("index >= total".into()));
            }
            Ok(())
        }
    }

    #[test]
    fn valid_share_passes() {
        let v = Validated::new(TestShare { index: 0, total: 3 });
        assert!(v.is_ok());
    }

    #[test]
    fn invalid_index_fails() {
        let v = Validated::new(TestShare { index: 5, total: 3 });
        assert!(v.is_err());
    }

    #[test]
    fn deref_gives_immutable_access() {
        let v = Validated::new(TestShare { index: 0, total: 3 }).unwrap();
        assert_eq!(v.index, 0);
        assert_eq!(v.total, 3);
    }

    #[test]
    fn into_inner_recovers_value() {
        let v = Validated::new(TestShare { index: 1, total: 5 }).unwrap();
        let inner = v.into_inner();
        assert_eq!(inner.index, 1);
        assert_eq!(inner.total, 5);
    }
}
