// SPDX-License-Identifier: MIT OR Apache-2.0
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Secret<T: Zeroize>(T);

impl<T: Zeroize> Secret<T> {
    pub fn new(inner: T) -> Self {
        Self(inner)
    }
}

impl<T: Zeroize> AsRef<T> for Secret<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize + Clone> Clone for Secret<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: Zeroize + serde::Serialize> serde::Serialize for Secret<T> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> core::result::Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de, T: Zeroize + serde::Deserialize<'de>> serde::Deserialize<'de> for Secret<T> {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> core::result::Result<Self, D::Error> {
        T::deserialize(deserializer).map(Self::new)
    }
}
