// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2023 Dfns <https://github.com/LFDT-Lockness/fast-paillier>
use crate::scheme::EncryptionKey;

impl serde::Serialize for EncryptionKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        tecdsa_bigint::int_wire::serialize(self.n(), serializer)
    }
}

impl<'de> serde::Deserialize<'de> for EncryptionKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let n = tecdsa_bigint::int_wire::deserialize(deserializer)?;
        Ok(EncryptionKey::from_n(n))
    }
}
