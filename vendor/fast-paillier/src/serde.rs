use crate::{backend::Integer, DecryptionKey, EncryptionKey};

/// Serializes/deserializes a single `&Integer`/`Integer` through the compact
/// [`crate::backend::int_wire`] adapter, so it can be used as an element of a
/// `serde`-derived tuple/array (which requires each element to implement
/// `Serialize`/`Deserialize` itself, unlike the `#[serde(with = ...)]`
/// field attribute).
struct IntWire<'a>(&'a Integer);

impl serde::Serialize for IntWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        crate::backend::int_wire::serialize(self.0, serializer)
    }
}

struct OwnedIntWire(Integer);

impl<'de> serde::Deserialize<'de> for OwnedIntWire {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(OwnedIntWire(crate::backend::int_wire::deserialize(
            deserializer,
        )?))
    }
}

impl serde::Serialize for EncryptionKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        crate::backend::int_wire::serialize(self.n(), serializer)
    }
}

impl<'de> serde::Deserialize<'de> for EncryptionKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let n = crate::backend::int_wire::deserialize(deserializer)?;
        Ok(EncryptionKey::from_n(n))
    }
}

impl serde::Serialize for DecryptionKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let pq = [IntWire(self.p()), IntWire(self.q())];
        pq.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for DecryptionKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let [p, q] = <[OwnedIntWire; 2]>::deserialize(deserializer)?;
        DecryptionKey::from_primes(p.0, q.0)
            .map_err(|_| <D::Error as serde::de::Error>::custom("invalid paillier key"))
    }
}
