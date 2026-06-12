use elliptic_curve::group::GroupEncoding;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

fn repr_from_slice<T: GroupEncoding>(bytes: &[u8]) -> Option<T::Repr> {
    let mut repr = T::Repr::default();
    let buf = repr.as_mut();
    if bytes.len() != buf.len() {
        return None;
    }
    buf.copy_from_slice(bytes);
    Some(repr)
}

pub fn serialize<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: GroupEncoding,
    S: Serializer,
{
    let bytes = value.to_bytes();
    bytes.as_ref().serialize(serializer)
}

pub fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: GroupEncoding,
    D: Deserializer<'de>,
{
    let bytes = Vec::<u8>::deserialize(deserializer)?;
    let repr = repr_from_slice::<T>(&bytes)
        .ok_or_else(|| serde::de::Error::custom("invalid byte length for projective point"))?;
    let ct_opt = T::from_bytes(&repr);
    Option::from(ct_opt)
        .ok_or_else(|| serde::de::Error::custom("invalid projective point encoding"))
}

pub mod vec {
    use elliptic_curve::group::GroupEncoding;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<T, S>(values: &[T], serializer: S) -> Result<S::Ok, S::Error>
    where
        T: GroupEncoding,
        S: Serializer,
    {
        let byte_vecs: Vec<Vec<u8>> = values
            .iter()
            .map(|v| v.to_bytes().as_ref().to_vec())
            .collect();
        byte_vecs.serialize(serializer)
    }

    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<Vec<T>, D::Error>
    where
        T: GroupEncoding,
        D: Deserializer<'de>,
    {
        let byte_vecs = Vec::<Vec<u8>>::deserialize(deserializer)?;
        byte_vecs
            .into_iter()
            .map(|bytes| {
                let repr = super::repr_from_slice::<T>(&bytes).ok_or_else(|| {
                    serde::de::Error::custom("invalid byte length for projective point")
                })?;
                let ct_opt = T::from_bytes(&repr);
                Option::from(ct_opt)
                    .ok_or_else(|| serde::de::Error::custom("invalid projective point encoding"))
            })
            .collect()
    }
}
