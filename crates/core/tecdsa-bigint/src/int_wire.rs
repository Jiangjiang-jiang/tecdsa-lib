use rug::{integer::Order, Integer};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};

pub fn serialize<S: Serializer>(val: &Integer, serializer: S) -> Result<S::Ok, S::Error> {
    let sign: i8 = if val.cmp0() == core::cmp::Ordering::Less {
        -1
    } else {
        0
    };
    let magnitude = val.to_digits::<u8>(Order::MsfBe);
    (sign, serde_bytes::ByteBuf::from(magnitude)).serialize(serializer)
}

pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Integer, D::Error> {
    let (sign, magnitude) = <(i8, serde_bytes::ByteBuf)>::deserialize(deserializer)?;
    let val = Integer::from_digits(&magnitude, Order::MsfBe);
    match sign {
        0 => Ok(val),
        -1 => Ok(-val),
        _ => Err(D::Error::custom("invalid integer sign")),
    }
}

pub mod vec {
    use super::{Deserialize, Deserializer, Integer, Order, Serialize, Serializer};
    use serde::de::Error as _;

    pub fn serialize<S: Serializer>(vals: &[Integer], serializer: S) -> Result<S::Ok, S::Error> {
        let wire: Vec<(i8, serde_bytes::ByteBuf)> = vals
            .iter()
            .map(|val| {
                let sign: i8 = if val.cmp0() == core::cmp::Ordering::Less {
                    -1
                } else {
                    0
                };
                (
                    sign,
                    serde_bytes::ByteBuf::from(val.to_digits::<u8>(Order::MsfBe)),
                )
            })
            .collect();
        wire.serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<Integer>, D::Error> {
        let wire = <Vec<(i8, serde_bytes::ByteBuf)>>::deserialize(deserializer)?;
        wire.into_iter()
            .map(|(sign, magnitude)| {
                let val = Integer::from_digits(&magnitude, Order::MsfBe);
                match sign {
                    0 => Ok(val),
                    -1 => Ok(-val),
                    _ => Err(D::Error::custom("invalid integer sign")),
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Integer;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Wire {
        #[serde(with = "super")]
        x: Integer,
        #[serde(with = "super::vec")]
        v: Vec<Integer>,
    }

    #[test]
    fn roundtrip() {
        let w = Wire {
            x: -Integer::from(0x1122_3344_5566u64),
            v: vec![
                Integer::ZERO,
                Integer::from(1),
                Integer::from(-1),
                Integer::from(u128::MAX) * Integer::from(u128::MAX),
            ],
        };
        let bytes = bincode::serde::encode_to_vec(&w, bincode::config::standard()).unwrap();
        let (w2, _): (Wire, _) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(w, w2);
    }

    #[test]
    fn compact_size() {
        let n = (Integer::from(1) << 3072u32) - 1u8;
        let w = Wire { x: n, v: vec![] };
        let bytes = bincode::serde::encode_to_vec(&w, bincode::config::standard()).unwrap();
        assert!(bytes.len() < 384 + 16, "wire size {} too large", bytes.len());
    }
}
