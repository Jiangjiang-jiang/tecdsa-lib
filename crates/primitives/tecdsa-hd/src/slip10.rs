use elliptic_curve::{group::GroupEncoding, sec1::ModulusSize, Field, FieldBytesSize, PrimeField};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use zeroize::Zeroize;

type HmacSha512 = Hmac<Sha512>;

#[derive(Clone, Zeroize)]
pub struct ChainCode(pub [u8; 32]);

#[derive(Debug, Clone, Copy)]
pub struct DerivationIndex(pub u32);

impl DerivationIndex {
    #[must_use]
    pub fn normal(index: u32) -> Self {
        assert!(index < 0x8000_0000, "normal index must be < 2^31");
        Self(index)
    }

    #[must_use]
    pub fn hardened(index: u32) -> Self {
        assert!(index < 0x8000_0000, "hardened base index must be < 2^31");
        Self(index | 0x8000_0000)
    }

    #[must_use]
    pub fn is_hardened(self) -> bool {
        self.0 >= 0x8000_0000
    }
}

fn slip10_key_string<C: TecdsaCurve>() -> &'static [u8]
where
    FieldBytesSize<C>: ModulusSize,
{
    match C::CURVE_NAME {
        "secp256k1" => b"Bitcoin seed",
        "secp256r1" => b"Nist256p1 seed",
        _ => C::CURVE_NAME.as_bytes(),
    }
}

pub fn derive_master<C: TecdsaCurve>(seed: &[u8]) -> Result<(C::Scalar, ChainCode), TecdsaError>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField,
{
    if seed.len() < 16 || seed.len() > 64 {
        return Err(TecdsaError::Other(
            "SLIP-10 seed must be 16..=64 bytes".into(),
        ));
    }

    let key = slip10_key_string::<C>();
    let mut data: Vec<u8> = seed.to_vec();

    loop {
        let mut mac = HmacSha512::new_from_slice(key)
            .map_err(|e| TecdsaError::Other(format!("HMAC init: {e}")))?;
        mac.update(&data);
        let result = mac.finalize().into_bytes();
        let (il, ir) = result.split_at(32);

        if let Some(scalar) = parse_scalar::<C>(il) {
            if !bool::from(Field::is_zero(&scalar)) {
                let mut chain_code = [0u8; 32];
                chain_code.copy_from_slice(ir);
                return Ok((scalar, ChainCode(chain_code)));
            }
        }
        data.clear();
        data.extend_from_slice(&result);
    }
}

pub fn derive_child_share<C: TecdsaCurve>(
    parent_share: &C::Scalar,
    parent_public: &C::ProjectivePoint,
    chain_code: &ChainCode,
    index: DerivationIndex,
) -> Result<(C::Scalar, ChainCode), TecdsaError>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField,
{
    let mut mac = HmacSha512::new_from_slice(&chain_code.0)
        .map_err(|e| TecdsaError::Other(format!("HMAC init: {e}")))?;

    if index.is_hardened() {
        mac.update(&[0x00]);
        let share_repr = parent_share.to_repr();
        mac.update(share_repr.as_ref());
    } else {
        let pub_bytes = parent_public.to_bytes();
        mac.update(pub_bytes.as_ref());
    }
    mac.update(&index.0.to_be_bytes());

    let result = mac.finalize().into_bytes();
    let (il, ir) = result.split_at(32);

    let tweak = parse_scalar::<C>(il)
        .ok_or_else(|| TecdsaError::Other("invalid child scalar (>= curve order)".into()))?;

    let child_share = tweak + *parent_share;

    if bool::from(Field::is_zero(&child_share)) {
        return Err(TecdsaError::Other("derived child key is zero".into()));
    }

    let mut child_cc = [0u8; 32];
    child_cc.copy_from_slice(ir);

    Ok((child_share, ChainCode(child_cc)))
}

pub fn derive_child_public<C: TecdsaCurve>(
    parent_public: &C::ProjectivePoint,
    chain_code: &ChainCode,
    index: DerivationIndex,
) -> Result<(C::ProjectivePoint, ChainCode), TecdsaError>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField,
{
    if index.is_hardened() {
        return Err(TecdsaError::Other(
            "hardened derivation requires secret key".into(),
        ));
    }

    let mut mac = HmacSha512::new_from_slice(&chain_code.0)
        .map_err(|e| TecdsaError::Other(format!("HMAC init: {e}")))?;
    let pub_bytes = parent_public.to_bytes();
    mac.update(pub_bytes.as_ref());
    mac.update(&index.0.to_be_bytes());

    let result = mac.finalize().into_bytes();
    let (il, ir) = result.split_at(32);

    let tweak =
        parse_scalar::<C>(il).ok_or_else(|| TecdsaError::Other("invalid child scalar".into()))?;

    let child_public = C::generator() * tweak + *parent_public;

    let mut child_cc = [0u8; 32];
    child_cc.copy_from_slice(ir);

    Ok((child_public, ChainCode(child_cc)))
}

fn parse_scalar<C: TecdsaCurve>(bytes: &[u8]) -> Option<C::Scalar>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField,
{
    let mut repr = <C::Scalar as PrimeField>::Repr::default();
    let repr_slice: &mut [u8] = repr.as_mut();
    if bytes.len() != repr_slice.len() {
        return None;
    }
    repr_slice.copy_from_slice(bytes);
    Option::from(C::Scalar::from_repr(repr))
}

#[cfg(test)]
mod tests {
    use k256::Secp256k1;

    use super::*;

    #[test]
    fn master_key_derivation() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let (master_key, chain_code) = derive_master::<Secp256k1>(&seed).unwrap();
        assert!(!bool::from(Field::is_zero(&master_key)));
        assert_eq!(chain_code.0.len(), 32);
    }

    #[test]
    fn master_key_seed_too_short() {
        let seed = [0u8; 15];
        let result = derive_master::<Secp256k1>(&seed);
        assert!(result.is_err());
    }

    #[test]
    fn master_key_seed_too_long() {
        let seed = [0u8; 65];
        let result = derive_master::<Secp256k1>(&seed);
        assert!(result.is_err());
    }

    #[test]
    fn normal_derivation_consistency() {
        let mut rng = rand::thread_rng();
        let parent_share = <Secp256k1 as TecdsaCurve>::random_scalar(&mut rng);
        let parent_public = Secp256k1::generator() * parent_share;
        let chain_code = ChainCode([42u8; 32]);
        let index = DerivationIndex::normal(0);

        let (child_share, child_cc1) =
            derive_child_share::<Secp256k1>(&parent_share, &parent_public, &chain_code, index)
                .unwrap();

        let (child_public, child_cc2) =
            derive_child_public::<Secp256k1>(&parent_public, &chain_code, index).unwrap();

        assert_eq!(
            Secp256k1::generator() * child_share,
            child_public,
            "child_share * G must equal child_public"
        );
        assert_eq!(child_cc1.0, child_cc2.0, "chain codes must match");
    }

    #[test]
    fn hardened_derivation_needs_secret() {
        let mut rng = rand::thread_rng();
        let parent_share = <Secp256k1 as TecdsaCurve>::random_scalar(&mut rng);
        let parent_public = Secp256k1::generator() * parent_share;
        let chain_code = ChainCode([0u8; 32]);
        let result = derive_child_public::<Secp256k1>(
            &parent_public,
            &chain_code,
            DerivationIndex::hardened(0),
        );
        assert!(result.is_err());
    }

    #[test]
    fn hardened_derivation_works_with_secret() {
        let mut rng = rand::thread_rng();
        let parent_share = <Secp256k1 as TecdsaCurve>::random_scalar(&mut rng);
        let parent_public = Secp256k1::generator() * parent_share;
        let chain_code = ChainCode([7u8; 32]);
        let index = DerivationIndex::hardened(0);

        let (child_share, _child_cc) =
            derive_child_share::<Secp256k1>(&parent_share, &parent_public, &chain_code, index)
                .unwrap();

        assert!(!bool::from(Field::is_zero(&child_share)));
    }

    #[test]
    fn different_indices_produce_different_keys() {
        let mut rng = rand::thread_rng();
        let share = <Secp256k1 as TecdsaCurve>::random_scalar(&mut rng);
        let public = Secp256k1::generator() * share;
        let cc = ChainCode([1u8; 32]);

        let (child0, _) =
            derive_child_share::<Secp256k1>(&share, &public, &cc, DerivationIndex::normal(0))
                .unwrap();
        let (child1, _) =
            derive_child_share::<Secp256k1>(&share, &public, &cc, DerivationIndex::normal(1))
                .unwrap();

        assert_ne!(
            child0, child1,
            "different indices must produce different keys"
        );
    }

    #[test]
    fn derivation_chain_multiple_levels() {
        let mut rng = rand::thread_rng();
        let mut share = <Secp256k1 as TecdsaCurve>::random_scalar(&mut rng);
        let mut public = Secp256k1::generator() * share;
        let mut cc = ChainCode([99u8; 32]);

        for i in 0..3 {
            let idx = DerivationIndex::normal(i);
            let (new_share, new_cc) =
                derive_child_share::<Secp256k1>(&share, &public, &cc, idx).unwrap();
            let (new_public, new_cc2) =
                derive_child_public::<Secp256k1>(&public, &cc, idx).unwrap();

            assert_eq!(Secp256k1::generator() * new_share, new_public);
            assert_eq!(new_cc.0, new_cc2.0);

            share = new_share;
            public = new_public;
            cc = new_cc;
        }
    }

    #[test]
    fn master_then_child_derivation() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let (master_key, master_cc) = derive_master::<Secp256k1>(&seed).unwrap();
        let master_public = Secp256k1::generator() * master_key;

        let (child_h, _) = derive_child_share::<Secp256k1>(
            &master_key,
            &master_public,
            &master_cc,
            DerivationIndex::hardened(0),
        )
        .unwrap();
        assert!(!bool::from(Field::is_zero(&child_h)));

        let (child_n, child_cc) = derive_child_share::<Secp256k1>(
            &master_key,
            &master_public,
            &master_cc,
            DerivationIndex::normal(0),
        )
        .unwrap();
        let (child_pub, _) = derive_child_public::<Secp256k1>(
            &master_public,
            &master_cc,
            DerivationIndex::normal(0),
        )
        .unwrap();

        assert_eq!(Secp256k1::generator() * child_n, child_pub);
        assert!(!bool::from(Field::is_zero(&child_n)));
        assert_ne!(child_h, child_n);
        assert_eq!(child_cc.0.len(), 32);
    }

    #[test]
    fn index_constructors() {
        let normal = DerivationIndex::normal(42);
        assert!(!normal.is_hardened());
        assert_eq!(normal.0, 42);

        let hardened = DerivationIndex::hardened(42);
        assert!(hardened.is_hardened());
        assert_eq!(hardened.0, 42 | 0x8000_0000);
    }

    #[test]
    #[should_panic(expected = "normal index must be < 2^31")]
    fn normal_index_overflow_panics() {
        let _ = DerivationIndex::normal(0x8000_0000);
    }

    #[test]
    #[should_panic(expected = "hardened base index must be < 2^31")]
    fn hardened_index_overflow_panics() {
        let _ = DerivationIndex::hardened(0x8000_0000);
    }
}
