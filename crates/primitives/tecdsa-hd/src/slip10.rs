// SPDX-License-Identifier: MIT OR Apache-2.0
//! SLIP-10 key derivation (extends BIP-32 to non-secp256k1 curves).
//!
//! Reference: <https://github.com/satoshilabs/slips/blob/master/slip-0010.md>
//!
//! Master key generation:
//! ```text
//! I = HMAC-SHA512(Key = curve_name, Data = seed)
//! IL = master secret key, IR = master chain code
//! ```
//!
//! Child key derivation (private):
//! ```text
//! Hardened:  I = HMAC-SHA512(Key = cc, Data = 0x00 || ser256(parent_key) || ser32(i))
//! Normal:    I = HMAC-SHA512(Key = cc, Data = serP(point(parent_key)) || ser32(i))
//! child_key = parse256(IL) + parent_key  (mod n)
//! child_cc  = IR
//! ```
//!
//! Child key derivation (public, normal only):
//! ```text
//! I = HMAC-SHA512(Key = cc, Data = serP(parent_public) || ser32(i))
//! child_public = parse256(IL) * G + parent_public
//! child_cc     = IR
//! ```

use elliptic_curve::{group::GroupEncoding, sec1::ModulusSize, Field, FieldBytesSize, PrimeField};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use zeroize::Zeroize;

type HmacSha512 = Hmac<Sha512>;

/// 32-byte chain code for HD derivation.
#[derive(Clone, Zeroize)]
pub struct ChainCode(pub [u8; 32]);

/// Derivation index. Hardened indices have bit 31 set.
#[derive(Debug, Clone, Copy)]
pub struct DerivationIndex(pub u32);

impl DerivationIndex {
    /// Create a normal (non-hardened) derivation index.
    ///
    /// # Panics
    /// Panics if `index >= 2^31`.
    #[must_use]
    pub fn normal(index: u32) -> Self {
        assert!(index < 0x8000_0000, "normal index must be < 2^31");
        Self(index)
    }

    /// Create a hardened derivation index.
    ///
    /// # Panics
    /// Panics if `index >= 2^31`.
    #[must_use]
    pub fn hardened(index: u32) -> Self {
        assert!(index < 0x8000_0000, "hardened base index must be < 2^31");
        Self(index | 0x8000_0000)
    }

    /// Returns `true` if this is a hardened index (bit 31 set).
    #[must_use]
    pub fn is_hardened(self) -> bool {
        self.0 >= 0x8000_0000
    }
}

/// SLIP-10 curve key string used for master key generation.
///
/// For secp256k1 (and BIP-32 compatibility) this is `"Bitcoin seed"`.
/// SLIP-10 defines per-curve strings; we fall back to the curve name
/// for any curve that does not have an explicit SLIP-10 mapping.
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

/// Derive the master secret key and chain code from a seed.
///
/// Per SLIP-10:
///   `I = HMAC-SHA512(Key = curve_name_key, Data = seed)`
///   Master secret = IL, Master chain code = IR.
///
/// If IL parses as zero or is >= the curve order, the spec says to retry
/// with `I = HMAC-SHA512(Key = curve_name_key, Data = I)` (SLIP-10 retry).
///
/// # Errors
/// Returns an error if the seed is shorter than 16 bytes or longer than 64 bytes.
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
        // SLIP-10: retry with I as the new data
        data.clear();
        data.extend_from_slice(&result);
    }
}

/// Derive a child key share from a parent share + chain code.
///
/// For **normal** derivation: uses the parent public key (compatible with
/// public-only derivation via [`derive_child_public`]).
///
/// For **hardened** derivation: uses the parent secret share. This requires
/// the full secret at derivation time but prevents any information leakage
/// from child public keys.
///
/// # Errors
/// Returns an error if the derived tweak scalar is invalid (>= curve order)
/// or if the resulting child key is zero (astronomically unlikely).
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
        // Hardened: HMAC-SHA512(Key=cc, Data = 0x00 || ser256(parent_share) || ser32(index))
        mac.update(&[0x00]);
        let share_repr = parent_share.to_repr();
        mac.update(share_repr.as_ref());
    } else {
        // Normal: HMAC-SHA512(Key=cc, Data = serP(parent_public) || ser32(index))
        let pub_bytes = parent_public.to_bytes();
        mac.update(pub_bytes.as_ref());
    }
    mac.update(&index.0.to_be_bytes());

    let result = mac.finalize().into_bytes();
    let (il, ir) = result.split_at(32);

    // Parse IL as a scalar (tweak)
    let tweak = parse_scalar::<C>(il)
        .ok_or_else(|| TecdsaError::Other("invalid child scalar (>= curve order)".into()))?;

    // child_share = tweak + parent_share
    let child_share = tweak + *parent_share;

    if bool::from(Field::is_zero(&child_share)) {
        return Err(TecdsaError::Other("derived child key is zero".into()));
    }

    // child_chain_code = IR
    let mut child_cc = [0u8; 32];
    child_cc.copy_from_slice(ir);

    Ok((child_share, ChainCode(child_cc)))
}

/// Derive a child public key without the secret (normal derivation only).
///
/// This is the public counterpart to [`derive_child_share`] for normal
/// (non-hardened) indices. It allows anyone who holds the parent public
/// key and chain code to compute any non-hardened child public key.
///
/// # Errors
/// Returns an error if `index` is hardened (which requires the secret key)
/// or if the derived tweak scalar is invalid.
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

    // child_public = tweak * G + parent_public
    let child_public = C::generator() * tweak + *parent_public;

    let mut child_cc = [0u8; 32];
    child_cc.copy_from_slice(ir);

    Ok((child_public, ChainCode(child_cc)))
}

/// Parse 32 bytes as a scalar in the curve's field. Returns `None` if >= order.
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
        // BIP-32 test vector 1 seed
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let (master_key, chain_code) = derive_master::<Secp256k1>(&seed).unwrap();
        // Verify the master key is non-zero and chain code is 32 bytes
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
        // Derive child from share, derive child public from public key.
        // Verify child_share * G == child_public.
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

        // Verify derived share is valid (non-zero)
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
        // Derive m/0/1/2 and verify consistency at each level.
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

        // Derive m/0'
        let (child_h, _) = derive_child_share::<Secp256k1>(
            &master_key,
            &master_public,
            &master_cc,
            DerivationIndex::hardened(0),
        )
        .unwrap();
        assert!(!bool::from(Field::is_zero(&child_h)));

        // Derive m/0
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
        // Hardened and normal should produce different keys
        assert_ne!(child_h, child_n);
        // Chain code should be valid
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
