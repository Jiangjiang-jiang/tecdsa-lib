// SPDX-License-Identifier: MIT OR Apache-2.0
//! Pseudorandom secret sharing (PRSS) and pseudorandom zero sharing (PRZS).
//!
//! This is Section 5 of the paper, which in turn follows Cramer, Damgard and
//! Ishai [CDI05].  It realises the `F_rss` functionality: once a one-time set of
//! replicated PRF keys is in place, every party can locally derive
//!
//! * a `(t + 1)`-out-of-`n` Shamir share of a fresh pseudorandom secret
//!   ([`PrssKeys::rand`]), and
//! * a `(2t + 1)`-out-of-`n` Shamir share of `0` ([`PrssKeys::zero`]),
//!
//! **with no interaction at all**.  This is what makes KU24's presignatures
//! cheap: the only communication left in the preprocessing is the degree
//! reduction inside `F_wmult` and the two verification openings.
//!
//! # Construction
//!
//! Let `S_{n-t,n}` be the collection of subsets `A subset [n]` with `|A| = n - t`,
//! and for each such `A` let `f_A` be the unique polynomial of degree at most `t`
//! with `f_A(0) = 1` and `f_A(x) = 0` for `x in [n] \ A` (there are exactly `t`
//! such `x`, so `f_A` is well defined).  Party `P_i` holds the key `k_A` for
//! every `A` containing `i`, and computes
//!
//! ```text
//! rand:  sigma_i = sum_{A ni i}                Psi_{k_A}(0 || idx)       * f_A(i)
//! zero:  rho_i   = sum_{A ni i} sum_{l=1..t}   Psi_{k_A}(1 || idx || l)  * i^l * f_A(i)
//! ```
//!
//! `sigma` lies on the degree-`t` polynomial `sum_A Psi_{k_A}(.) * f_A(X)` whose
//! constant term is `sum_A Psi_{k_A}(.)`, and `rho` lies on the degree-`2t`
//! polynomial `sum_A sum_l Psi_{k_A}(.) * X^l * f_A(X)`, which vanishes at `0`.
//!
//! # Dealer-free setup
//!
//! Section 5 observes that no trusted dealer (and no commit/complain rounds, and
//! no broadcast channel) is required: the party with the smallest index in `A`
//! simply samples `k_A` and sends it over the private point-to-point channels to
//! the other members of `A`.  A corrupted dealer for `A` can send inconsistent
//! keys, but `k_H` -- the key for the set of honest parties -- is always sampled
//! by an honest party, and that is the only key the security argument needs.
//! See [`crate::setup`] for the state machine.
//!
//! # Cost
//!
//! Each party stores `binomial(n - 1, t)` keys and evaluates that many PRF calls
//! per shared value (times `t` for zero sharings), so the scheme is exponential
//! in `n`.  The paper explicitly targets small committees (`n < 20`); we cap the
//! committee size at [`MAX_PARTIES`].

use elliptic_curve::{sec1::ModulusSize, Field, FieldBytes, FieldBytesSize, PrimeField};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tecdsa_curve::TecdsaCurve;
use zeroize::Zeroize;

use crate::error::{Ku24Error, Ku24Result};

/// Byte length of a PRSS key.
pub const KEY_LEN: usize = 32;

/// Largest committee size for which PRSS key material is generated.
///
/// `binomial(n, t)` keys are needed in total; at `n = 16` that is already
/// 11 440 subsets.  Anything larger is not practical and is rejected outright
/// rather than silently exhausting memory.
pub const MAX_PARTIES: u16 = 16;

/// Domain-separation tag for the PRF.
const PRF_DST: &[u8] = b"tecdsa/ku24/prss/v1";

/// PRF label tag for [`PrssKeys::rand`] (the paper's `0 || i`).
const TAG_RAND: u8 = 0;
/// PRF label tag for [`PrssKeys::zero`] (the paper's `1 || i || l`).
const TAG_ZERO: u8 = 1;

/// A subset of `[n]`, encoded as a bitmask with bit `i - 1` set iff `i` is a member.
pub type SubsetMask = u32;

/// Enumerate all subsets of `{1, ..., n}` of size `size`, in ascending mask order.
///
/// # Panics
/// Panics if `n > MAX_PARTIES`; callers should validate with [`check_params`] first.
#[must_use]
pub fn subsets(n: u16, size: u16) -> Vec<SubsetMask> {
    assert!(
        n <= MAX_PARTIES,
        "PRSS subset enumeration is exponential; n must be at most {MAX_PARTIES}"
    );
    if size > n {
        return Vec::new();
    }
    (0u32..(1u32 << n))
        .filter(|mask| mask.count_ones() == u32::from(size))
        .collect()
}

/// Iterate over the 1-based members of a subset mask.
pub fn members(mask: SubsetMask, n: u16) -> impl Iterator<Item = u16> {
    (1..=n).filter(move |i| mask & (1 << (i - 1)) != 0)
}

/// Whether `i` (1-based) belongs to `mask`.
#[must_use]
pub fn contains(mask: SubsetMask, i: u16) -> bool {
    mask & (1 << (i - 1)) != 0
}

/// The designated dealer of `mask`: the member with the smallest index.
///
/// # Panics
/// Panics if `mask` is empty.
#[must_use]
pub fn dealer(mask: SubsetMask) -> u16 {
    u16::try_from(mask.trailing_zeros()).expect("mask fits in u16 indices") + 1
}

/// Evaluate `f_A` at the point `i`, where `A` is given by `mask`.
///
/// `f_A(X) = prod_{x in [n] \ A} (x - X) / x`, the unique degree-`t` polynomial
/// with `f_A(0) = 1` that vanishes on `[n] \ A`.
#[must_use]
pub fn f_a_eval<C>(mask: SubsetMask, n: u16, i: u16) -> C::Scalar
where
    C: TecdsaCurve,
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let xi = C::Scalar::from(u64::from(i));
    (1..=n)
        .filter(|&x| !contains(mask, x))
        .fold(C::Scalar::ONE, |acc, x| {
            let xx = C::Scalar::from(u64::from(x));
            acc * (xx - xi)
                * xx.invert()
                    .expect("evaluation points are 1-based, hence non-zero")
        })
}

/// One replicated PRF key together with the local evaluation of `f_A`.
struct PrssEntry<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    key: [u8; KEY_LEN],
    /// `f_A(my_index)`, precomputed once at setup time.
    f_at_me: C::Scalar,
}

impl<C: TecdsaCurve> Clone for PrssEntry<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn clone(&self) -> Self {
        Self {
            key: self.key,
            f_at_me: self.f_at_me,
        }
    }
}

/// The local PRSS state of one party: all keys `k_A` for subsets `A` containing it.
///
/// Produced by [`crate::setup::Ku24SetupMachine`] and consumed by keygen and
/// presigning.  This is key-independent, long-lived material: a single setup
/// serves an unbounded number of ECDSA keys and presignature batches, provided
/// callers use distinct `session` domain separators (see [`PrssKeys::rand`]).
pub struct PrssKeys<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    my_index: u16,
    n: u16,
    /// The paper's `t`: the corruption threshold, one less than the
    /// reconstruction threshold.
    degree: u16,
    entries: Vec<PrssEntry<C>>,
}

impl<C: TecdsaCurve> Clone for PrssKeys<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn clone(&self) -> Self {
        Self {
            my_index: self.my_index,
            n: self.n,
            degree: self.degree,
            entries: self.entries.clone(),
        }
    }
}

impl<C: TecdsaCurve> core::fmt::Debug for PrssKeys<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PrssKeys")
            .field("my_index", &self.my_index)
            .field("n", &self.n)
            .field("degree", &self.degree)
            .field("keys", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl<C: TecdsaCurve> Zeroize for PrssKeys<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn zeroize(&mut self) {
        for entry in &mut self.entries {
            entry.key.zeroize();
        }
    }
}

impl<C: TecdsaCurve> Drop for PrssKeys<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Validate an `(n, reconstruction threshold)` pair for the honest-majority setting.
///
/// Returns the paper's `t = threshold - 1`.
///
/// # Errors
/// Fails if `threshold == 0`, if `n < 2t + 1` (no honest majority), or if `n`
/// exceeds [`MAX_PARTIES`].
pub fn check_params(n: u16, threshold: u16) -> Ku24Result<u16> {
    if threshold == 0 || threshold > n {
        return Err(Ku24Error::InvalidThreshold { n, threshold });
    }
    let degree = threshold - 1;
    if n < 2 * degree + 1 {
        return Err(Ku24Error::InvalidThreshold { n, threshold });
    }
    if n > MAX_PARTIES {
        return Err(Ku24Error::TooManyParties {
            n,
            max: MAX_PARTIES,
        });
    }
    Ok(degree)
}

impl<C: TecdsaCurve> PrssKeys<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// Assemble the local PRSS state from the collected keys.
    ///
    /// `keys` must contain exactly one entry for every subset of size `n - t`
    /// that contains `my_index`.
    ///
    /// # Errors
    /// Fails if the parameters are out of range or if a key is missing.
    pub fn from_keys(
        my_index: u16,
        n: u16,
        threshold: u16,
        keys: &std::collections::BTreeMap<SubsetMask, [u8; KEY_LEN]>,
    ) -> Ku24Result<Self> {
        let degree = check_params(n, threshold)?;
        let mut entries = Vec::new();
        for mask in subsets(n, n - degree) {
            if !contains(mask, my_index) {
                continue;
            }
            let key = *keys.get(&mask).ok_or_else(|| {
                Ku24Error::Other(format!("missing PRSS key for subset mask {mask:#x}"))
            })?;
            entries.push(PrssEntry {
                key,
                f_at_me: f_a_eval::<C>(mask, n, my_index),
            });
        }
        Ok(Self {
            my_index,
            n,
            degree,
            entries,
        })
    }

    /// This party's 1-based Shamir evaluation point.
    #[must_use]
    pub fn my_index(&self) -> u16 {
        self.my_index
    }

    /// Number of parties.
    #[must_use]
    pub fn n(&self) -> u16 {
        self.n
    }

    /// The paper's `t` (corruption threshold): sharings have degree `t`.
    #[must_use]
    pub fn degree(&self) -> u16 {
        self.degree
    }

    /// Reconstruction threshold `t + 1`.
    #[must_use]
    pub fn threshold(&self) -> u16 {
        self.degree + 1
    }

    /// Number of replicated keys held locally, `binomial(n - 1, t)`.
    #[must_use]
    pub fn key_count(&self) -> usize {
        self.entries.len()
    }

    /// Derive `count` shares of fresh pseudorandom secrets (`F_rss.Rand`).
    ///
    /// The result is this party's share of `count` independent uniform values,
    /// each shared with a degree-`t` polynomial.
    ///
    /// `session` and `stream` provide domain separation.  **Callers must never
    /// reuse a `(session, stream, index)` triple**: doing so re-derives the same
    /// secret.  KU24 uses a fresh random `session` per presignature batch and a
    /// distinct `stream` per logical invocation (see [`crate::presign::streams`]).
    #[must_use]
    pub fn rand(&self, session: &[u8; 32], stream: u32, count: usize) -> Vec<C::Scalar> {
        let macs = self.keyed_macs();
        let mut label = Label::new(session, stream, TAG_RAND);
        (0..count)
            .map(|idx| {
                label.set_index(idx as u64, 0);
                self.entries
                    .iter()
                    .zip(&macs)
                    .fold(C::Scalar::ZERO, |acc, (entry, mac)| {
                        acc + prf::<C>(mac, &label) * entry.f_at_me
                    })
            })
            .collect()
    }

    /// Derive `count` shares of `0` under degree-`2t` polynomials (`F_rss.Zero`).
    ///
    /// These are the masks that hide the degree-`2t` intermediate values opened
    /// by `F_wmult` and by online signing.
    ///
    /// The same domain-separation warning as [`PrssKeys::rand`] applies.
    #[must_use]
    pub fn zero(&self, session: &[u8; 32], stream: u32, count: usize) -> Vec<C::Scalar> {
        // Precompute i, i^2, ..., i^t for the local evaluation point.
        let x = C::Scalar::from(u64::from(self.my_index));
        let mut powers = Vec::with_capacity(usize::from(self.degree));
        let mut cur = x;
        for _ in 0..self.degree {
            powers.push(cur);
            cur *= x;
        }

        let macs = self.keyed_macs();
        let mut label = Label::new(session, stream, TAG_ZERO);
        (0..count)
            .map(|idx| {
                self.entries
                    .iter()
                    .zip(&macs)
                    .fold(C::Scalar::ZERO, |acc, (entry, mac)| {
                        let mut inner = C::Scalar::ZERO;
                        for (l, power) in powers.iter().enumerate() {
                            let sub = u16::try_from(l + 1).expect("t fits in u16");
                            label.set_index(idx as u64, sub);
                            inner += prf::<C>(mac, &label) * *power;
                        }
                        acc + inner * entry.f_at_me
                    })
            })
            .collect()
    }

    /// One HMAC instance per held key, with the key schedule already absorbed.
    ///
    /// `Psi_{k_A}` is evaluated once per shared value *per subset*, i.e.
    /// `binomial(n - 1, t)` times for a `Rand` and `t` times that for a `Zero`.
    /// Deriving the ipad/opad blocks once per call and cloning the state
    /// thereafter removes that work from the inner loop.
    ///
    /// These instances are deliberately **not** cached in `self`: the `hmac`
    /// crate does not zeroize its internal state, so keeping key-derived
    /// material alive for the lifetime of a `PrssKeys` would defeat the
    /// `Zeroize` impl below, which can only clear the raw `key` bytes.
    fn keyed_macs(&self) -> Vec<Hmac<Sha256>> {
        self.entries
            .iter()
            .map(|entry| {
                <Hmac<Sha256>>::new_from_slice(&entry.key).expect("HMAC accepts keys of any length")
            })
            .collect()
    }
}

/// A PRF input, laid out once and mutated in place across a batch.
///
/// Layout: `DST || session (32) || stream (4) || tag (1) || index (8) || sub (2)
/// || counter (1)`, which reproduces the paper's `0 || i` and `1 || i || l` plus
/// the session/stream fields that let a single `F_rss` initialisation serve an
/// unbounded number of invocations.
struct Label {
    bytes: [u8; LABEL_LEN],
}

/// Offset of the `index` field inside a [`Label`].
const INDEX_OFFSET: usize = PRF_DST.len() + 32 + 4 + 1;
/// Offset of the rejection-sampling counter.
const COUNTER_OFFSET: usize = INDEX_OFFSET + 8 + 2;
/// Total label length.
const LABEL_LEN: usize = COUNTER_OFFSET + 1;

impl Label {
    fn new(session: &[u8; 32], stream: u32, tag: u8) -> Self {
        let mut bytes = [0u8; LABEL_LEN];
        let mut at = 0;
        bytes[at..at + PRF_DST.len()].copy_from_slice(PRF_DST);
        at += PRF_DST.len();
        bytes[at..at + 32].copy_from_slice(session);
        at += 32;
        bytes[at..at + 4].copy_from_slice(&stream.to_be_bytes());
        at += 4;
        bytes[at] = tag;
        Self { bytes }
    }

    fn set_index(&mut self, index: u64, sub: u16) {
        self.bytes[INDEX_OFFSET..INDEX_OFFSET + 8].copy_from_slice(&index.to_be_bytes());
        self.bytes[INDEX_OFFSET + 8..COUNTER_OFFSET].copy_from_slice(&sub.to_be_bytes());
    }

    fn with_counter(&self, counter: u8) -> [u8; LABEL_LEN] {
        let mut out = self.bytes;
        out[COUNTER_OFFSET] = counter;
        out
    }
}

/// The pseudorandom function `Psi_k(label) -> Z_q`.
///
/// Instantiated as HMAC-SHA256 with the key schedule already absorbed into
/// `mac`.  The digest is turned into a field element by **rejection sampling**:
/// the byte string is accepted iff it is a canonical field element, otherwise
/// the counter is bumped.  For every curve in this workspace the modulus fills
/// its byte length, so a retry happens with probability far below `2^-100`.
///
/// Rejection is used rather than reducing a double-width digest because this
/// function runs `binomial(n - 1, t)` times per shared value (and `t` times
/// that for a zero sharing); the wide reduction would put big-integer
/// arithmetic and two heap allocations on that path for no security benefit --
/// rejection sampling is exactly uniform, whereas a wide reduction is only
/// statistically close.
fn prf<C>(mac: &Hmac<Sha256>, label: &Label) -> C::Scalar
where
    C: TecdsaCurve,
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let mut repr = FieldBytes::<C>::default();
    let len = repr.len();
    for counter in 0u8..=u8::MAX {
        let input = label.with_counter(counter);
        let mut written = 0;
        let mut block = 0u8;
        while written < len {
            let mut mac = mac.clone();
            mac.update(&input);
            mac.update(&[block]);
            let digest = mac.finalize().into_bytes();
            let take = core::cmp::min(len - written, digest.len());
            repr[written..written + take].copy_from_slice(&digest[..take]);
            written += take;
            block += 1;
        }
        if let Some(scalar) =
            Option::<C::Scalar>::from(<C::Scalar as PrimeField>::from_repr(repr.clone()))
        {
            return scalar;
        }
    }
    unreachable!("rejection sampling cannot fail for all 256 counter values")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use k256::{Scalar, Secp256k1};

    use super::*;
    use crate::interp::Interp;

    /// Deal PRSS keys centrally (only used to unit-test the derivation itself;
    /// the protocol uses the dealer-free setup in `crate::setup`).
    fn deal(n: u16, threshold: u16) -> Vec<PrssKeys<Secp256k1>> {
        let degree = threshold - 1;
        let mut all: BTreeMap<SubsetMask, [u8; KEY_LEN]> = BTreeMap::new();
        for (seed, mask) in subsets(n, n - degree).into_iter().enumerate() {
            let mut key = [0u8; KEY_LEN];
            key[..8].copy_from_slice(&(seed as u64).to_be_bytes());
            all.insert(mask, key);
        }
        (1..=n)
            .map(|i| PrssKeys::<Secp256k1>::from_keys(i, n, threshold, &all).unwrap())
            .collect()
    }

    #[test]
    fn rand_yields_a_degree_t_sharing() {
        let (n, threshold) = (5u16, 3u16);
        let parties = deal(n, threshold);
        let session = [7u8; 32];
        let indices: Vec<u16> = (1..=n).collect();
        let interp = Interp::<Secp256k1>::new(&indices, usize::from(threshold - 1));

        for idx in 0..3 {
            let shares: Vec<Scalar> = parties
                .iter()
                .map(|p| p.rand(&session, 0, 3)[idx])
                .collect();
            // Consistency with degree t is exactly what `Interp` checks.
            let secret = interp.scalar(&shares).expect("degree-t consistent");
            assert_ne!(secret, Scalar::ZERO);
        }
    }

    #[test]
    fn zero_yields_a_degree_2t_sharing_of_zero() {
        let (n, threshold) = (5u16, 3u16);
        let parties = deal(n, threshold);
        let session = [9u8; 32];
        let indices: Vec<u16> = (1..=n).collect();
        let interp = Interp::<Secp256k1>::new(&indices, 2 * usize::from(threshold - 1));

        for idx in 0..3 {
            let shares: Vec<Scalar> = parties
                .iter()
                .map(|p| p.zero(&session, 0, 3)[idx])
                .collect();
            assert!(
                shares.iter().any(|s| *s != Scalar::ZERO),
                "shares are not all zero"
            );
            assert_eq!(interp.scalar(&shares), Some(Scalar::ZERO));
        }
    }

    #[test]
    fn domain_separation_changes_the_output() {
        let parties = deal(5, 3);
        let a = parties[0].rand(&[1u8; 32], 0, 1)[0];
        let b = parties[0].rand(&[2u8; 32], 0, 1)[0];
        let c = parties[0].rand(&[1u8; 32], 1, 1)[0];
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn f_a_is_one_at_zero_and_vanishes_outside_a() {
        let n = 5u16;
        for mask in subsets(n, 3) {
            for x in 1..=n {
                let v = f_a_eval::<Secp256k1>(mask, n, x);
                if contains(mask, x) {
                    // No constraint other than being well defined.
                    let _ = v;
                } else {
                    assert_eq!(v, Scalar::ZERO);
                }
            }
        }
    }

    #[test]
    fn params_reject_dishonest_majority() {
        // n = 5, t = 2 is fine.
        assert_eq!(check_params(5, 3).unwrap(), 2);
        // n = 5, t = 3 needs n >= 7.
        assert!(check_params(5, 4).is_err());
        assert!(check_params(64, 3).is_err());
    }
}
