// SPDX-License-Identifier: MIT OR Apache-2.0
//! Batch generation of key-independent presignatures.
//!
//! This module fuses the three protocols of the paper that make up the KU24
//! preprocessing phase:
//!
//! * `Pi_wmult` (Appendix A, Figure 8) -- degree reduction, secure *up to
//!   additive attacks*;
//! * `Pi_triple` (Section 4, Figure 6) -- `m` multiplication triples plus one
//!   batched verification of all of them;
//! * the presigning half of `Pi_ECDSA` (Section 3, Figure 2).
//!
//! Everything `F_rss` provides is derived locally from the PRSS setup, so the
//! whole phase costs **four rounds regardless of the batch size `m`** -- this is
//! what makes the amortized cost collapse as `m` grows.
//!
//! # What is computed
//!
//! With `a_i, k_i, r, beta <- F_rss.Rand` (degree `t`), the parties run
//!
//! | round | contents | degree opened |
//! |---|---|---|
//! | 1 | `F_wmult` on the `2m` pairs `(k_i, a_i)` and `(r, a_i)` | `2t` |
//! | 2 | `F_wmult` on the `m` pairs `(mu_i, k_i)` | `2t` |
//! | 3 | open `r` and `beta` | `t` |
//! | 4 | open `T = sum_i (tau_i - r*w_i) * beta^i`, `w_i`, and `R_i = g^{k_i}` | `t` |
//!
//! writing `w_i = k_i a_i`, `mu_i = r a_i` and `tau_i = mu_i k_i`.
//!
//! # Round ordering is security-critical
//!
//! `r` and `beta` come straight out of `F_rss`, so every party could broadcast
//! them in round 1 -- and that would be a five-rounds-into-three saving.  It
//! would also be **wrong**.  Lemma 1 needs the adversary's shifts to be
//! independent of `r` and `beta`; a rushing adversary that learned `r` before
//! the second `F_wmult` could set `delta'_i = r * d_i`, which makes
//! `T_i = k_i delta_i + delta'_i - r d_i` vanish for any shift `d_i` it likes.
//! So the challenge is opened in round 3, after both `F_wmult` calls have
//! closed, exactly as in `Pi_triple`.
//!
//! Merging `Pi_triple` step 6 (opening `T`) with `Pi_ECDSA` presigning step 4
//! (opening `w_i` and `R_i`) *is* sound and saves the fifth round: both values
//! are already determined by rounds 1-2, both openings carry the degree-`t`
//! consistency check, and Section 4 explicitly notes that when the check fails
//! the leaked `(a_i, k_i)` are just random values that need not stay private.
//!
//! # Why three weak multiplications and not four
//!
//! Chida et al.'s generic compiler would randomize *and* re-multiply every
//! product, costing `3m + 1` random values and `4m` weak multiplications for
//! `m` triples.  Section 4 observes that for ECDSA preprocessing it suffices to
//! use `2m + 2` random values and `3m` weak multiplications: the triples are
//! random and public correctness of the final ECDSA signature is checkable
//! against the public key, so the values need not stay private once cheating is
//! detected.
//!
//! # Why the check works
//!
//! `F_wmult` lets the adversary shift each product by an arbitrary constant:
//! `w_i = k_i a_i + d_i`, `mu_i = r a_i + delta_i`, `tau_i = mu_i k_i + delta'_i`.
//! Substituting into `T` makes the honest terms cancel, leaving
//! `T = sum_i (k_i delta_i + delta'_i - r d_i) * beta^i`.  Because `r`, the
//! `k_i` and `beta` are uniform and independent of the shifts, any non-zero
//! shift leaves `T != 0` except with probability at most `(m + 1) / q`
//! (Lemma 1).  Honest parties abort in that case.
//!
//! # Key independence
//!
//! Nothing above mentions a signing key: the output is a sharing of `k_i^{-1}`
//! together with `R_i = g^{k_i}`, plus a fresh degree-`2t` sharing of zero.  Any
//! of the (possibly millions of) keys hosted by the network can later be signed
//! with any unused presignature -- the property that motivates the paper.

pub mod machine;
pub mod msg;

use std::collections::BTreeMap;

use elliptic_curve::{sec1::ModulusSize, Field, FieldBytes, FieldBytesSize, PrimeField};
pub use machine::Ku24PresignMachine;
pub use msg::Ku24PresignMsg;
use tecdsa_curve::TecdsaCurve;
use zeroize::Zeroize;

use crate::{
    error::{Ku24Error, Ku24Result},
    interp::Interp,
};

/// PRSS stream identifiers used by presigning.
///
/// Each identifier labels one logical `F_rss` invocation.  Combined with the
/// per-batch session identifier they guarantee that no PRF input is ever
/// repeated, which is exactly the domain separation the paper requires in order
/// to initialise `F_rss` once and for all.
pub mod streams {
    /// `F_rss.Rand`, `2m + 2` values: `a_1..a_m`, `k_1..k_m`, then `r` and `beta`.
    pub const TRIPLE_RANDOM: u32 = 1;
    /// `F_rss.Rand`, `2m` masks for the first `F_wmult` call.
    pub const WMULT1_MASK: u32 = 2;
    /// `F_rss.Zero`, `2m` degree-`2t` zero shares for the first `F_wmult` call.
    pub const WMULT1_ZERO: u32 = 3;
    /// `F_rss.Rand`, `m` masks for the second `F_wmult` call.
    pub const WMULT2_MASK: u32 = 4;
    /// `F_rss.Zero`, `m` degree-`2t` zero shares for the second `F_wmult` call.
    pub const WMULT2_ZERO: u32 = 5;
    /// `F_rss.Zero`, `m` degree-`2t` zero shares consumed by online signing.
    pub const SIGN_ZERO: u32 = 6;
}

/// One party's share of a single key-independent presignature.
///
/// Holds `r_i = F(R_i)`, a degree-`t` share of `k_i^{-1}` and a degree-`2t`
/// share of zero.  Must be used **at most once** (see [`crate::sign`]).
pub struct Ku24Presignature<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// This party's 1-based Shamir evaluation point.
    pub party_index: u16,
    /// Number of parties the presignature was generated with.
    pub total: u16,
    /// Reconstruction threshold `t + 1`.
    pub threshold: u16,
    /// `r_i = F(R_i)`, the x-coordinate of `R_i` reduced mod `q`.
    pub r: C::Scalar,
    /// The public nonce `R_i = g^{k_i}`.
    pub big_r: C::ProjectivePoint,
    /// `k'_{i,j} = w_i^{-1} a_{i,j}`: a degree-`t` share of `k_i^{-1}`.
    pub k_inv_share: C::Scalar,
    /// `o_{i,j}`: a degree-`2t` share of `0`, masking the partial signature.
    pub zero_share: C::Scalar,
}

impl<C: TecdsaCurve> Clone for Ku24Presignature<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn clone(&self) -> Self {
        Self {
            party_index: self.party_index,
            total: self.total,
            threshold: self.threshold,
            r: self.r,
            big_r: self.big_r,
            k_inv_share: self.k_inv_share,
            zero_share: self.zero_share,
        }
    }
}

impl<C: TecdsaCurve> Zeroize for Ku24Presignature<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn zeroize(&mut self) {
        self.k_inv_share = C::Scalar::default();
        self.zero_share = C::Scalar::default();
    }
}

impl<C: TecdsaCurve> Drop for Ku24Presignature<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<C: TecdsaCurve> core::fmt::Debug for Ku24Presignature<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ku24Presignature")
            .field("party_index", &self.party_index)
            .finish_non_exhaustive()
    }
}

/// The output of one run of the presigning protocol: `m` presignatures.
pub struct Ku24PresignBatch<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// The presignatures, in generation order.
    pub presignatures: Vec<Ku24Presignature<C>>,
}

impl<C: TecdsaCurve> Ku24PresignBatch<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Number of presignatures in the batch.
    #[must_use]
    pub fn len(&self) -> usize {
        self.presignatures.len()
    }

    /// Whether the batch is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.presignatures.is_empty()
    }

    /// Borrow the presignature at `index`.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&Ku24Presignature<C>> {
        self.presignatures.get(index)
    }

    /// Consume the batch and return the presignatures.
    #[must_use]
    pub fn into_vec(self) -> Vec<Ku24Presignature<C>> {
        self.presignatures
    }
}

impl<C: TecdsaCurve> core::fmt::Debug for Ku24PresignBatch<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ku24PresignBatch")
            .field("len", &self.presignatures.len())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Round computations (pure functions, shared with the state machine)
// ---------------------------------------------------------------------------

/// Local `F_wmult` contribution: `e_j[i] = x[i] * y[i] + mask[i] + zero[i]`.
///
/// The product of two degree-`t` shares has degree `2t`; adding a degree-`t`
/// random mask and a degree-`2t` sharing of zero makes the opened value both
/// uniform and safely re-shareable at degree `t` (`w_j = e - mask_j`).
pub(crate) fn wmult_contribution<C>(
    x: &[C::Scalar],
    y: &[C::Scalar],
    mask: &[C::Scalar],
    zero: &[C::Scalar],
) -> Vec<C::Scalar>
where
    C: TecdsaCurve,
    FieldBytesSize<C>: ModulusSize,
{
    debug_assert_eq!(x.len(), y.len());
    debug_assert_eq!(x.len(), mask.len());
    debug_assert_eq!(x.len(), zero.len());
    x.iter()
        .zip(y)
        .zip(mask)
        .zip(zero)
        .map(|(((x, y), mask), zero)| *x * *y + *mask + *zero)
        .collect()
}

/// Open `count` values that were shared column-wise by all `n` parties.
///
/// `shares` maps a 1-based evaluation point to that party's vector of `count`
/// shares.  Returns the `count` reconstructed values, or an error if any column
/// is not consistent with the interpolator's degree.
pub(crate) fn open_scalars<C>(
    interp: &Interp<C>,
    n: u16,
    count: usize,
    shares: &BTreeMap<u16, Vec<C::Scalar>>,
    what: &'static str,
) -> Ku24Result<Vec<C::Scalar>>
where
    C: TecdsaCurve,
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let mut column = vec![C::Scalar::ZERO; usize::from(n)];
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        for j in 1..=n {
            column[usize::from(j) - 1] = shares[&j][i];
        }
        out.push(
            interp
                .scalar(&column)
                .ok_or(Ku24Error::InconsistentShares {
                    what,
                    degree: interp.degree(),
                })?,
        );
    }
    Ok(out)
}

/// Group-element analogue of [`open_scalars`] (interpolation "in the exponent").
pub(crate) fn open_points<C>(
    interp: &Interp<C>,
    n: u16,
    count: usize,
    shares: &BTreeMap<u16, Vec<C::ProjectivePoint>>,
    what: &'static str,
) -> Ku24Result<Vec<C::ProjectivePoint>>
where
    C: TecdsaCurve,
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let mut column = Vec::with_capacity(usize::from(n));
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        column.clear();
        for j in 1..=n {
            column.push(shares[&j][i]);
        }
        out.push(interp.point(&column).ok_or(Ku24Error::InconsistentShares {
            what,
            degree: interp.degree(),
        })?);
    }
    Ok(out)
}

/// Open a single value shared by all `n` parties.
pub(crate) fn open_scalar<C>(
    interp: &Interp<C>,
    n: u16,
    shares: &BTreeMap<u16, C::Scalar>,
    what: &'static str,
) -> Ku24Result<C::Scalar>
where
    C: TecdsaCurve,
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let column: Vec<C::Scalar> = (1..=n).map(|j| shares[&j]).collect();
    interp.scalar(&column).ok_or(Ku24Error::InconsistentShares {
        what,
        degree: interp.degree(),
    })
}

/// The batch check of `Pi_triple` step 6: `T_j = sum_i (tau_i - r * w_i) * beta^i`.
///
/// Applied to shares this yields a degree-`t` sharing of `T`; applied to the
/// reconstructed values it yields `T` itself, which is how the unit tests below
/// exercise Lemma 1 directly.
///
/// Note the exponent starts at `1`, matching the paper: a constant term would
/// make the polynomial `T(X)` able to hide a shift at index 0.
pub(crate) fn triple_check_share<C>(
    tau: &[C::Scalar],
    w: &[C::Scalar],
    r: &C::Scalar,
    beta: &C::Scalar,
) -> C::Scalar
where
    C: TecdsaCurve,
    FieldBytesSize<C>: ModulusSize,
{
    debug_assert_eq!(tau.len(), w.len());
    let mut power = *beta;
    let mut acc = C::Scalar::ZERO;
    for (tau_i, w_i) in tau.iter().zip(w) {
        acc += (*tau_i - *r * *w_i) * power;
        power *= *beta;
    }
    acc
}

#[cfg(test)]
mod tests {
    use k256::{Scalar, Secp256k1};
    use rand::rngs::OsRng;

    use super::*;

    fn rnd() -> Scalar {
        <Secp256k1 as TecdsaCurve>::random_scalar(&mut OsRng)
    }

    /// Evaluate `T` on reconstructed values, given the adversary's additive shifts.
    ///
    /// Mirrors Lemma 1: `w_i = k_i a_i + d_i`, `mu_i = r a_i + delta_i`,
    /// `tau_i = mu_i k_i + delta'_i`.
    fn t_value(
        a: &[Scalar],
        k: &[Scalar],
        r: Scalar,
        beta: Scalar,
        d: &[Scalar],
        delta: &[Scalar],
        delta_prime: &[Scalar],
    ) -> Scalar {
        let w: Vec<Scalar> = (0..a.len()).map(|i| k[i] * a[i] + d[i]).collect();
        let mu: Vec<Scalar> = (0..a.len()).map(|i| r * a[i] + delta[i]).collect();
        let tau: Vec<Scalar> = (0..a.len())
            .map(|i| mu[i] * k[i] + delta_prime[i])
            .collect();
        triple_check_share::<Secp256k1>(&tau, &w, &r, &beta)
    }

    #[test]
    fn honest_execution_yields_zero() {
        let m = 6;
        let a: Vec<Scalar> = (0..m).map(|_| rnd()).collect();
        let k: Vec<Scalar> = (0..m).map(|_| rnd()).collect();
        let zeros = vec![Scalar::ZERO; m];
        assert_eq!(
            t_value(&a, &k, rnd(), rnd(), &zeros, &zeros, &zeros),
            Scalar::ZERO
        );
    }

    /// Lemma 1: any non-zero additive shift is caught except with probability
    /// `(m + 1)/q`, which for secp256k1 means "always" in practice.
    #[test]
    fn additive_attacks_are_detected() {
        let m = 6;
        let a: Vec<Scalar> = (0..m).map(|_| rnd()).collect();
        let k: Vec<Scalar> = (0..m).map(|_| rnd()).collect();
        let zeros = vec![Scalar::ZERO; m];

        for target in 0..m {
            // Case 1 of the lemma: a shift in the product k_i a_i.
            let mut d = zeros.clone();
            d[target] = rnd();
            assert_ne!(
                t_value(&a, &k, rnd(), rnd(), &d, &zeros, &zeros),
                Scalar::ZERO,
                "shift d_{target} went undetected"
            );

            // Case 2: a shift in r a_i.
            let mut delta = zeros.clone();
            delta[target] = rnd();
            assert_ne!(
                t_value(&a, &k, rnd(), rnd(), &zeros, &delta, &zeros),
                Scalar::ZERO,
                "shift delta_{target} went undetected"
            );

            // Case 3: a shift in mu_i k_i, which survives verbatim into T_i.
            let mut delta_prime = zeros.clone();
            delta_prime[target] = rnd();
            assert_ne!(
                t_value(&a, &k, rnd(), rnd(), &zeros, &zeros, &delta_prime),
                Scalar::ZERO,
                "shift delta'_{target} went undetected"
            );
        }
    }

    /// Regression guard for the round schedule.
    ///
    /// If `r` were opened before the second `F_wmult` (say by piggybacking
    /// `Pi_triple` step 5 on round 1), a rushing adversary could pick
    /// `delta'_i = r * d_i` for the shift `d_i` it already introduced and make
    /// `T` vanish -- shipping a *wrong* triple past the check. The presign
    /// machine therefore opens `r` and `beta` only in round 3.
    #[test]
    fn knowing_r_before_choosing_delta_prime_would_break_the_check() {
        let m = 4;
        let a: Vec<Scalar> = (0..m).map(|_| rnd()).collect();
        let k: Vec<Scalar> = (0..m).map(|_| rnd()).collect();
        let r = rnd();
        let beta = rnd();

        // The adversary shifts every product, then cancels using its knowledge of r.
        let d: Vec<Scalar> = (0..m).map(|_| rnd()).collect();
        let delta_prime: Vec<Scalar> = d.iter().map(|d_i| r * d_i).collect();
        assert!(d.iter().any(|d_i| *d_i != Scalar::ZERO));

        assert_eq!(
            t_value(&a, &k, r, beta, &d, &vec![Scalar::ZERO; m], &delta_prime),
            Scalar::ZERO,
            "the cancellation must work -- this is the attack the ordering prevents"
        );
        // With r sampled independently of delta' (the real schedule), it fails.
        assert_ne!(
            t_value(
                &a,
                &k,
                rnd(),
                beta,
                &d,
                &vec![Scalar::ZERO; m],
                &delta_prime
            ),
            Scalar::ZERO
        );
    }

    /// Cancelling shifts across indices must not hide behind a bad `beta` power
    /// layout: the check starts at `beta^1`, so index 0 is not free.
    #[test]
    fn a_shift_at_index_zero_is_not_free() {
        let m = 3;
        let a: Vec<Scalar> = (0..m).map(|_| rnd()).collect();
        let k: Vec<Scalar> = (0..m).map(|_| rnd()).collect();
        let mut delta_prime = vec![Scalar::ZERO; m];
        delta_prime[0] = Scalar::ONE;
        assert_ne!(
            t_value(
                &a,
                &k,
                rnd(),
                rnd(),
                &vec![Scalar::ZERO; m],
                &vec![Scalar::ZERO; m],
                &delta_prime
            ),
            Scalar::ZERO
        );
    }
}
