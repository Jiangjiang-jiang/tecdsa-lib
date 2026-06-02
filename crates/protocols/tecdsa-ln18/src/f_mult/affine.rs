// SPDX-License-Identifier: MIT OR Apache-2.0
//! Protocol 4.6 — $\mathcal{F}_\text{mult}$.affine: compute $b = a \cdot x + y$ locally.
//!
//! Given stored input for $a$ (sid1), compute $b = a \cdot x + y$ for known
//! scalars $x, y$ with **no communication**:
//!
//! 1. $U' = x \cdot U$, $V' = x \cdot V + y \cdot G$
//! 2. For each party: $U'_j = x \cdot U_j$, $V'_j = x \cdot V_j + \frac{y}{n} \cdot G$
//! 3. Update own share: $a'_i = a_i \cdot x + \frac{y}{n}$, $s'_i = x \cdot s_i$
//!
//! **Output:** Updated stored state for sid2.

use elliptic_curve::{sec1::ModulusSize, Field, FieldBytes, FieldBytesSize, PrimeField};
use tecdsa_curve::{elgamal_exp::EgexpCiphertext, TecdsaCurve};
use tecdsa_protocol::PartyId;

/// Input for the affine sub-protocol, taken from a previous `input` output.
pub struct AffineInput<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Aggregate ciphertext $(U, V)$, an encryption of $a = \sum_j a_j$.
    pub ciphertext: EgexpCiphertext<C>,
    /// Own additive share $a_i$.
    pub a_i: C::Scalar,
    /// Own encryption randomness $s_i$.
    pub s_i: C::Scalar,
    /// Per-party ciphertexts $(U_j, V_j)$.
    pub per_party_cts: Vec<(PartyId, EgexpCiphertext<C>)>,
}

/// Output of the affine sub-protocol: updated state for the new value $b = a \cdot x + y$.
pub struct AffineOutput<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Updated aggregate ciphertext $(U', V')$, an encryption of $b = a \cdot x + y$.
    pub ciphertext: EgexpCiphertext<C>,
    /// Updated own share $a'_i = a_i \cdot x + \frac{y}{n}$.
    pub a_i: C::Scalar,
    /// Updated encryption randomness $s'_i = x \cdot s_i$.
    pub s_i: C::Scalar,
    /// Updated per-party ciphertexts.
    pub per_party_cts: Vec<(PartyId, EgexpCiphertext<C>)>,
}

/// Perform the affine transformation $b = a \cdot x + y$ locally, with no communication.
///
/// - `input`: stored state from a previous `input` call
/// - `x`: scalar multiplier
/// - `y`: scalar addend
/// - `n`: total number of parties
///
/// The additive offset $y$ is split equally among all $n$ parties as $\frac{y}{n}$.
pub fn affine<C: TecdsaCurve>(
    input: AffineInput<C>,
    x: &C::Scalar,
    y: &C::Scalar,
    n: u16,
) -> AffineOutput<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let g = C::generator();

    // Compute y/n: invert n in the scalar field
    let n_scalar = scalar_from_u16::<C>(n);
    let n_inv: C::Scalar = {
        let ct_opt = n_scalar.invert();
        let opt: Option<C::Scalar> = ct_opt.into();
        opt.expect("n must be invertible in the scalar field")
    };
    let y_over_n = *y * n_inv;

    // Update aggregate ciphertext: U' = x*U, V' = x*V + y*G
    let ciphertext = EgexpCiphertext::<C> {
        a: input.ciphertext.a * x,
        b: input.ciphertext.b * x + g * y,
    };

    // Update per-party ciphertexts: U'_j = x*U_j, V'_j = x*V_j + (y/n)*G
    let per_party_cts: Vec<(PartyId, EgexpCiphertext<C>)> = input
        .per_party_cts
        .iter()
        .map(|(pid, ct)| {
            let new_ct = EgexpCiphertext::<C> {
                a: ct.a * x,
                b: ct.b * x + g * y_over_n,
            };
            (*pid, new_ct)
        })
        .collect();

    // Update own share: a'_i = a_i * x + y/n
    let a_i = input.a_i * x + y_over_n;

    // Update own randomness: s'_i = x * s_i
    let s_i = *x * input.s_i;

    AffineOutput {
        ciphertext,
        a_i,
        s_i,
        per_party_cts,
    }
}

/// Convert a `u16` to a scalar field element.
fn scalar_from_u16<C: TecdsaCurve>(val: u16) -> C::Scalar
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let mut bytes = FieldBytes::<C>::default();
    let len = bytes.len();
    // Write val as big-endian in the last 2 bytes
    bytes[len - 2] = (val >> 8) as u8;
    bytes[len - 1] = val as u8;
    Option::from(<C::Scalar as PrimeField>::from_repr(bytes))
        .expect("small u16 value must be representable as a scalar")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "secp256k1")]
    type C = k256::Secp256k1;

    /// Test the affine transformation: input a, compute affine(x, y), verify the result.
    ///
    /// Runs init -> input -> affine, then verifies that the updated ciphertext
    /// decrypts to `(a*x + y) * G` and that per-party invariants hold.
    #[test]
    #[cfg(feature = "secp256k1")]
    fn affine_basic() {
        use crate::f_mult::init::InitState;
        use crate::f_mult::input::InputState;

        let mut rng = rand::thread_rng();
        let n: usize = 3;
        let parties: Vec<PartyId> = (0..n).map(|i| PartyId(i as u16)).collect();

        // --- Phase 1: init ---
        let mut init_states: Vec<InitState<C>> = Vec::with_capacity(n);
        let mut r1_msgs = Vec::with_capacity(n);
        for i in 0..n {
            let (state, msg) = InitState::<C>::new(parties[i], parties.clone(), &mut rng);
            init_states.push(state);
            r1_msgs.push(msg);
        }

        let mut r2_msgs = Vec::with_capacity(n);
        for i in 0..n {
            let others: Vec<_> = r1_msgs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, m)| m.clone())
                .collect();
            let r2 = init_states[i]
                .handle_round1(&others)
                .expect("init Round-1 should succeed");
            r2_msgs.push(r2);
        }

        let mut init_outputs = Vec::with_capacity(n);
        for i in 0..n {
            let others: Vec<_> = r2_msgs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, m)| m.clone())
                .collect();
            let output = init_states[i]
                .finish_round2(&others)
                .expect("init Round-2 should succeed");
            init_outputs.push(output);
        }

        let elgamal_pk = init_outputs[0].elgamal_pk;

        // --- Phase 2: input ---
        let shares: Vec<<C as elliptic_curve::CurveArithmetic>::Scalar> =
            (0..n).map(|_| C::random_scalar(&mut rng)).collect();

        let mut input_states: Vec<InputState<C>> = Vec::with_capacity(n);
        let mut input_r1_msgs = Vec::with_capacity(n);
        for i in 0..n {
            let (state, msg) =
                InputState::<C>::new(parties[i], parties.clone(), elgamal_pk, shares[i], &mut rng);
            input_states.push(state);
            input_r1_msgs.push(msg);
        }

        let mut input_r2_msgs = Vec::with_capacity(n);
        for i in 0..n {
            let others: Vec<_> = input_r1_msgs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, m)| m.clone())
                .collect();
            let r2 = input_states[i]
                .handle_round1(&others)
                .expect("input Round-1 should succeed");
            input_r2_msgs.push(r2);
        }

        let mut input_outputs = Vec::with_capacity(n);
        for i in 0..n {
            let others: Vec<_> = input_r2_msgs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, m)| m.clone())
                .collect();
            let output = input_states[i]
                .finish_round2(&others)
                .expect("input Round-2 should succeed");
            input_outputs.push(output);
        }

        // --- Phase 3: affine with x=2, y=3 ---
        let x = scalar_from_u16::<C>(2);
        let y = scalar_from_u16::<C>(3);

        let mut affine_outputs: Vec<AffineOutput<C>> = Vec::with_capacity(n);
        for i in 0..n {
            let aff_input = AffineInput::<C> {
                ciphertext: input_outputs[i].ciphertext.clone(),
                a_i: input_outputs[i].a_i,
                s_i: input_outputs[i].s_i,
                per_party_cts: input_outputs[i].per_party_cts.clone(),
            };
            let output = affine::<C>(aff_input, &x, &y, n as u16);
            affine_outputs.push(output);
        }

        // Verify: all parties compute the same aggregate ciphertext
        let ct0 = &affine_outputs[0].ciphertext;
        for output in &affine_outputs[1..] {
            assert_eq!(
                output.ciphertext, *ct0,
                "all parties must agree on the affine-transformed ciphertext"
            );
        }

        // Verify: the updated ciphertext decrypts to (a*x + y)*G
        let d: <C as elliptic_curve::CurveArithmetic>::Scalar = init_outputs
            .iter()
            .map(|o| o.d_i)
            .reduce(|acc, d| acc + d)
            .unwrap();

        let decrypted = ct0.decrypt_to_point(&d);
        let a_sum: <C as elliptic_curve::CurveArithmetic>::Scalar =
            shares.iter().copied().reduce(|acc, s| acc + s).unwrap();
        let expected_val = a_sum * x + y;
        let expected_point = C::generator() * expected_val;
        assert_eq!(
            decrypted, expected_point,
            "affine-transformed ciphertext must decrypt to (a*x + y) * G"
        );

        // Verify: sum of updated shares equals a*x + y
        let share_sum: <C as elliptic_curve::CurveArithmetic>::Scalar = affine_outputs
            .iter()
            .map(|o| o.a_i)
            .reduce(|acc, s| acc + s)
            .unwrap();
        assert_eq!(
            share_sum, expected_val,
            "sum of updated shares must equal a*x + y"
        );

        // Verify: updated randomness s'_i = x * s_i
        for i in 0..n {
            let expected_s = x * input_outputs[i].s_i;
            assert_eq!(
                affine_outputs[i].s_i, expected_s,
                "updated randomness must equal x * s_i"
            );
        }

        // Verify: per-party ciphertext count is preserved
        for output in &affine_outputs {
            assert_eq!(
                output.per_party_cts.len(),
                n,
                "should have n per-party ciphertexts"
            );
        }
    }

    /// Test affine with identity transformation: x=1, y=0 should not change the value.
    #[test]
    #[cfg(feature = "secp256k1")]
    fn affine_identity() {
        use crate::f_mult::init::InitState;
        use crate::f_mult::input::InputState;
        use elliptic_curve::Field;

        let mut rng = rand::thread_rng();
        let n: usize = 2;
        let parties: Vec<PartyId> = (0..n).map(|i| PartyId(i as u16)).collect();

        // --- init ---
        let mut init_states: Vec<InitState<C>> = Vec::with_capacity(n);
        let mut r1_msgs = Vec::with_capacity(n);
        for i in 0..n {
            let (state, msg) = InitState::<C>::new(parties[i], parties.clone(), &mut rng);
            init_states.push(state);
            r1_msgs.push(msg);
        }

        let mut r2_msgs = Vec::with_capacity(n);
        for i in 0..n {
            let others: Vec<_> = r1_msgs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, m)| m.clone())
                .collect();
            let r2 = init_states[i].handle_round1(&others).unwrap();
            r2_msgs.push(r2);
        }

        let mut init_outputs = Vec::with_capacity(n);
        for i in 0..n {
            let others: Vec<_> = r2_msgs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, m)| m.clone())
                .collect();
            let output = init_states[i].finish_round2(&others).unwrap();
            init_outputs.push(output);
        }

        let elgamal_pk = init_outputs[0].elgamal_pk;

        // --- input ---
        let shares: Vec<<C as elliptic_curve::CurveArithmetic>::Scalar> =
            (0..n).map(|_| C::random_scalar(&mut rng)).collect();

        let mut input_states: Vec<InputState<C>> = Vec::with_capacity(n);
        let mut input_r1_msgs = Vec::with_capacity(n);
        for i in 0..n {
            let (state, msg) =
                InputState::<C>::new(parties[i], parties.clone(), elgamal_pk, shares[i], &mut rng);
            input_states.push(state);
            input_r1_msgs.push(msg);
        }

        let mut input_r2_msgs = Vec::with_capacity(n);
        for i in 0..n {
            let others: Vec<_> = input_r1_msgs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, m)| m.clone())
                .collect();
            let r2 = input_states[i].handle_round1(&others).unwrap();
            input_r2_msgs.push(r2);
        }

        let mut input_outputs = Vec::with_capacity(n);
        for i in 0..n {
            let others: Vec<_> = input_r2_msgs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, m)| m.clone())
                .collect();
            let output = input_states[i].finish_round2(&others).unwrap();
            input_outputs.push(output);
        }

        // --- affine with x=1, y=0 (identity) ---
        let x = <<C as elliptic_curve::CurveArithmetic>::Scalar as Field>::ONE;
        let y = <<C as elliptic_curve::CurveArithmetic>::Scalar as Field>::ZERO;

        let d: <C as elliptic_curve::CurveArithmetic>::Scalar = init_outputs
            .iter()
            .map(|o| o.d_i)
            .reduce(|acc, d| acc + d)
            .unwrap();

        // Original decrypted value
        let original_decrypted = input_outputs[0].ciphertext.decrypt_to_point(&d);

        let aff_input = AffineInput::<C> {
            ciphertext: input_outputs[0].ciphertext.clone(),
            a_i: input_outputs[0].a_i,
            s_i: input_outputs[0].s_i,
            per_party_cts: input_outputs[0].per_party_cts.clone(),
        };
        let output = affine::<C>(aff_input, &x, &y, n as u16);
        let new_decrypted = output.ciphertext.decrypt_to_point(&d);

        assert_eq!(
            original_decrypted, new_decrypted,
            "identity affine transformation should not change the plaintext"
        );
    }
}
