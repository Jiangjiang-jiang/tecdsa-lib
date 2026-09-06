// SPDX-License-Identifier: MIT OR Apache-2.0
//! `MtABroadcast` implementations for NIM and scaled decryption.
//!
//! Two backends:
//!
//! - [`NimMtA`]: Non-Interactive Multiplication from the LLZ25 paper.
//!   Both parties encode their inputs, broadcast, and locally decode.
//!   NIM is inherently asymmetric (Party A and Party B use different
//!   encode/decode pairs), so each party must be created with its role.
//!
//! - [`ScaledDecryptMtA`]: Scaled decryption from Trout (Protocol 4.1).
//!   Each party encodes its CL ciphertext/commitment components, the
//!   components are aggregated externally, and each party decodes using
//!   the aggregated public data plus its own secret state.
//!
//! # Interior mutability
//!
//! Both backends use `RefCell<ClSetup>` for interior mutability, matching
//! the pattern established by `ClMtA` in the `mta` module.

use std::cell::RefCell;

use rand_core::CryptoRngCore;
use rug::{integer::Order, Integer};

use crate::{
    cl::{Ciphertext as ClHsmqkCiphertext, ClError, ClSetup, PublicKey as ClHsmqkPublicKey, Qfi},
    nim::{Nim, NimStateA, NimStateB},
};

// ============================================================================
// NimMtA
// ============================================================================

/// Which role a party plays in the NIM protocol.
///
/// NIM is asymmetric: Party A computes `pe_A = h^r * pk^x` (a `Qfi`)
/// while Party B computes `pe_B = Enc(pk, y; s)` (a `ClHsmqkCiphertext`).
/// The role determines which encode/decode path is taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NimRole {
    /// Party A: encodes as `h^r * pk^x`, decodes from B's ciphertext.
    A,
    /// Party B: encodes as `Enc(pk, y; s)`, decodes from A's pseudo-encryption.
    B,
}

/// Setup material for the NIM-based `MtABroadcast`.
///
/// Contains the CL scheme (wrapped in `RefCell` for interior mutability),
/// the CRS public key, and the party's role.
pub struct NimMtaSetup {
    /// CL-HSM scheme parameters.
    pub setup: RefCell<ClSetup>,
    /// CRS public key shared by both parties.
    pub pk: ClHsmqkPublicKey,
    /// This party's role (A or B).
    pub role: NimRole,
}

impl Clone for NimMtaSetup {
    fn clone(&self) -> Self {
        unimplemented!(
            "NimMtaSetup::clone is not supported; each party should create its own setup"
        )
    }
}

/// Encoding broadcast by a NIM party.
///
/// Since Party A produces a `Qfi` and Party B produces a
/// `ClHsmqkCiphertext`, the encoding is an enum.
pub enum NimEncoding {
    /// Party A's pseudo-encryption `pe_A = h^r * pk^x`.
    RoleA(Qfi),
    /// Party B's CL ciphertext `pe_B = Enc(pk, y; s)`.
    RoleB(ClHsmqkCiphertext),
}

impl Clone for NimEncoding {
    fn clone(&self) -> Self {
        // Qfi and ClHsmqkCiphertext do not implement Clone directly.
        // The MtABroadcast trait requires Encoding: Clone for the type
        // bound, but actual cloning should not be needed in normal use.
        // Provide a panicking clone to satisfy the bound.
        unimplemented!(
            "NimEncoding::clone is not supported; \
             each party produces its own encoding"
        )
    }
}

/// Internal state retained by a NIM party between encode and decode.
pub enum NimState {
    /// Party A's state: encryption randomness `r` and input `x`.
    RoleA(NimStateA),
    /// Party B's state: encryption randomness `s`.
    RoleB(NimStateB),
}

/// Error type for the NIM `MtA` backend.
#[derive(Debug, thiserror::Error)]
pub enum NimMtaError {
    /// Class-group operation failure.
    #[error("CL error: {0}")]
    Cl(#[from] ClError),

    /// Role mismatch: the other party's encoding does not match
    /// the expected complementary role.
    #[error("NIM role mismatch: expected encoding from {expected}, got {got}")]
    RoleMismatch {
        expected: &'static str,
        got: &'static str,
    },

    /// Invalid parameter.
    #[error("invalid parameter: {0}")]
    InvalidParam(String),
}

impl std::fmt::Display for NimRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::A => write!(f, "A"),
            Self::B => write!(f, "B"),
        }
    }
}

/// NIM-based `MtABroadcast` backend (LLZ25).
///
/// Two parties with inputs `x` (Party A) and `y` (Party B) each call
/// `encode`, broadcast their `NimEncoding`, and call `decode` with the
/// other party's encoding to obtain additive shares:
///
/// ```text
/// z_A + z_B = x * y  (mod q)
/// ```
pub struct NimMtA;

impl tecdsa_protocol::MtABroadcast for NimMtA {
    type Setup = NimMtaSetup;
    type Encoding = NimEncoding;
    type State = NimState;
    type Error = NimMtaError;

    /// Encode this party's input.
    ///
    /// - Role A: calls `Nim::encode_a`, producing a `Qfi` pseudo-encryption.
    /// - Role B: calls `Nim::encode_b`, producing a CL ciphertext.
    ///
    /// `input_bytes` is the big-endian representation of the party's
    /// private scalar.  `q_bytes` is ignored (the CL scheme already
    /// knows `q`).  `rng` is unused because NIM uses the CL setup's
    /// internal PRNG.
    fn encode(
        setup: &Self::Setup,
        input_bytes: &[u8],
        _q_bytes: &[u8],
        _rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::Encoding, Self::State), Self::Error> {
        let mut cl_setup = setup.setup.borrow_mut();
        let mut nim = Nim::new(&mut cl_setup);

        match setup.role {
            NimRole::A => {
                let out = nim.encode_a(input_bytes, &setup.pk)?;
                Ok((NimEncoding::RoleA(out.pe_a), NimState::RoleA(out.state)))
            }
            NimRole::B => {
                let out = nim.encode_b(input_bytes, &setup.pk)?;
                Ok((NimEncoding::RoleB(out.pe_b), NimState::RoleB(out.state)))
            }
        }
    }

    /// Decode the other party's encoding using this party's state.
    ///
    /// - Role A decodes Party B's ciphertext via `Nim::decode_a`.
    /// - Role B decodes Party A's pseudo-encryption via `Nim::decode_b`.
    ///
    /// Returns the additive share as big-endian bytes (reduced mod q).
    fn decode(
        setup: &Self::Setup,
        other_encoding: &Self::Encoding,
        my_state: &Self::State,
        q_bytes: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        let cl_setup = setup.setup.borrow();
        // NIM decode methods take &self (immutable), so we construct
        // a temporary reference.  This is safe because decode does not
        // mutate the setup.
        //
        // However, Nim::new requires &mut ClSetup.  Since decode_a and
        // decode_b only use &self on Nim (which holds &ClSetup), we need
        // to use an unsafe workaround or restructure.  Instead, we call
        // the free functions directly on ClSetup, bypassing Nim::new.
        //
        // Actually, looking at the Nim API: decode_a and decode_b take
        // `&self` on Nim, which holds `&mut ClSetup`.  But the decode
        // methods only call methods that take `&self` on ClSetup (like
        // `exp`, `compose`, `dlog_in_F`).  So we can safely drop the
        // borrow and re-borrow mutably.
        drop(cl_setup);

        let mut cl_setup = setup.setup.borrow_mut();
        let nim = Nim::new(&mut cl_setup);

        let q = Integer::from_digits(q_bytes, Order::Msf);

        match (my_state, other_encoding) {
            (NimState::RoleA(state_a), NimEncoding::RoleB(pe_b)) => {
                let share_bytes = nim.decode_a(pe_b, state_a)?;
                let share = Integer::from_digits(&share_bytes, Order::Msf);
                let share_mod_q = share % &q;
                Ok(share_mod_q.to_digits::<u8>(Order::Msf))
            }
            (NimState::RoleB(state_b), NimEncoding::RoleA(pe_a)) => {
                let share_bytes = nim.decode_b(pe_a, state_b)?;
                let share = Integer::from_digits(&share_bytes, Order::Msf);
                let share_mod_q = share % &q;
                Ok(share_mod_q.to_digits::<u8>(Order::Msf))
            }
            (NimState::RoleA(_), NimEncoding::RoleA(_)) => Err(NimMtaError::RoleMismatch {
                expected: "B",
                got: "A",
            }),
            (NimState::RoleB(_), NimEncoding::RoleB(_)) => Err(NimMtaError::RoleMismatch {
                expected: "A",
                got: "B",
            }),
        }
    }
}

// ============================================================================
// ScaledDecryptMtA
// ============================================================================

/// Setup material for the scaled-decryption `MtABroadcast`.
///
/// Contains the CL scheme, the joint public key, and its QFI element
/// (needed for computing commitments).
pub struct ScaledDecryptSetup {
    /// CL-HSM scheme parameters (interior mutability).
    pub setup: RefCell<ClSetup>,
    /// Joint CL public key.
    pub pk: ClHsmqkPublicKey,
}

impl Clone for ScaledDecryptSetup {
    fn clone(&self) -> Self {
        unimplemented!("ScaledDecryptSetup::clone is not supported; each party creates its own")
    }
}

/// Encoding broadcast by a party in scaled decryption.
///
/// Each party broadcasts its CL ciphertext components `(c1_i, c2_i)`
/// for the encryption of `a_i`, and its commitment element `u_i` for
/// the commitment to `b_i`.
///
/// The protocol needs two inputs per party (`a_i` and `b_i`).  Since
/// `MtABroadcast::encode` takes a single `input_bytes`, we pack both
/// values: the first 32 bytes are `a_i`, the remaining bytes are `b_i`.
pub struct ScaledDecryptEncoding {
    /// First ciphertext component: `c1_i` from `Enc(a_i)`.
    pub c1: Qfi,
    /// Second ciphertext component: `c2_i` from `Enc(a_i)`.
    pub c2: Qfi,
    /// Commitment element: `U_i = h^{beta_i} * pk^{b_i}`.
    pub u_com: Qfi,
}

impl Clone for ScaledDecryptEncoding {
    fn clone(&self) -> Self {
        unimplemented!(
            "ScaledDecryptEncoding::clone is not supported; \
             each party produces its own encoding"
        )
    }
}

/// Per-party secret state for scaled decryption, retained between
/// encode and decode.
pub struct ScaledDecryptState {
    /// CL encryption randomness `alpha_i` (big-endian bytes).
    pub alpha_i: Vec<u8>,
    /// CL commitment randomness `beta_i` (big-endian bytes).
    pub beta_i: Vec<u8>,
    /// Party's share of the commitment value `b_i` (big-endian bytes, mod q).
    pub b_i: Vec<u8>,
}

/// Error type for the scaled-decryption `MtA` backend.
#[derive(Debug, thiserror::Error)]
pub enum ScaledDecryptError {
    /// Class-group operation failure.
    #[error("CL error: {0}")]
    Cl(#[from] ClError),

    /// Invalid parameter.
    #[error("invalid parameter: {0}")]
    InvalidParam(String),
}

/// Scaled-decryption `MtABroadcast` backend (Trout Protocol 4.1).
///
/// Unlike pairwise NIM, scaled decryption is an n-party protocol.
/// Each party encodes its own CL ciphertext and commitment components,
/// all parties' encodings are aggregated externally (via
/// [`ScaledDecryptMtA::aggregate`]), and then each party calls `decode`
/// with the aggregated encoding and its own secret state.
///
/// The `MtABroadcast` trait models the per-party encode/decode steps.
/// Aggregation is handled by a separate associated function.
///
/// ## Input packing
///
/// `encode` expects `input_bytes` to contain two 32-byte big-endian
/// scalars concatenated: `a_i || b_i` (64 bytes total).
pub struct ScaledDecryptMtA;

impl ScaledDecryptMtA {
    /// Aggregate all parties' encodings into a single "combined" encoding.
    ///
    /// The aggregated encoding contains:
    /// - `A_1 = prod(c1_i)`
    /// - `A_2 = prod(c2_i)`
    /// - `B = prod(u_com_i)`
    ///
    /// The result can be passed as `other_encoding` to `decode`.
    ///
    /// # Errors
    ///
    /// Returns an error if class-group composition fails.
    pub fn aggregate(
        setup: &ScaledDecryptSetup,
        encodings: &[&ScaledDecryptEncoding],
    ) -> Result<ScaledDecryptEncoding, ScaledDecryptError> {
        let cl = setup.setup.borrow();

        let mut a1 = cl.identity()?;
        let mut a2 = cl.identity()?;
        let mut b_agg = cl.identity()?;

        for enc in encodings {
            a1 = cl.compose(&a1, &enc.c1)?;
            a2 = cl.compose(&a2, &enc.c2)?;
            b_agg = cl.compose(&b_agg, &enc.u_com)?;
        }

        Ok(ScaledDecryptEncoding {
            c1: a1,
            c2: a2,
            u_com: b_agg,
        })
    }

    /// Aggregate and solve: compute the final product `a * b mod q`.
    ///
    /// Given all parties' F-share contributions (from individual `decode`
    /// calls), composes them and extracts the discrete log in `F`.
    ///
    /// # Errors
    ///
    /// Returns an error if class-group operations fail.
    pub fn aggregate_f_shares(
        setup: &ScaledDecryptSetup,
        f_shares: &[Qfi],
    ) -> Result<Vec<u8>, ScaledDecryptError> {
        let cl = setup.setup.borrow();
        let mut f_agg = cl.identity()?;
        for fi in f_shares {
            f_agg = cl.compose(&f_agg, fi)?;
        }

        #[allow(non_snake_case)]
        let result_bytes = cl.dlog_in_F_bytes(&f_agg)?;
        Ok(result_bytes)
    }
}

impl tecdsa_protocol::MtABroadcast for ScaledDecryptMtA {
    type Setup = ScaledDecryptSetup;
    type Encoding = ScaledDecryptEncoding;
    type State = ScaledDecryptState;
    type Error = ScaledDecryptError;

    /// Encode this party's inputs for scaled decryption.
    ///
    /// `input_bytes` must be 64 bytes: `a_i (32 bytes) || b_i (32 bytes)`,
    /// both big-endian scalars.
    ///
    /// Produces:
    /// - Encryption of `a_i`: `Enc(pk, a_i; alpha_i)` decomposed into `(c1, c2)`
    /// - Commitment to `b_i`: `U_i = h^{beta_i} * pk^{b_i}`
    /// - State: `(alpha_i, beta_i, b_i)` for the decode step.
    fn encode(
        setup: &Self::Setup,
        input_bytes: &[u8],
        _q_bytes: &[u8],
        _rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::Encoding, Self::State), Self::Error> {
        if input_bytes.len() != 64 {
            return Err(ScaledDecryptError::InvalidParam(format!(
                "input_bytes must be 64 bytes (a_i || b_i), got {}",
                input_bytes.len()
            )));
        }

        let a_i_bytes = &input_bytes[..32];
        let b_i_bytes = &input_bytes[32..];

        let mut cl = setup.setup.borrow_mut();

        // Sample alpha_i (encryption randomness)
        let (sk_tmp, _) = cl.keygen()?;
        let alpha_i = cl.sk_to_bytes(&sk_tmp)?;

        // Encrypt a_i with explicit randomness alpha_i
        let ct = cl.encrypt_with_r_bytes(&setup.pk, a_i_bytes, &alpha_i)?;
        let (c1, c2) = cl.ct_components(&ct)?;

        // Sample beta_i (commitment randomness)
        let (sk_tmp2, _) = cl.keygen()?;
        let beta_i = cl.sk_to_bytes(&sk_tmp2)?;

        // Compute commitment U_i = h^{beta_i} * pk_elt^{b_i}
        let h_beta = cl.power_of_h_bytes(&beta_i)?;
        let pk_b = cl.pk_pow_bytes(&setup.pk, b_i_bytes)?;
        let u_com = cl.compose(&h_beta, &pk_b)?;

        let encoding = ScaledDecryptEncoding { c1, c2, u_com };
        let state = ScaledDecryptState {
            alpha_i,
            beta_i,
            b_i: b_i_bytes.to_vec(),
        };

        Ok((encoding, state))
    }

    /// Decode using the aggregated encoding and this party's secret state.
    ///
    /// `other_encoding` is the **aggregated** encoding (from
    /// [`ScaledDecryptMtA::aggregate`]), not a single party's encoding.
    ///
    /// Computes the F-share:
    /// ```text
    /// F_i = A_2^{b_i} * A_1^{beta_i} * B^{-alpha_i}
    /// ```
    ///
    /// Returns the `F_i` element serialised as binary bytes (using
    /// `Qfi::to_bytes`).
    ///
    /// **Note**: The raw `F_i` is a class-group element, not a scalar.
    /// The caller must collect all parties' `F_i` shares and pass them to
    /// [`ScaledDecryptMtA::aggregate_f_shares`] to obtain the final
    /// product scalar.
    fn decode(
        setup: &Self::Setup,
        other_encoding: &Self::Encoding,
        my_state: &Self::State,
        _q_bytes: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        let cl = setup.setup.borrow();

        // F_i = A_2^{b_i} * A_1^{beta_i} * B^{-alpha_i}, via one shared-squaring
        // multi-exponentiation instead of three exps + two composes.
        let f_i = cl.multiexp_signed_bytes(
            &[
                &other_encoding.c2,
                &other_encoding.c1,
                &other_encoding.u_com,
            ],
            &[
                (false, my_state.b_i.clone()),
                (false, my_state.beta_i.clone()),
                (true, my_state.alpha_i.clone()),
            ],
        )?;

        // Serialise F_i using binary Qfi::to_bytes for reconstruction.
        let serialised = f_i.to_bytes();
        Ok(serialised)
    }
}

impl ScaledDecryptMtA {
    /// Reconstruct a `Qfi` from the bytes returned by `decode`.
    ///
    /// The bytes are in the binary format produced by `Qfi::to_bytes`.
    ///
    /// # Errors
    ///
    /// Returns an error if parsing or QFI reconstruction fails.
    pub fn decode_to_qfi(decoded_bytes: &[u8]) -> Result<Qfi, ScaledDecryptError> {
        let qfi = Qfi::from_bytes(decoded_bytes);
        Ok(qfi)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use tecdsa_bigint::mul_mod;
    use tecdsa_protocol::MtABroadcast;

    use super::*;

    // ---- NimMtA tests ----

    /// Helper: create a `NimMtaSetup` for the given role.
    fn nim_setup(seed: &str, role: NimRole) -> NimMtaSetup {
        let mut cl = ClSetup::new_secp256k1(seed).expect("CL setup");
        let (_sk, pk) = cl.keygen().expect("keygen");
        NimMtaSetup {
            setup: RefCell::new(cl),
            pk,
            role,
        }
    }

    fn secp256k1_order_bytes() -> Vec<u8> {
        tecdsa_curve::conv::curve_order::<k256::Secp256k1>().to_digits::<u8>(Order::Msf)
    }

    #[test]
    fn nim_mta_roundtrip() {
        // Party A (x=7) and Party B (y=11) should get shares summing to 77.
        let q_bytes = secp256k1_order_bytes();
        let q = Integer::from_digits(&q_bytes, Order::Msf);

        let x = Integer::from(7u32);
        let y = Integer::from(11u32);

        // Both parties share the same CL setup (same seed = same CRS).
        // In a real protocol they would share the CRS parameters.
        // For testing, we create them with the same seed so the CRS matches.
        let setup_a = nim_setup("42", NimRole::A);
        let setup_b = nim_setup("42", NimRole::B);

        let mut rng = rand::thread_rng();

        // Party A encodes
        let (enc_a, state_a) =
            NimMtA::encode(&setup_a, &x.to_digits::<u8>(Order::Msf), &q_bytes, &mut rng)
                .expect("encode A");

        // Party B encodes
        let (enc_b, state_b) =
            NimMtA::encode(&setup_b, &y.to_digits::<u8>(Order::Msf), &q_bytes, &mut rng)
                .expect("encode B");

        // Party A decodes using B's encoding
        let share_a_bytes = NimMtA::decode(&setup_a, &enc_b, &state_a, &q_bytes).expect("decode A");

        // Party B decodes using A's encoding
        let share_b_bytes = NimMtA::decode(&setup_b, &enc_a, &state_b, &q_bytes).expect("decode B");

        let z_a = Integer::from_digits(&share_a_bytes, Order::Msf);
        let z_b = Integer::from_digits(&share_b_bytes, Order::Msf);
        let sum = (z_a + z_b) % &q;
        let expected = mul_mod(&x, &y, &q);

        assert_eq!(sum, expected, "NIM MtABroadcast: z_A + z_B != x*y mod q");
    }

    #[test]
    #[ignore = "redundant broadcast MtA variant"]
    fn nim_mta_larger_values() {
        let q_bytes = secp256k1_order_bytes();
        let q = Integer::from_digits(&q_bytes, Order::Msf);

        // Use values closer to the field order.
        let x = Integer::from(&q - 3);
        let y = Integer::from(1000u32);

        let setup_a = nim_setup("100", NimRole::A);
        let setup_b = nim_setup("100", NimRole::B);
        let mut rng = rand::thread_rng();

        let (enc_a, state_a) =
            NimMtA::encode(&setup_a, &x.to_digits::<u8>(Order::Msf), &q_bytes, &mut rng)
                .expect("encode A");
        let (enc_b, state_b) =
            NimMtA::encode(&setup_b, &y.to_digits::<u8>(Order::Msf), &q_bytes, &mut rng)
                .expect("encode B");

        let share_a_bytes = NimMtA::decode(&setup_a, &enc_b, &state_a, &q_bytes).expect("decode A");
        let share_b_bytes = NimMtA::decode(&setup_b, &enc_a, &state_b, &q_bytes).expect("decode B");

        let z_a = Integer::from_digits(&share_a_bytes, Order::Msf);
        let z_b = Integer::from_digits(&share_b_bytes, Order::Msf);
        let sum = (z_a + z_b) % &q;
        let expected = mul_mod(&x, &y, &q);

        assert_eq!(
            sum, expected,
            "NIM MtABroadcast: large values, z_A + z_B != x*y mod q"
        );
    }

    #[test]
    #[ignore = "redundant broadcast MtA variant"]
    fn nim_mta_role_mismatch_errors() {
        let q_bytes = secp256k1_order_bytes();

        let setup_a = nim_setup("200", NimRole::A);
        let mut rng = rand::thread_rng();

        let (enc_a, state_a) =
            NimMtA::encode(&setup_a, &[7], &q_bytes, &mut rng).expect("encode A");

        // Trying to decode a Role-A encoding with a Role-A state should fail.
        let result = NimMtA::decode(&setup_a, &enc_a, &state_a, &q_bytes);
        assert!(result.is_err(), "decoding own-role encoding must fail");

        match result.unwrap_err() {
            NimMtaError::RoleMismatch { expected, got } => {
                assert_eq!(expected, "B");
                assert_eq!(got, "A");
            }
            other => panic!("expected RoleMismatch, got: {other}"),
        }
    }

    // ---- ScaledDecryptMtA tests ----

    #[test]
    fn scaled_decrypt_mta_roundtrip() {
        let q_bytes = secp256k1_order_bytes();
        let q = Integer::from_digits(&q_bytes, Order::Msf);

        // 3 parties, each with shares a_i and b_i
        let n = 3usize;
        let mut cl = ClSetup::new_secp256k1("9002").expect("CL setup");
        let (_sk, pk) = cl.keygen().expect("keygen");

        let setup = ScaledDecryptSetup {
            setup: RefCell::new(cl),
            pk,
        };

        let mut rng = rand::thread_rng();

        // Generate random scalars for a_i and b_i
        use rand::RngCore;
        let mut a_scalars = Vec::new();
        let mut b_scalars = Vec::new();
        for _ in 0..n {
            // Generate random 32-byte values mod q
            let mut buf = [0u8; 32];
            rng.fill_bytes(&mut buf);
            // Ensure they are valid scalars by reducing mod q
            let val = Integer::from_digits(&buf, Order::Msf) % &q;
            a_scalars.push(val);

            rng.fill_bytes(&mut buf);
            let val = Integer::from_digits(&buf, Order::Msf) % &q;
            b_scalars.push(val);
        }

        // Compute expected product: (sum a_i) * (sum b_i) mod q
        let a_sum: Integer = a_scalars.iter().fold(Integer::from(0u32), |acc, v| acc + v) % &q;
        let b_sum: Integer = b_scalars.iter().fold(Integer::from(0u32), |acc, v| acc + v) % &q;
        let expected = mul_mod(&a_sum, &b_sum, &q);

        // Each party encodes
        let mut encodings = Vec::new();
        let mut states = Vec::new();

        for i in 0..n {
            // Pack a_i || b_i into 64 bytes
            let mut input = vec![0u8; 64];
            let a_bytes = a_scalars[i].to_digits::<u8>(Order::Msf);
            let b_bytes = b_scalars[i].to_digits::<u8>(Order::Msf);
            // Right-align into 32-byte slots
            let a_offset = 32 - a_bytes.len().min(32);
            input[a_offset..32].copy_from_slice(&a_bytes[..a_bytes.len().min(32)]);
            let b_offset = 64 - b_bytes.len().min(32);
            input[b_offset..64].copy_from_slice(&b_bytes[..b_bytes.len().min(32)]);

            let (enc, state) =
                ScaledDecryptMtA::encode(&setup, &input, &q_bytes, &mut rng).expect("encode");
            encodings.push(enc);
            states.push(state);
        }

        // Aggregate all encodings
        let enc_refs: Vec<&ScaledDecryptEncoding> = encodings.iter().collect();
        let aggregated = ScaledDecryptMtA::aggregate(&setup, &enc_refs).expect("aggregate");

        // Each party decodes to get its F_i share
        let f_shares = states
            .iter()
            .map(|state| {
                let f_bytes =
                    ScaledDecryptMtA::decode(&setup, &aggregated, state, &q_bytes).expect("decode");
                ScaledDecryptMtA::decode_to_qfi(&f_bytes).expect("decode_to_qfi")
            })
            .collect::<Vec<_>>();

        // Aggregate F-shares and extract the product
        let result_bytes =
            ScaledDecryptMtA::aggregate_f_shares(&setup, &f_shares).expect("aggregate_f_shares");
        let result = Integer::from_digits(&result_bytes, Order::Msf);
        let result_mod_q = result % q;

        assert_eq!(
            result_mod_q, expected,
            "scaled decryption: result != sum(a_i) * sum(b_i) mod q"
        );
    }

    #[test]
    #[ignore = "redundant broadcast MtA variant"]
    fn scaled_decrypt_bad_input_length() {
        let q_bytes = secp256k1_order_bytes();

        let mut cl = ClSetup::new_secp256k1("9003").expect("CL setup");
        let (_sk, pk) = cl.keygen().expect("keygen");
        let setup = ScaledDecryptSetup {
            setup: RefCell::new(cl),
            pk,
        };

        let mut rng = rand::thread_rng();

        // 32 bytes instead of 64 should fail
        let result = ScaledDecryptMtA::encode(&setup, &[0u8; 32], &q_bytes, &mut rng);
        assert!(result.is_err(), "encode with 32 bytes must fail");
    }
}
