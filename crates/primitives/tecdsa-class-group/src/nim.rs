// SPDX-License-Identifier: MIT OR Apache-2.0
//! Non-Interactive Multiplication (NIM) protocol.
//!
//! Clean-room implementation from the LLZ25 paper description.
//!
//! # Protocol overview
//!
//! Two parties A and B hold private values `x` and `y` respectively.
//! They share a Common Reference String (CRS) containing a CL-HSM
//! scheme and a public key `pk`.  They wish to obtain additive shares
//! `z_A` and `z_B` such that:
//!
//! ```text
//! z_A + z_B = x * y  (mod q)
//! ```
//!
//! The protocol uses CL-HSM encryption homomorphically:
//!
//! 1. **`Encode_A`**: Party A computes `pe_A = h^r * pk^x` where `r`
//!    is random, and stores state `r`.
//!
//! 2. **`Encode_B`**: Party B encrypts `y` under the CRS key:
//!    `pe_B = CL.Enc(pk, y; s)`, storing state `s`.
//!
//! 3. **`Decode_A`**: Party A uses `pe_B` and its state `(r, x)` to
//!    compute an element in `Cl(Delta)` and extracts its F-component.
//!
//! 4. **`Decode_B`**: Party B uses `pe_A` and its state `s` to
//!    compute an element in `Cl(Delta)` and extracts its F-component.
//!
//! Finally, `dlog_F(alpha) + dlog_F(beta) = x * y mod q`.

use crate::cl::{
    Ciphertext as ClHsmqkCiphertext, ClResult, ClSetup, PublicKey as ClHsmqkPublicKey, Qfi,
};

/// State retained by Party A after encoding.
#[derive(Debug)]
pub struct NimStateA {
    /// The encryption randomness `r` (big-endian bytes).
    pub r_bytes: Vec<u8>,
    /// Party A's private input `x` (big-endian bytes).
    pub x_bytes: Vec<u8>,
}

/// State retained by Party B after encoding.
#[derive(Debug)]
pub struct NimStateB {
    /// The encryption randomness `s` (big-endian bytes).
    pub s_bytes: Vec<u8>,
}

/// Result of Party A's encode step.
#[derive(Debug)]
pub struct NimEncodeAOutput {
    /// The pseudo-encryption `pe_A = h^r * pk^x` sent to Party B.
    pub pe_a: Qfi,
    /// State kept by Party A for the decode step.
    pub state: NimStateA,
}

/// Result of Party B's encode step.
pub struct NimEncodeBOutput {
    /// The CL-HSM ciphertext `pe_B = Enc(pk, y; s)` sent to Party A.
    pub pe_b: ClHsmqkCiphertext,
    /// State kept by Party B for the decode step.
    pub state: NimStateB,
}

impl std::fmt::Debug for NimEncodeBOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NimEncodeBOutput").finish_non_exhaustive()
    }
}

/// The NIM protocol context.
///
/// Holds a mutable reference to the CL setup and the CRS public key.
/// Provides the encode/decode methods.
pub struct Nim<'a> {
    setup: &'a mut ClSetup,
}

impl<'a> Nim<'a> {
    /// Creates a new NIM context wrapping the given CL setup.
    pub fn new(setup: &'a mut ClSetup) -> Self {
        Self { setup }
    }

    /// **`Encode_A`**: Party A's encoding step.
    ///
    /// Computes `pe_A = h^r * pk^x` where `r` is sampled from the
    /// secret-key distribution, and returns the pseudo-encryption along
    /// with state for the decode step.
    ///
    /// # Arguments
    ///
    /// - `x_bytes`: Party A's private input as big-endian bytes.
    /// - `pk`: The CRS public key.
    ///
    /// # Errors
    ///
    /// Returns an error if BICYCL operations fail.
    pub fn encode_a(
        &mut self,
        x_bytes: &[u8],
        pk: &ClHsmqkPublicKey,
    ) -> ClResult<NimEncodeAOutput> {
        // Sample randomness r.
        let r_bytes = sample_randomness(self.setup)?;

        // Compute pe_A = h^r * pk^x
        let h_r = self.setup.power_of_h_bytes(&r_bytes)?;
        let pk_x = self.setup.pk_pow_bytes(pk, x_bytes)?;
        let pe_a = self.setup.compose(&h_r, &pk_x)?;

        Ok(NimEncodeAOutput {
            pe_a,
            state: NimStateA {
                r_bytes,
                x_bytes: x_bytes.to_vec(),
            },
        })
    }

    /// **`Encode_B`**: Party B's encoding step.
    ///
    /// Encrypts `y` under the CRS public key using CL-HSM encryption
    /// with fresh randomness `s`.
    ///
    /// # Arguments
    ///
    /// - `y_bytes`: Party B's private input as big-endian bytes.
    /// - `pk`: The CRS public key.
    ///
    /// # Errors
    ///
    /// Returns an error if BICYCL operations fail.
    pub fn encode_b(
        &mut self,
        y_bytes: &[u8],
        pk: &ClHsmqkPublicKey,
    ) -> ClResult<NimEncodeBOutput> {
        // Sample randomness s.
        let s_bytes = sample_randomness(self.setup)?;

        // Compute pe_B = CL.Enc(pk, y; s)
        let pe_b = self.setup.encrypt_with_r_bytes(pk, y_bytes, &s_bytes)?;

        Ok(NimEncodeBOutput {
            pe_b,
            state: NimStateB { s_bytes },
        })
    }

    /// **`Decode_A`**: Party A's decoding step.
    ///
    /// Computes `z_A_raw = c1^r * c2^x` from `pe_B`, then extracts
    /// the F-component: `alpha = z_A_raw * H(z_A_raw)^{-1}`.
    ///
    /// Returns `dlog_in_F(alpha)` as big-endian bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if BICYCL operations fail.
    pub fn decode_a(&self, pe_b: &ClHsmqkCiphertext, state: &NimStateA) -> ClResult<Vec<u8>> {
        let (c1, c2) = self.setup.ct_components(pe_b)?;

        // z_A_raw = c1^r · c2^x, via one shared-squaring multi-exponentiation.
        let z_a_raw = self
            .setup
            .multiexp_bytes(&[&c1, &c2], &[state.r_bytes.clone(), state.x_bytes.clone()])?;

        extract_f_component(self.setup, &z_a_raw, false)
    }

    /// **`Decode_B`**: Party B's decoding step.
    ///
    /// Computes `z_B_raw = pe_A^s`, then extracts the F-component:
    /// `beta = H(z_B_raw) * z_B_raw^{-1}`.
    ///
    /// Returns `dlog_in_F(beta)` as big-endian bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if BICYCL operations fail.
    pub fn decode_b(&self, pe_a: &Qfi, state: &NimStateB) -> ClResult<Vec<u8>> {
        let z_b_raw = self.setup.exp_bytes(pe_a, &state.s_bytes)?;

        extract_f_component(self.setup, &z_b_raw, true)
    }
}

/// Extract the F-component from a class-group element `z`.
///
/// Computes H(z) via `to_maximal_order + lift` on a copy, then:
/// - If `negate=false` (decode_A): `result = z * H(z)^{-1}` → `dlog_in_F(result)`
/// - If `negate=true`  (decode_B): `result = H(z) * z^{-1}` → `dlog_in_F(result)`
///
/// Uses `Qfi::dup` to produce an independent copy.
#[allow(non_snake_case)]
fn extract_f_component(setup: &ClSetup, z: &Qfi, negate: bool) -> ClResult<Vec<u8>> {
    let mut h_label = setup.cl().to_cl_delta_k(z); // reduced π(z)
    setup.cl().from_cl_delta_k_to_cl_delta(&mut h_label); // reduced lift back

    let f_component = if negate {
        let mut z_inv = z.clone();
        z_inv.neg();
        setup.compose(&h_label, &z_inv)?
    } else {
        h_label.neg();
        setup.compose(z, &h_label)?
    };

    #[allow(non_snake_case)]
    setup.dlog_in_F_bytes(&f_component)
}

/// Samples a random value suitable for encryption randomness.
///
/// Returns the randomness as big-endian bytes.
fn sample_randomness(setup: &mut ClSetup) -> ClResult<Vec<u8>> {
    // Generate a key pair and extract the secret key value as our
    // randomness. The BICYCL keygen samples `sk` uniformly from
    // `[0, secret_key_bound)`.
    let (sk, _pk) = setup.keygen()?;
    setup.sk_to_bytes(&sk)
}

#[cfg(test)]
mod tests {
    use rug::{integer::Order, Integer};

    use super::*;

    #[test]
    #[allow(clippy::similar_names)]
    fn nim_smoke() {
        let mut setup = ClSetup::new_secp256k1("42").expect("setup");
        // Generate a single CRS key pair.
        let (_sk, pk) = setup.keygen().expect("keygen");

        let x = &7u32.to_be_bytes();
        let y = &11u32.to_be_bytes();

        let mut nim = Nim::new(&mut setup);

        // Party A encodes
        let encode_a = nim.encode_a(x, &pk).expect("encode_a");

        // Party B encodes
        let encode_b = nim.encode_b(y, &pk).expect("encode_b");

        // Party A decodes using pe_B
        let share_a_bytes = nim
            .decode_a(&encode_b.pe_b, &encode_a.state)
            .expect("decode_a");

        // Party B decodes using pe_A
        let share_b_bytes = nim
            .decode_b(&encode_a.pe_a, &encode_b.state)
            .expect("decode_b");

        let q = Integer::from_digits(&setup.q_bytes().unwrap(), Order::Msf);
        let z_a = Integer::from_digits(&share_a_bytes, Order::Msf);
        let z_b = Integer::from_digits(&share_b_bytes, Order::Msf);
        let x_val = Integer::from(7u32);
        let y_val = Integer::from(11u32);
        let xy = Integer::from(&x_val * &y_val).modulo(&q);
        let sum = (z_a + z_b) % q;

        assert_eq!(sum, xy, "NIM correctness: z_A + z_B != x*y mod q");
    }
}
