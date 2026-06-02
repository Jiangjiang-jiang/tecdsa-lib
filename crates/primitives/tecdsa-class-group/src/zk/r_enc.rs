// SPDX-License-Identifier: GPL-3.0-or-later
#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown
)]

//! `R_enc` — proof of correct CL encryption in range.
//!
//! Sigma protocol: prover knows plaintext `m` and randomness `r` such
//! that `ct = Enc(pk, m; r)`, i.e.
//!   `c1 = h^r`  and  `c2 = pk^r * f^m`.
//!
//! Follows the `CL_HSMqk_ZKAoKProof` pattern from BICYCL.

use crate::bicycl_glue::{ClResult, ClSetup};
use bicycl_rs::{ClHsmqkCiphertext, ClHsmqkPublicKey, Qfi};

use super::{
    challenge_from_qfi, challenge_from_qfi_with_prefix, response_mod_q, response_unbounded,
    sample_random, sample_random_mod_q,
};

/// Proof of correct CL-HSM encryption.
pub struct REncProof {
    /// Commitment: t1 = h^{a1}  (randomness part -- the c1 component of Enc(pk, a2; a1)).
    pub t1: Qfi,
    /// Commitment: t2 = pk^{a1} * f^{a2} (message part).
    pub t2: Qfi,
    /// Response for randomness: u1 = a1 + e * r (big-endian bytes).
    pub u1: Vec<u8>,
    /// Response for plaintext: u2 = (a2 + e * m) mod q (big-endian bytes).
    pub u2: Vec<u8>,
    /// Fiat-Shamir challenge (big-endian bytes).
    pub e: Vec<u8>,
}

impl REncProof {
    /// Generates a proof of correct encryption.
    ///
    /// # Arguments
    /// - `pk`: the public key.
    /// - `ct`: the ciphertext `(c1, c2)`.
    /// - `m_bytes`: the plaintext (big-endian bytes).
    /// - `r_bytes`: the encryption randomness (big-endian bytes).
    pub fn prove(
        setup: &mut ClSetup,
        pk: &ClHsmqkPublicKey,
        ct: &ClHsmqkCiphertext,
        m_bytes: &[u8],
        r_bytes: &[u8],
    ) -> ClResult<Self> {
        // 1. Sample random commitment values.
        let a1 = sample_random(setup)?;
        let a2 = sample_random_mod_q(setup)?;

        // 2. Compute commitment: t = Enc(pk, a2; a1) => (h^a1, pk^a1 * f^a2).
        let t1 = setup.power_of_h_bytes(&a1)?;
        let pk_elt = setup.pk_element(pk)?;
        let pk_a1 = setup.exp_bytes(&pk_elt, &a1)?;
        let f_a2 = setup.power_of_f_bytes(&a2)?;
        let t2 = setup.compose(&pk_a1, &f_a2)?;

        // 3. Compute challenge.
        let (c1, c2) = setup.ct_components(ct)?;
        let e = challenge_from_qfi(setup, b"R_enc", &[&pk_elt, &c1, &c2, &t1, &t2], &[])?;

        // 4. Compute responses.
        let u1 = response_unbounded(&a1, &e, r_bytes)?;
        let q_bytes = setup.q_bytes()?;
        let u2 = response_mod_q(&a2, &e, m_bytes, &q_bytes)?;

        Ok(Self { t1, t2, u1, u2, e })
    }

    /// Verifies a proof of correct encryption.
    pub fn verify(
        &self,
        setup: &ClSetup,
        pk: &ClHsmqkPublicKey,
        ct: &ClHsmqkCiphertext,
    ) -> ClResult<bool> {
        let (c1, c2) = setup.ct_components(ct)?;
        let pk_elt = setup.pk_element(pk)?;

        // Recompute challenge from stored commitment.
        let e_check = challenge_from_qfi(
            setup,
            b"R_enc",
            &[&pk_elt, &c1, &c2, &self.t1, &self.t2],
            &[],
        )?;
        if e_check != self.e {
            return Ok(false);
        }

        // Check 1: h^u1 == t1 * c1^e
        let lhs1 = setup.power_of_h_bytes(&self.u1)?;
        let c1_e = setup.exp_bytes(&c1, &self.e)?;
        let rhs1 = setup.compose(&self.t1, &c1_e)?;
        if !lhs1.equal(setup.ctx(), &rhs1)? {
            return Ok(false);
        }

        // Check 2: pk^u1 * f^u2 == t2 * c2^e
        let pk_u1 = setup.exp_bytes(&pk_elt, &self.u1)?;
        let f_u2 = setup.power_of_f_bytes(&self.u2)?;
        let lhs2 = setup.compose(&pk_u1, &f_u2)?;
        let c2_e = setup.exp_bytes(&c2, &self.e)?;
        let rhs2 = setup.compose(&self.t2, &c2_e)?;
        if !lhs2.equal(setup.ctx(), &rhs2)? {
            return Ok(false);
        }

        Ok(true)
    }

    /// Like [`prove`](Self::prove), but binds the Fiat-Shamir challenge to an
    /// opaque context prefix (e.g. session/party/round bytes).
    pub fn prove_with_prefix(
        prefix: &[u8],
        setup: &mut ClSetup,
        pk: &ClHsmqkPublicKey,
        ct: &ClHsmqkCiphertext,
        m_bytes: &[u8],
        r_bytes: &[u8],
    ) -> ClResult<Self> {
        // 1. Sample random commitment values.
        let a1 = sample_random(setup)?;
        let a2 = sample_random_mod_q(setup)?;

        // 2. Compute commitment: t = Enc(pk, a2; a1) => (h^a1, pk^a1 * f^a2).
        let t1 = setup.power_of_h_bytes(&a1)?;
        let pk_elt = setup.pk_element(pk)?;
        let pk_a1 = setup.exp_bytes(&pk_elt, &a1)?;
        let f_a2 = setup.power_of_f_bytes(&a2)?;
        let t2 = setup.compose(&pk_a1, &f_a2)?;

        // 3. Compute challenge with prefix.
        let (c1, c2) = setup.ct_components(ct)?;
        let e = challenge_from_qfi_with_prefix(
            setup,
            prefix,
            b"R_enc",
            &[&pk_elt, &c1, &c2, &t1, &t2],
            &[],
        )?;

        // 4. Compute responses.
        let u1 = response_unbounded(&a1, &e, r_bytes)?;
        let q_bytes = setup.q_bytes()?;
        let u2 = response_mod_q(&a2, &e, m_bytes, &q_bytes)?;

        Ok(Self { t1, t2, u1, u2, e })
    }

    /// Like [`verify`](Self::verify), but uses the same context prefix that was
    /// used during proving.
    pub fn verify_with_prefix(
        &self,
        prefix: &[u8],
        setup: &ClSetup,
        pk: &ClHsmqkPublicKey,
        ct: &ClHsmqkCiphertext,
    ) -> ClResult<bool> {
        let (c1, c2) = setup.ct_components(ct)?;
        let pk_elt = setup.pk_element(pk)?;

        // Recompute challenge from stored commitment with prefix.
        let e_check = challenge_from_qfi_with_prefix(
            setup,
            prefix,
            b"R_enc",
            &[&pk_elt, &c1, &c2, &self.t1, &self.t2],
            &[],
        )?;
        if e_check != self.e {
            return Ok(false);
        }

        // Check 1: h^u1 == t1 * c1^e
        let lhs1 = setup.power_of_h_bytes(&self.u1)?;
        let c1_e = setup.exp_bytes(&c1, &self.e)?;
        let rhs1 = setup.compose(&self.t1, &c1_e)?;
        if !lhs1.equal(setup.ctx(), &rhs1)? {
            return Ok(false);
        }

        // Check 2: pk^u1 * f^u2 == t2 * c2^e
        let pk_u1 = setup.exp_bytes(&pk_elt, &self.u1)?;
        let f_u2 = setup.power_of_f_bytes(&self.u2)?;
        let lhs2 = setup.compose(&pk_u1, &f_u2)?;
        let c2_e = setup.exp_bytes(&c2, &self.e)?;
        let rhs2 = setup.compose(&self.t2, &c2_e)?;
        if !lhs2.equal(setup.ctx(), &rhs2)? {
            return Ok(false);
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bicycl_glue::ClSetup;

    #[test]
    fn r_enc_honest_verifies() {
        let mut setup = ClSetup::new_secp256k1("1001").expect("setup");
        let (sk_raw, pk_raw) = setup.keygen().expect("keygen");
        let _ = sk_raw;

        let m = 42u32.to_be_bytes();
        let r = {
            let (sk2, _) = setup.keygen().expect("keygen2");
            setup.sk_to_bytes(&sk2).expect("sk_bytes")
        };
        let ct = setup
            .encrypt_with_r_bytes(&pk_raw, &m, &r)
            .expect("encrypt");
        let proof = REncProof::prove(&mut setup, &pk_raw, &ct, &m, &r).expect("prove");
        assert!(proof.verify(&setup, &pk_raw, &ct).expect("verify"));
    }

    #[test]
    fn r_enc_rejects_wrong_plaintext() {
        let mut setup = ClSetup::new_secp256k1("1002").expect("setup");
        let (_sk_raw, pk_raw) = setup.keygen().expect("keygen");

        let m = 42u32.to_be_bytes();
        let r = {
            let (sk2, _) = setup.keygen().expect("keygen2");
            setup.sk_to_bytes(&sk2).expect("sk_bytes")
        };
        let ct = setup
            .encrypt_with_r_bytes(&pk_raw, &m, &r)
            .expect("encrypt");

        let wrong_m = 99u32.to_be_bytes();
        let proof = REncProof::prove(&mut setup, &pk_raw, &ct, &wrong_m, &r).expect("prove");
        assert!(!proof.verify(&setup, &pk_raw, &ct).expect("verify"));
    }

    #[test]
    fn r_enc_with_prefix_honest_verifies() {
        let mut setup = ClSetup::new_secp256k1("1003").expect("setup");
        let (sk_raw, pk_raw) = setup.keygen().expect("keygen");
        let _ = sk_raw;

        let m = 42u32.to_be_bytes();
        let r = {
            let (sk2, _) = setup.keygen().expect("keygen2");
            setup.sk_to_bytes(&sk2).expect("sk_bytes")
        };
        let ct = setup
            .encrypt_with_r_bytes(&pk_raw, &m, &r)
            .expect("encrypt");
        let prefix = b"session-1::party-2::round-3";
        let proof =
            REncProof::prove_with_prefix(prefix, &mut setup, &pk_raw, &ct, &m, &r).expect("prove");
        assert!(proof
            .verify_with_prefix(prefix, &setup, &pk_raw, &ct)
            .expect("verify"));
    }

    #[test]
    fn r_enc_with_prefix_rejects_wrong_prefix() {
        let mut setup = ClSetup::new_secp256k1("1004").expect("setup");
        let (sk_raw, pk_raw) = setup.keygen().expect("keygen");
        let _ = sk_raw;

        let m = 42u32.to_be_bytes();
        let r = {
            let (sk2, _) = setup.keygen().expect("keygen2");
            setup.sk_to_bytes(&sk2).expect("sk_bytes")
        };
        let ct = setup
            .encrypt_with_r_bytes(&pk_raw, &m, &r)
            .expect("encrypt");
        let proof = REncProof::prove_with_prefix(b"prefix-A", &mut setup, &pk_raw, &ct, &m, &r)
            .expect("prove");
        // Verify with a different prefix must fail.
        assert!(!proof
            .verify_with_prefix(b"prefix-B", &setup, &pk_raw, &ct)
            .expect("verify"));
    }

    #[test]
    fn r_enc_rejects_mutated_proof() {
        let mut setup = ClSetup::new_secp256k1("1005").expect("setup");
        let (_sk_raw, pk_raw) = setup.keygen().expect("keygen");

        let m = 42u32.to_be_bytes();
        let r = {
            let (sk2, _) = setup.keygen().expect("keygen2");
            setup.sk_to_bytes(&sk2).expect("sk_bytes")
        };
        let ct = setup
            .encrypt_with_r_bytes(&pk_raw, &m, &r)
            .expect("encrypt");
        let mut proof = REncProof::prove(&mut setup, &pk_raw, &ct, &m, &r).expect("prove");

        // Mutate the u1 response field by flipping a byte.
        assert!(!proof.u1.is_empty(), "u1 must be non-empty");
        proof.u1[0] ^= 0xff;

        assert!(
            !proof.verify(&setup, &pk_raw, &ct).expect("verify"),
            "verification must reject a proof with mutated u1 response"
        );
    }
}
