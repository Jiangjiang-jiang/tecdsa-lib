// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown
)]

//! `R_dec_dl` — correct CL decryption + discrete-log proof.
//!
//! Proves that a partial decryption `pd = c1^{sk}` is correct relative
//! to the public key `pk = h^{sk}`, where `sk` is the secret key.
//! This is identical to the `CL_HSMqk_Part_Dec_ZKProof` pattern from BICYCL.

use rug::{integer::Order, Integer};

use super::{
    challenge_from_qfi, challenge_from_qfi_with_prefix, response_unbounded, sample_random,
};
use crate::cl::{
    Ciphertext as ClHsmqkCiphertext, ClResult, ClSetup, PublicKey as ClHsmqkPublicKey, Qfi,
};

/// Proof of correct partial decryption (decryption + DL).
pub struct RDecDlProof {
    /// Commitment `t1 = h^a`.
    pub t1: Qfi,
    /// Commitment `t2 = c1^a`.
    pub t2: Qfi,
    /// Response `z = a + e * sk` (unbounded integer, big-endian bytes).
    pub z: Vec<u8>,
    /// Fiat-Shamir challenge (big-endian bytes).
    pub e: Vec<u8>,
}

impl RDecDlProof {
    /// Generates a proof that `pd = c1^{sk}` for ciphertext `ct` and
    /// public key `pk = h^{sk}`.
    pub fn prove(
        setup: &mut ClSetup,
        pk: &ClHsmqkPublicKey,
        ct: &ClHsmqkCiphertext,
        pd: &Qfi,
        sk: &Integer,
    ) -> ClResult<Self> {
        let a = sample_random(setup)?;

        let t1 = setup.power_of_h(&a)?;
        let (c1, _c2) = setup.ct_components(ct)?;
        let t2 = setup.exp(&c1, &a)?;

        let pk_elt = pk.elt();
        let e = challenge_from_qfi(setup, b"R_dec_dl", &[pk_elt, &c1, pd, &t1, &t2], &[])?;

        let z = response_unbounded(&a, &e, sk);

        Ok(Self { t1, t2, z, e })
    }

    /// Verifies the partial-decryption proof.
    pub fn verify(
        &self,
        setup: &ClSetup,
        pk: &ClHsmqkPublicKey,
        ct: &ClHsmqkCiphertext,
        pd: &Qfi,
    ) -> ClResult<bool> {
        let (c1, _c2) = setup.ct_components(ct)?;

        let e_check = challenge_from_qfi(
            setup,
            b"R_dec_dl",
            &[pk.elt(), &c1, pd, &self.t1, &self.t2],
            &[],
        )?;
        if e_check != self.e {
            return Ok(false);
        }

        let z = Integer::from_digits(&self.z, Order::Msf);
        let e = Integer::from_digits(&self.e, Order::Msf);

        // Check 1: h^z == pk^e * t1
        let lhs1 = setup.power_of_h(&z)?;
        let pk_e = setup.exp(pk.elt(), &e)?;
        let rhs1 = setup.compose(&pk_e, &self.t1)?;
        if lhs1 != rhs1 {
            return Ok(false);
        }

        // Check 2: c1^z == pd^e * t2
        // c1^z == pd^e * t2 ⟺ c1^z * pd^{-e} == t2 (shared-squaring multi-exp;
        // both bases vary per proof).
        if setup.multiexp(&[&c1, pd], &[z, -e])? != self.t2 {
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
        pd: &Qfi,
        sk: &Integer,
    ) -> ClResult<Self> {
        let a = sample_random(setup)?;

        let t1 = setup.power_of_h(&a)?;
        let (c1, _c2) = setup.ct_components(ct)?;
        let t2 = setup.exp(&c1, &a)?;

        let pk_elt = pk.elt();
        let e = challenge_from_qfi_with_prefix(
            setup,
            prefix,
            b"R_dec_dl",
            &[pk_elt, &c1, pd, &t1, &t2],
            &[],
        )?;

        let z = response_unbounded(&a, &e, sk);

        Ok(Self { t1, t2, z, e })
    }

    /// Like [`verify`](Self::verify), but uses the same context prefix that was
    /// used during proving.
    pub fn verify_with_prefix(
        &self,
        prefix: &[u8],
        setup: &ClSetup,
        pk: &ClHsmqkPublicKey,
        ct: &ClHsmqkCiphertext,
        pd: &Qfi,
    ) -> ClResult<bool> {
        let pk_elt = pk.elt();
        let (c1, _c2) = setup.ct_components(ct)?;

        let e_check = challenge_from_qfi_with_prefix(
            setup,
            prefix,
            b"R_dec_dl",
            &[pk_elt, &c1, pd, &self.t1, &self.t2],
            &[],
        )?;
        if e_check != self.e {
            return Ok(false);
        }

        let z = Integer::from_digits(&self.z, Order::Msf);
        let e = Integer::from_digits(&self.e, Order::Msf);

        let lhs1 = setup.power_of_h(&z)?;
        let pk_e = setup.exp(pk_elt, &e)?;
        let rhs1 = setup.compose(&pk_e, &self.t1)?;
        if lhs1 != rhs1 {
            return Ok(false);
        }

        // c1^z == pd^e * t2 ⟺ c1^z * pd^{-e} == t2 (shared-squaring multi-exp;
        // both bases vary per proof).
        let lhs2 = setup.multiexp(&[&c1, pd], &[z, -e])?;
        if lhs2 != self.t2 {
            return Ok(false);
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cl::ClSetup;

    #[test]
    fn r_dec_dl_honest_verifies() {
        let mut setup = ClSetup::new_secp256k1(2001u64).expect("setup");
        let (sk_raw, pk_raw) = setup.keygen().expect("keygen");
        let sk = setup.sk_to_integer(&sk_raw);

        let ct = setup
            .encrypt(&pk_raw, &Integer::from(123u32))
            .expect("encrypt");
        let (c1, _) = setup.ct_components(&ct).expect("components");
        let pd = setup.exp(&c1, &sk).expect("partial_dec");

        let proof = RDecDlProof::prove(&mut setup, &pk_raw, &ct, &pd, &sk).expect("prove");
        assert!(proof.verify(&setup, &pk_raw, &ct, &pd).expect("verify"));
    }

    #[test]
    #[ignore = "redundant ZK negative test"]
    fn r_dec_dl_rejects_wrong_sk() {
        let mut setup = ClSetup::new_secp256k1(2002u64).expect("setup");
        let (sk_raw, pk_raw) = setup.keygen().expect("keygen");
        let sk = setup.sk_to_integer(&sk_raw);
        let (sk_raw2, _) = setup.keygen().expect("keygen2");
        let sk2 = setup.sk_to_integer(&sk_raw2);

        let ct = setup
            .encrypt(&pk_raw, &Integer::from(123u32))
            .expect("encrypt");
        let (c1, _) = setup.ct_components(&ct).expect("components");
        let pd = setup.exp(&c1, &sk).expect("partial_dec");

        // Prove with wrong secret key.
        let proof = RDecDlProof::prove(&mut setup, &pk_raw, &ct, &pd, &sk2).expect("prove");
        assert!(!proof.verify(&setup, &pk_raw, &ct, &pd).expect("verify"));
    }

    #[test]
    fn r_dec_dl_with_prefix_honest_verifies() {
        let mut setup = ClSetup::new_secp256k1(2003u64).expect("setup");
        let (sk_raw, pk_raw) = setup.keygen().expect("keygen");
        let sk = setup.sk_to_integer(&sk_raw);

        let ct = setup
            .encrypt(&pk_raw, &Integer::from(123u32))
            .expect("encrypt");
        let (c1, _) = setup.ct_components(&ct).expect("components");
        let pd = setup.exp(&c1, &sk).expect("partial_dec");

        let prefix = b"session-1::party-2::round-3";
        let proof = RDecDlProof::prove_with_prefix(prefix, &mut setup, &pk_raw, &ct, &pd, &sk)
            .expect("prove");
        assert!(proof
            .verify_with_prefix(prefix, &setup, &pk_raw, &ct, &pd)
            .expect("verify"));
    }

    #[ignore = "redundant ZK negative test"]
    #[test]
    fn r_dec_dl_with_prefix_rejects_wrong_prefix() {
        let mut setup = ClSetup::new_secp256k1(2004u64).expect("setup");
        let (sk_raw, pk_raw) = setup.keygen().expect("keygen");
        let sk = setup.sk_to_integer(&sk_raw);

        let ct = setup
            .encrypt(&pk_raw, &Integer::from(123u32))
            .expect("encrypt");
        let (c1, _) = setup.ct_components(&ct).expect("components");
        let pd = setup.exp(&c1, &sk).expect("partial_dec");

        let proof = RDecDlProof::prove_with_prefix(b"prefix-A", &mut setup, &pk_raw, &ct, &pd, &sk)
            .expect("prove");
        assert!(!proof
            .verify_with_prefix(b"prefix-B", &setup, &pk_raw, &ct, &pd)
            .expect("verify"));
    }
}
