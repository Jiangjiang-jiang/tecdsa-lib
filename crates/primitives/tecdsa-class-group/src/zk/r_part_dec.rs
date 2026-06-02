// SPDX-License-Identifier: GPL-3.0-or-later
#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown
)]

//! `R_part_dec` — partial decryption proof.
//!
//! Proves that `pd = c1^{sk}` is a correct partial decryption, where
//! `pk = h^{sk}`.  This is the same relation as `R_dec_dl` but with
//! the dedicated `Part_Dec` naming from the threshold ECDSA literature.
//!
//! Re-exports `RDecDlProof` under the `RPartDecProof` name.

pub use super::r_dec_dl::RDecDlProof as RPartDecProof;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bicycl_glue::ClSetup;

    #[test]
    fn r_part_dec_honest_verifies() {
        let mut setup = ClSetup::new_secp256k1("7001").expect("setup");
        let (sk_raw, pk_raw) = setup.keygen().expect("keygen");
        let sk_bytes = setup.sk_to_bytes(&sk_raw).expect("sk_bytes");

        let ct = setup
            .encrypt_bytes(&pk_raw, &55u32.to_be_bytes())
            .expect("encrypt");
        let (c1, _) = setup.ct_components(&ct).expect("comp");
        let pd = setup.exp_bytes(&c1, &sk_bytes).expect("pd");

        let proof = RPartDecProof::prove(&mut setup, &pk_raw, &ct, &pd, &sk_bytes).expect("prove");
        assert!(proof.verify(&setup, &pk_raw, &ct, &pd).expect("verify"));
    }

    #[test]
    fn r_part_dec_rejects_wrong_dec() {
        let mut setup = ClSetup::new_secp256k1("7002").expect("setup");
        let (sk_raw, pk_raw) = setup.keygen().expect("keygen");
        let sk_bytes = setup.sk_to_bytes(&sk_raw).expect("sk_bytes");

        let ct = setup
            .encrypt_bytes(&pk_raw, &55u32.to_be_bytes())
            .expect("encrypt");
        let (c1, _) = setup.ct_components(&ct).expect("comp");
        let pd = setup.exp_bytes(&c1, &sk_bytes).expect("pd");

        // Prove with a different sk.
        let (sk2, _) = setup.keygen().expect("kg2");
        let wrong_sk = setup.sk_to_bytes(&sk2).expect("bytes");
        let proof = RPartDecProof::prove(&mut setup, &pk_raw, &ct, &pd, &wrong_sk).expect("prove");
        assert!(!proof.verify(&setup, &pk_raw, &ct, &pd).expect("verify"));
    }
}
