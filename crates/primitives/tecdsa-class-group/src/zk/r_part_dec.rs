// SPDX-License-Identifier: MIT OR Apache-2.0
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
    use rug::Integer;

    use super::*;
    use crate::cl::ClSetup;

    #[test]
    fn r_part_dec_honest_verifies() {
        let mut setup = ClSetup::new_secp256k1(7001u64).expect("setup");
        let (sk_raw, pk_raw) = setup.keygen().expect("keygen");
        let sk = setup.sk_to_integer(&sk_raw);

        let ct = setup
            .encrypt(&pk_raw, &Integer::from(55u32))
            .expect("encrypt");
        let (c1, _) = setup.ct_components(&ct).expect("comp");
        let pd = setup.exp(&c1, &sk).expect("pd");

        let proof = RPartDecProof::prove(&mut setup, &pk_raw, &ct, &pd, &sk).expect("prove");
        assert!(proof.verify(&setup, &pk_raw, &ct, &pd).expect("verify"));
    }

    #[test]
    #[ignore = "redundant ZK negative test"]
    fn r_part_dec_rejects_wrong_dec() {
        let mut setup = ClSetup::new_secp256k1(7002u64).expect("setup");
        let (sk_raw, pk_raw) = setup.keygen().expect("keygen");
        let sk = setup.sk_to_integer(&sk_raw);

        let ct = setup
            .encrypt(&pk_raw, &Integer::from(55u32))
            .expect("encrypt");
        let (c1, _) = setup.ct_components(&ct).expect("comp");
        let pd = setup.exp(&c1, &sk).expect("pd");

        // Prove with a different sk.
        let (sk2, _) = setup.keygen().expect("kg2");
        let wrong_sk = setup.sk_to_integer(&sk2);
        let proof = RPartDecProof::prove(&mut setup, &pk_raw, &ct, &pd, &wrong_sk).expect("prove");
        assert!(!proof.verify(&setup, &pk_raw, &ct, &pd).expect("verify"));
    }
}
