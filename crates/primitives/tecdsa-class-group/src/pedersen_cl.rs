#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown
)]

use crate::cl::{ClResult, ClSetup, Mpz, Qfi};

pub fn pedersen_commit_cl(
    setup: &ClSetup,
    a_bytes: &[u8],
    b_bytes: &[u8],
    delta: &Mpz,
) -> ClResult<Qfi> {
    let h_a = setup.power_of_h_bytes(a_bytes)?;

    let b = Mpz::from_bytes_be(b_bytes);
    let b_delta = &b * delta;

    let b_delta_bytes = if b_delta.is_zero() {
        vec![0u8]
    } else {
        b_delta.to_bytes_be()
    };
    let gq_bd = setup.power_of_f_bytes(&b_delta_bytes)?;

    setup.compose(&h_a, &gq_bd)
}

pub fn pedersen_verify_cl(
    setup: &ClSetup,
    pc: &Qfi,
    a_bytes: &[u8],
    b_bytes: &[u8],
    delta: &Mpz,
) -> ClResult<bool> {
    let recomputed = pedersen_commit_cl(setup, a_bytes, b_bytes, delta)?;
    Ok(*pc == recomputed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_setup() -> ClSetup {
        ClSetup::new_secp256k1("42").unwrap()
    }

    #[test]
    fn commit_and_verify() {
        let setup = test_setup();

        let a_bytes = 12345u64.to_be_bytes();
        let b_bytes = 67890u64.to_be_bytes();
        let delta = Mpz::from(720u64);

        let pc = pedersen_commit_cl(&setup, &a_bytes, &b_bytes, &delta).unwrap();
        let valid = pedersen_verify_cl(&setup, &pc, &a_bytes, &b_bytes, &delta).unwrap();
        assert!(valid, "commitment should verify with correct opening");
    }

    #[test]
    fn verify_fails_with_wrong_opening() {
        let setup = test_setup();

        let a_bytes = 12345u64.to_be_bytes();
        let b_bytes = 67890u64.to_be_bytes();
        let delta = Mpz::from(720u64);

        let pc = pedersen_commit_cl(&setup, &a_bytes, &b_bytes, &delta).unwrap();

        let wrong_a = 99999u64.to_be_bytes();
        let valid = pedersen_verify_cl(&setup, &pc, &wrong_a, &b_bytes, &delta).unwrap();
        assert!(!valid, "commitment should NOT verify with wrong a");

        let wrong_b = 11111u64.to_be_bytes();
        let valid = pedersen_verify_cl(&setup, &pc, &a_bytes, &wrong_b, &delta).unwrap();
        assert!(!valid, "commitment should NOT verify with wrong b");

        let wrong_delta = Mpz::from(100u64);
        let valid = pedersen_verify_cl(&setup, &pc, &a_bytes, &b_bytes, &wrong_delta).unwrap();
        assert!(!valid, "commitment should NOT verify with wrong delta");
    }

    #[test]
    fn commit_with_zero_b() {
        let setup = test_setup();

        let a_bytes = 42u64.to_be_bytes();
        let b_bytes = 0u64.to_be_bytes();
        let delta = Mpz::from(720u64);

        let pc = pedersen_commit_cl(&setup, &a_bytes, &b_bytes, &delta).unwrap();
        let valid = pedersen_verify_cl(&setup, &pc, &a_bytes, &b_bytes, &delta).unwrap();
        assert!(valid, "commitment with zero b should verify");
    }

    #[test]
    fn commit_with_zero_delta() {
        let setup = test_setup();

        let a_bytes = 42u64.to_be_bytes();
        let b_bytes = 67890u64.to_be_bytes();
        let delta = Mpz::from(0);

        let pc = pedersen_commit_cl(&setup, &a_bytes, &b_bytes, &delta).unwrap();
        let valid = pedersen_verify_cl(&setup, &pc, &a_bytes, &b_bytes, &delta).unwrap();
        assert!(valid, "commitment with zero delta should verify");
    }
}
