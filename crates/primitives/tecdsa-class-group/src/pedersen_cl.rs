// SPDX-License-Identifier: MIT OR Apache-2.0
#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown
)]

//! Pedersen commitment in the class group.
//!
//! The WMC24 DKG uses Pedersen commitments of the form:
//!
//! ```text
//! PC = h^a * g_q^{b * Delta}
//! ```
//!
//! where `h` is the CL hidden-order subgroup generator, `g_q` (= `f` in
//! the CL-HSMqk notation) is the order-`q` generator, and `Delta = n!`.
//!
//! In our CL-HSMqk implementation:
//! - `h` is the hidden-order generator accessed via `ClSetup::power_of_h_bytes`
//! - `g_q` = `f` is the order-`q` generator accessed via `ClSetup::power_of_f_bytes`

use rug::{Complete, Integer};
use tecdsa_bigint::BigIntExt;

use crate::cl::{ClResult, ClSetup, Qfi};

/// Compute a Pedersen commitment in the class group: `PC = h^a * g_q^{b * Delta}`.
///
/// # Arguments
///
/// - `setup`: the CL-HSMqk setup (provides `h`, `f = g_q`, and group operations).
/// - `a_bytes`: the first exponent `a` as big-endian unsigned bytes.
/// - `b_bytes`: the second exponent `b` as big-endian unsigned bytes.
/// - `delta`: the parameter `Delta = n!`.
///
/// # Returns
///
/// The QFI element `PC = h^a * f^{b * Delta}`.
pub fn pedersen_commit_cl(
    setup: &ClSetup,
    a_bytes: &[u8],
    b_bytes: &[u8],
    delta: &Integer,
) -> ClResult<Qfi> {
    // Compute h^a
    let h_a = setup.power_of_h_bytes(a_bytes)?;

    // Compute b * Delta
    let b = Integer::from_bytes_msf(b_bytes);
    let b_delta = (&b * delta).complete();

    // Compute g_q^{b * Delta} = f^{b * Delta}
    let b_delta_bytes = if b_delta.is_zero() {
        vec![0u8]
    } else {
        b_delta.to_bytes_msf()
    };
    let gq_bd = setup.power_of_f_bytes(&b_delta_bytes)?;

    // PC = h^a * g_q^{b * Delta}
    setup.compose(&h_a, &gq_bd)
}

/// Verify a Pedersen commitment: check `PC == h^a * g_q^{b * Delta}`.
///
/// Recomputes the commitment from the opening `(a, b)` and checks equality
/// with the given commitment `pc`.
///
/// # Arguments
///
/// - `setup`: the CL-HSMqk setup.
/// - `pc`: the commitment to verify.
/// - `a_bytes`: the claimed first exponent `a` as big-endian unsigned bytes.
/// - `b_bytes`: the claimed second exponent `b` as big-endian unsigned bytes.
/// - `delta`: the parameter `Delta = n!`.
///
/// # Returns
///
/// `true` if the recomputed commitment equals `pc`, `false` otherwise.
pub fn pedersen_verify_cl(
    setup: &ClSetup,
    pc: &Qfi,
    a_bytes: &[u8],
    b_bytes: &[u8],
    delta: &Integer,
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
        // delta = 6! = 720
        let delta = Integer::from(720u64);

        let pc = pedersen_commit_cl(&setup, &a_bytes, &b_bytes, &delta).unwrap();
        let valid = pedersen_verify_cl(&setup, &pc, &a_bytes, &b_bytes, &delta).unwrap();
        assert!(valid, "commitment should verify with correct opening");
    }

    #[test]
    fn verify_fails_with_wrong_opening() {
        let setup = test_setup();

        let a_bytes = 12345u64.to_be_bytes();
        let b_bytes = 67890u64.to_be_bytes();
        let delta = Integer::from(720u64);

        let pc = pedersen_commit_cl(&setup, &a_bytes, &b_bytes, &delta).unwrap();

        // Wrong a
        let wrong_a = 99999u64.to_be_bytes();
        let valid = pedersen_verify_cl(&setup, &pc, &wrong_a, &b_bytes, &delta).unwrap();
        assert!(!valid, "commitment should NOT verify with wrong a");

        // Wrong b
        let wrong_b = 11111u64.to_be_bytes();
        let valid = pedersen_verify_cl(&setup, &pc, &a_bytes, &wrong_b, &delta).unwrap();
        assert!(!valid, "commitment should NOT verify with wrong b");

        // Wrong delta
        let wrong_delta = Integer::from(100u64);
        let valid = pedersen_verify_cl(&setup, &pc, &a_bytes, &b_bytes, &wrong_delta).unwrap();
        assert!(!valid, "commitment should NOT verify with wrong delta");
    }

    #[test]
    fn commit_with_zero_b() {
        let setup = test_setup();

        let a_bytes = 42u64.to_be_bytes();
        let b_bytes = 0u64.to_be_bytes();
        let delta = Integer::from(720u64);

        let pc = pedersen_commit_cl(&setup, &a_bytes, &b_bytes, &delta).unwrap();
        let valid = pedersen_verify_cl(&setup, &pc, &a_bytes, &b_bytes, &delta).unwrap();
        assert!(valid, "commitment with zero b should verify");
    }

    #[test]
    fn commit_with_zero_delta() {
        let setup = test_setup();

        let a_bytes = 42u64.to_be_bytes();
        let b_bytes = 67890u64.to_be_bytes();
        let delta = Integer::from(0);

        let pc = pedersen_commit_cl(&setup, &a_bytes, &b_bytes, &delta).unwrap();
        let valid = pedersen_verify_cl(&setup, &pc, &a_bytes, &b_bytes, &delta).unwrap();
        assert!(valid, "commitment with zero delta should verify");
    }
}
