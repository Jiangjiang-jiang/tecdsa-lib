// SPDX-License-Identifier: GPL-3.0-or-later
#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    non_snake_case
)]

//! TX25 threshold key generation protocol.
//!
//! A 3-round protocol where $n$ parties produce shared ECDSA key material
//! using publicly-verifiable secret sharing (PVSS) and CL-HSM key generation.
//!
//! ## Protocol Rounds (from TX25, Section 4.1)
//!
//! 1. **Round 1 (CL Key Generation):** each party generates a CL keypair
//!    `(ek_i, dk_i)`, proves knowledge of the secret key with an `R_key`
//!    proof, and broadcasts `(ek_i, pi_bar_i)`.
//!
//! 2. **Round 2 (PVSS Share Distribution):** upon receiving and verifying
//!    all `R_key` proofs, each party runs PVSS `ShareDist` with all valid
//!    parties' encryption keys and broadcasts the encrypted shares plus an
//!    `R_Sh` proof.
//!
//! 3. **Round 3 (PVSS Share Combination):** upon receiving and verifying
//!    all `R_Sh` proofs, each party decrypts their shares, combines them
//!    into a single secret share `x_i`, computes `X_i = x_i * G`, generates
//!    an `R_Dec_DL` proof, and broadcasts `(X_i, pi'_i)`.
//!
//! 4. **Output:** upon receiving and verifying all `R_Dec_DL` proofs,
//!    each party computes the joint public key `X = sum lambda_{j,S} * X_j`
//!    and stores the `Tx25KeyShare`.
//!
//! ## Implementation
//!
//! The state machine collects messages per round, transitions when all
//! expected messages have arrived, and stores outgoing broadcasts.  CL
//! types are serialized as decimal strings (QFI -> (a, b, c) triplets).
//!
//! Reference: Tang & Xue. "Robust Threshold ECDSA." S&P 2025, Section 4.

pub mod machine;
pub mod msg;
pub mod rounds;

pub use machine::Tx25KeygenMachine;
pub use msg::Tx25KeygenMsg;

use elliptic_curve::group::GroupEncoding;

use tecdsa_class_group::bicycl_glue::{BicyclQfi, ClSetup};
use tecdsa_class_group::zk::r_dec_dl::RDecDlProof;
use tecdsa_class_group::zk::r_key::RKeyProof;
use tecdsa_class_group::zk::r_sh::RShProof;

use crate::error::Tx25Error;
use crate::pvss::PvssOutput;

// ---------------------------------------------------------------------------
// QFI serialization helpers
// ---------------------------------------------------------------------------

/// Extracts (a, b, c) decimal strings from a QFI element.
fn qfi_to_abc(setup: &ClSetup, qfi: &BicyclQfi) -> Result<(String, String, String), Tx25Error> {
    let ctx = setup.ctx();
    let a = qfi
        .a_decimal(ctx)
        .map_err(|e| Tx25Error::ClError(e.into()))?;
    let b = qfi
        .b_decimal(ctx)
        .map_err(|e| Tx25Error::ClError(e.into()))?;
    let c = qfi
        .c_decimal(ctx)
        .map_err(|e| Tx25Error::ClError(e.into()))?;
    Ok((a, b, c))
}

/// Reconstructs a QFI element from (a, b, c) decimal strings.
fn abc_to_qfi(setup: &ClSetup, abc: &(String, String, String)) -> Result<BicyclQfi, Tx25Error> {
    let ctx = setup.ctx();
    BicyclQfi::from_abc_decimal(ctx, &abc.0, &abc.1, &abc.2)
        .map_err(|e| Tx25Error::ClError(e.into()))
}

// ---------------------------------------------------------------------------
// Wire-format serialization / deserialization
//
// Messages are serialized as length-prefixed fields:
//   [4-byte LE length][field bytes]
// QFI elements are stored as three consecutive length-prefixed decimal strings.
// ---------------------------------------------------------------------------

/// Writes a length-prefixed byte field to a buffer.
fn write_field(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
    buf.extend_from_slice(data);
}

/// Reads a length-prefixed byte field from a buffer at the given position.
/// Returns (field_bytes, new_position).
fn read_field(data: &[u8], pos: usize) -> Result<(&[u8], usize), Tx25Error> {
    if pos + 4 > data.len() {
        return Err(Tx25Error::InvalidInput("truncated field length".into()));
    }
    let len = u32::from_le_bytes(
        data[pos..pos + 4]
            .try_into()
            .map_err(|_| Tx25Error::InvalidInput("bad length bytes".into()))?,
    ) as usize;
    let start = pos + 4;
    let end = start + len;
    if end > data.len() {
        return Err(Tx25Error::InvalidInput("truncated field data".into()));
    }
    Ok((&data[start..end], end))
}

/// Reads a length-prefixed UTF-8 string field.
fn read_string_field(data: &[u8], pos: usize) -> Result<(String, usize), Tx25Error> {
    let (bytes, new_pos) = read_field(data, pos)?;
    let s = std::str::from_utf8(bytes)
        .map_err(|e| Tx25Error::InvalidInput(format!("invalid UTF-8: {e}")))?
        .to_string();
    Ok((s, new_pos))
}

/// Serializes a QFI's (a, b, c) decimal strings.
fn write_qfi_abc(buf: &mut Vec<u8>, abc: &(String, String, String)) {
    write_field(buf, abc.0.as_bytes());
    write_field(buf, abc.1.as_bytes());
    write_field(buf, abc.2.as_bytes());
}

/// Deserializes a QFI's (a, b, c) decimal strings.
fn read_qfi_abc(data: &[u8], pos: usize) -> Result<((String, String, String), usize), Tx25Error> {
    let (a, pos) = read_string_field(data, pos)?;
    let (b, pos) = read_string_field(data, pos)?;
    let (c, pos) = read_string_field(data, pos)?;
    Ok(((a, b, c), pos))
}

/// Serializes a Round 1 message: pk_abc + R_key proof (t_abc, z, e).
fn serialize_round1(
    setup: &ClSetup,
    pk_abc: &(String, String, String),
    proof: &RKeyProof,
) -> Result<Vec<u8>, Tx25Error> {
    let mut buf = Vec::new();

    // CL public key (a, b, c).
    write_qfi_abc(&mut buf, pk_abc);

    // R_key proof: t (QFI abc), z (string), e (string).
    let t_abc = qfi_to_abc(setup, &proof.t)?;
    write_qfi_abc(&mut buf, &t_abc);
    write_field(&mut buf, &proof.z);
    write_field(&mut buf, &proof.e);

    Ok(buf)
}

/// Deserializes a Round 1 message.
fn deserialize_round1(
    data: &[u8],
    setup: &ClSetup,
) -> Result<((String, String, String), RKeyProof), Tx25Error> {
    let (pk_abc, pos) = read_qfi_abc(data, 0)?;
    let (t_abc, pos) = read_qfi_abc(data, pos)?;
    let (z_bytes, pos) = read_field(data, pos)?;
    let (e_bytes, _pos) = read_field(data, pos)?;

    let t = abc_to_qfi(setup, &t_abc)?;
    let proof = RKeyProof {
        t,
        z: z_bytes.to_vec(),
        e: e_bytes.to_vec(),
    };

    Ok((pk_abc, proof))
}

/// Serializes a Round 2 message: c1_abc + n * c2_abc + R_Sh proof (k, rho_response).
fn serialize_round2(setup: &ClSetup, pvss: &PvssOutput) -> Result<Vec<u8>, Tx25Error> {
    let mut buf = Vec::new();

    // Number of c2 elements.
    buf.extend_from_slice(&(pvss.c2s.len() as u32).to_le_bytes());

    // c1 (QFI abc).
    let c1_abc = qfi_to_abc(setup, &pvss.c1)?;
    write_qfi_abc(&mut buf, &c1_abc);

    // c2s (each as QFI abc).
    for c2 in &pvss.c2s {
        let c2_abc = qfi_to_abc(setup, c2)?;
        write_qfi_abc(&mut buf, &c2_abc);
    }

    // R_Sh proof: k (bytes), rho_response (bytes).
    write_field(&mut buf, &pvss.proof.k);
    write_field(&mut buf, &pvss.proof.rho_response);

    Ok(buf)
}

/// Deserializes a Round 2 message.
fn deserialize_round2(
    data: &[u8],
    setup: &ClSetup,
) -> Result<(BicyclQfi, Vec<BicyclQfi>, RShProof), Tx25Error> {
    if data.len() < 4 {
        return Err(Tx25Error::InvalidInput("R2 data too short".into()));
    }
    let n = u32::from_le_bytes(
        data[0..4]
            .try_into()
            .map_err(|_| Tx25Error::InvalidInput("bad n bytes".into()))?,
    ) as usize;
    let mut pos = 4;

    // c1.
    let (c1_abc, new_pos) = read_qfi_abc(data, pos)?;
    pos = new_pos;
    let c1 = abc_to_qfi(setup, &c1_abc)?;

    // c2s.
    let mut c2s = Vec::with_capacity(n);
    for _ in 0..n {
        let (c2_abc, new_pos) = read_qfi_abc(data, pos)?;
        pos = new_pos;
        c2s.push(abc_to_qfi(setup, &c2_abc)?);
    }

    // R_Sh proof.
    let (k_bytes, new_pos) = read_field(data, pos)?;
    pos = new_pos;
    let (rho_response_bytes, _) = read_field(data, pos)?;

    let proof = RShProof {
        k: k_bytes.to_vec(),
        rho_response: rho_response_bytes.to_vec(),
    };

    Ok((c1, c2s, proof))
}

/// Serializes a Round 3 message: X_i bytes + pd (QFI abc) + R_Dec_DL proof.
fn serialize_round3(
    setup: &ClSetup,
    public_share_bytes: &[u8],
    pd: &BicyclQfi,
    proof: &RDecDlProof,
) -> Result<Vec<u8>, Tx25Error> {
    let mut buf = Vec::new();

    // Public share (compressed EC point).
    write_field(&mut buf, public_share_bytes);

    // Partial decryption pd = c1^{sk} (QFI abc).
    let pd_abc = qfi_to_abc(setup, pd)?;
    write_qfi_abc(&mut buf, &pd_abc);

    // R_Dec_DL proof: t1 (QFI abc), t2 (QFI abc), z (string), e (string).
    let t1_abc = qfi_to_abc(setup, &proof.t1)?;
    let t2_abc = qfi_to_abc(setup, &proof.t2)?;
    write_qfi_abc(&mut buf, &t1_abc);
    write_qfi_abc(&mut buf, &t2_abc);
    write_field(&mut buf, &proof.z);
    write_field(&mut buf, &proof.e);

    Ok(buf)
}

/// Deserializes a Round 3 message (includes pd for R_Dec_DL verification).
fn deserialize_round3(
    data: &[u8],
    setup: &ClSetup,
) -> Result<(k256::ProjectivePoint, RDecDlProof, BicyclQfi), Tx25Error> {
    let (point_bytes, pos) = read_field(data, 0)?;

    // Parse EC point.
    let repr = k256::CompressedPoint::try_from(point_bytes)
        .map_err(|e| Tx25Error::InvalidInput(format!("invalid point bytes: {e}")))?;
    let point: k256::ProjectivePoint = Option::from(k256::ProjectivePoint::from_bytes(&repr))
        .ok_or_else(|| Tx25Error::InvalidInput("invalid EC point".into()))?;

    // Partial decryption pd (QFI abc).
    let (pd_abc, pos) = read_qfi_abc(data, pos)?;
    let pd = abc_to_qfi(setup, &pd_abc)?;

    // R_Dec_DL proof.
    let (t1_abc, pos) = read_qfi_abc(data, pos)?;
    let (t2_abc, pos) = read_qfi_abc(data, pos)?;
    let (z_bytes, pos) = read_field(data, pos)?;
    let (e_bytes, _) = read_field(data, pos)?;

    let t1 = abc_to_qfi(setup, &t1_abc)?;
    let t2 = abc_to_qfi(setup, &t2_abc)?;
    let proof = RDecDlProof {
        t1,
        t2,
        z: z_bytes.to_vec(),
        e: e_bytes.to_vec(),
    };

    Ok((point, proof, pd))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use elliptic_curve::CurveArithmetic;
    use tecdsa_protocol::{PartyId, StateMachine};

    /// Runs the TX25 keygen state machine for `n` parties with threshold `t`.
    ///
    /// Uses the testkit `Orchestrator` to drive all machines to completion,
    /// then returns the resulting key shares.
    fn run_keygen_state_machine(n: usize, t: u16) -> Vec<crate::key_share::Tx25KeyShare> {
        let seed = "90001";

        let parties: Vec<PartyId> = (0..n as u16).map(PartyId).collect();

        let machines: Vec<(PartyId, Tx25KeygenMachine)> = parties
            .iter()
            .map(|&pid| {
                let machine = Tx25KeygenMachine::new(pid, parties.clone(), t, seed, false)
                    .unwrap_or_else(|e| panic!("new() failed for party {pid}: {e}"));
                (pid, machine)
            })
            .collect();

        let orchestrator = tecdsa_testkit::Orchestrator::new(machines, 10);
        let results = orchestrator.run().expect("orchestrator must succeed");

        results
            .into_iter()
            .enumerate()
            .map(|(i, r)| r.unwrap_or_else(|e| panic!("party {i} finish() failed: {e}")))
            .collect()
    }

    #[test]
    fn test_keygen_3_of_2() {
        // TX25 honest majority: n >= 2t-1, so n=3 requires t <= 2.
        let shares = run_keygen_state_machine(3, 2);

        // All parties should agree on the joint public key.
        let pk0 = shares[0].public_key;
        for share in &shares[1..] {
            assert_eq!(
                pk0, share.public_key,
                "all parties should agree on the joint public key"
            );
        }

        // Each party should have a distinct secret share.
        assert_ne!(shares[0].secret_share, shares[1].secret_share);
        assert_ne!(shares[1].secret_share, shares[2].secret_share);

        // Verify public_shares[i] = secret_share_i * G.
        for share in &shares {
            let expected = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR
                * share.secret_share;
            let my_idx = (share.party_index - 1) as usize;
            assert_eq!(
                share.public_shares[my_idx], expected,
                "public_share should match secret_share * G for party {}",
                share.party_index
            );
        }

        // Verify the joint public key is the Lagrange-interpolated sum of public shares.
        let indices: Vec<u16> = (1..=3).collect();
        let lambdas = tecdsa_vss::lagrange::coefficients::<k256::Secp256k1>(&indices);
        let reconstructed_pk = shares[0].public_shares.iter().zip(lambdas.iter()).fold(
            <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::IDENTITY,
            |acc, (x_j, l_j)| acc + *x_j * l_j,
        );
        assert_eq!(
            pk0, reconstructed_pk,
            "Lagrange reconstruction should match joint PK"
        );
    }

    #[test]
    fn test_keygen_5_of_3() {
        let shares = run_keygen_state_machine(5, 3);

        // All parties should agree on the joint public key.
        let pk0 = shares[0].public_key;
        for share in &shares[1..] {
            assert_eq!(pk0, share.public_key);
        }

        // Verify all public shares match secret shares.
        for share in &shares {
            let expected = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR
                * share.secret_share;
            let my_idx = (share.party_index - 1) as usize;
            assert_eq!(share.public_shares[my_idx], expected);
        }

        // Verify Lagrange reconstruction with all 5 parties.
        let indices: Vec<u16> = (1..=5).collect();
        let lambdas = tecdsa_vss::lagrange::coefficients::<k256::Secp256k1>(&indices);
        let reconstructed_pk = shares[0].public_shares.iter().zip(lambdas.iter()).fold(
            <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::IDENTITY,
            |acc, (x_j, l_j)| acc + *x_j * l_j,
        );
        assert_eq!(pk0, reconstructed_pk);

        // Also verify with a subset of 3 parties (threshold).
        let subset_indices: Vec<u16> = vec![1, 3, 5];
        let subset_lambdas = tecdsa_vss::lagrange::coefficients::<k256::Secp256k1>(&subset_indices);
        let subset_shares: Vec<k256::ProjectivePoint> = subset_indices
            .iter()
            .map(|&i| shares[0].public_shares[(i - 1) as usize])
            .collect();
        let subset_pk = subset_shares.iter().zip(subset_lambdas.iter()).fold(
            <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::IDENTITY,
            |acc, (x_j, l_j)| acc + *x_j * l_j,
        );
        assert_eq!(
            pk0, subset_pk,
            "threshold subset should reconstruct same PK"
        );
    }

    #[test]
    fn test_keygen_metadata() {
        let shares = run_keygen_state_machine(3, 2);

        for share in &shares {
            assert_eq!(share.threshold, 2);
            assert_eq!(share.total, 3);
            assert!(!share.cl_setup_seed.is_empty());
        }
        assert_eq!(shares[0].party_index, 1);
        assert_eq!(shares[1].party_index, 2);
        assert_eq!(shares[2].party_index, 3);
    }

    #[test]
    fn keygen_rejects_unknown_party() {
        let seed = "90001";
        let parties: Vec<PartyId> = (0..3u16).map(PartyId).collect();

        let mut machine = Tx25KeygenMachine::new(PartyId(0), parties, 2, seed, false)
            .expect("machine creation should succeed");

        // Drain initial outgoing so the machine is in Round1.
        let _out = machine.drain_outgoing();

        // Send a Round1 message from an unknown party (PartyId(99)).
        let result = machine.handle(PartyId(99), Tx25KeygenMsg::Round1(vec![0u8; 64]));
        let err = result.expect_err("should reject unknown party");
        let msg = format!("{err}");
        assert!(
            msg.contains("unknown party"),
            "error should mention unknown party, got: {msg}"
        );
    }
}
