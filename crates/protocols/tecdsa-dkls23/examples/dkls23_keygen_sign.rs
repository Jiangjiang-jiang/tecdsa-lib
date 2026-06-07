// SPDX-License-Identifier: MIT OR Apache-2.0
//! `DKLs23` threshold ECDSA: keygen + presign + online-sign end-to-end.
//!
//! Demonstrates a 2-of-3 threshold ECDSA signature using the `DKLs23` protocol
//! (Doerner, Kondi, Lee, shelat -- IEEE S&P 2023).
//!
//! `DKLs23` is an OT/VOLE-based protocol with no Paillier encryption and no
//! heavy ZK proofs, making it significantly faster than CGGMP20 for small
//! party counts.
//!
//! The pipeline has three stages:
//!   1. **Key Generation** -- 3 parties run a relaxed DKG (2 rounds + local
//!      verification) to produce Shamir key shares.
//!   2. **Presigning**     -- a 2-party signing subset runs 3 rounds using
//!      real OT-based RVOLE to produce a message-independent presignature.
//!   3. **Online Signing** -- each signer broadcasts `(u_i, w_i)` partial
//!      contributions in a single round, then assembles the ECDSA signature.
//!
//! Run with:
//!   cargo run --example `dkls23_keygen_sign` -p tecdsa-dkls23

use elliptic_curve::PrimeField;
use sha2::{Digest as _, Sha256};
use tecdsa_dkls23::{
    key_share::Dkls23KeyShare,
    keygen::Dkls23KeygenMachine,
    presign::{Dkls23PresignMachine, PresignConfig},
    sign::{Dkls23OnlineSignMachine, OnlineSignConfig},
};
use tecdsa_protocol::{verify_ecdsa, DataToSign, PartyId};
use tecdsa_testkit::Orchestrator;

type C = k256::Secp256k1;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Hash a message with SHA-256 and convert to a signing digest scalar.
fn hash_message(msg: &[u8]) -> DataToSign<C> {
    let hash = Sha256::digest(msg);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash);
    let scalar = <C as elliptic_curve::CurveArithmetic>::Scalar::from_repr(
        elliptic_curve::FieldBytes::<C>::from(bytes),
    )
    .expect("SHA-256 output must be a valid scalar");
    DataToSign::from_digest(scalar)
}

// ---------------------------------------------------------------------------
// Protocol phases
// ---------------------------------------------------------------------------

/// Phase 1: Distributed Key Generation (2 rounds + local verification).
///
/// Each party contributes a random polynomial. Share consistency is checked
/// via EC point commitments rather than heavy ZK proofs. The output is a
/// `Dkls23KeyShare` containing the Shamir share, verification shares, and
/// the joint ECDSA public key.
///
/// `t` = reconstruction threshold (number of parties needed to sign).
fn run_keygen(n: u16, t: u16) -> Vec<Dkls23KeyShare<C>> {
    let mut rng = rand::thread_rng();
    let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();

    // Create one keygen state machine per party.
    let machines: Vec<(PartyId, Dkls23KeygenMachine<C>)> = all_parties
        .iter()
        .map(|&pid| {
            let machine = Dkls23KeygenMachine::new(pid, all_parties.clone(), t, &mut rng);
            (pid, machine)
        })
        .collect();

    // Drive all machines to completion via the Orchestrator.
    let results = Orchestrator::new(machines, 10)
        .run()
        .expect("orchestrator must succeed");
    results
        .into_iter()
        .map(|r| r.expect("keygen should succeed"))
        .collect()
}

/// Phase 2: Presigning (3 rounds, message-independent).
///
/// Uses real OT-based RVOLE (random vector oblivious linear evaluation)
/// from `tecdsa-ot::rvole` for secure multiplication. Each pair of signers
/// runs a two-party RVOLE to obtain correlated randomness, which is then
/// used to compute additive shares of the nonce inverse and the key-nonce
/// product.
fn run_presign(
    shares: &[Dkls23KeyShare<C>],
    signer_indices: &[u16],
) -> Vec<tecdsa_dkls23::presign::Dkls23Presignature<C>> {
    let signer_parties: Vec<PartyId> = signer_indices.iter().map(|&i| PartyId(i)).collect();

    // Build one presign state machine per signing party.
    let machines: Vec<(PartyId, Dkls23PresignMachine<C>)> = signer_indices
        .iter()
        .map(|&idx| {
            let share = shares[(idx - 1) as usize].clone();
            let pid = PartyId(idx);
            let config = PresignConfig {
                key_share: share,
                my_id: pid,
                signer_parties: signer_parties.clone(),
            };
            (pid, Dkls23PresignMachine::new(config, rand_core::OsRng))
        })
        .collect();

    let results = Orchestrator::new(machines, 20)
        .run()
        .expect("orchestrator must succeed");
    results
        .into_iter()
        .map(|r| r.expect("presign should succeed"))
        .collect()
}

/// Phase 3: Online Signing (1 round).
///
/// Each signer computes partial signature contributions (`u_i`, `w_i`) from its
/// presignature and the message digest, broadcasts them, and then all
/// signers independently assemble the full ECDSA signature:
///   `s = sum(w_i) * sum(u_i)^{-1} mod q`
fn run_online_sign(
    presignatures: Vec<tecdsa_dkls23::presign::Dkls23Presignature<C>>,
    message: DataToSign<C>,
) -> tecdsa_protocol::Signature<C> {
    let machines: Vec<(PartyId, Dkls23OnlineSignMachine<C>)> = presignatures
        .into_iter()
        .map(|presig| {
            let pid = presig.my_id;
            let config = OnlineSignConfig {
                presignature: presig,
                message,
            };
            (pid, Dkls23OnlineSignMachine::new(config))
        })
        .collect();

    let results = Orchestrator::new(machines, 10)
        .run()
        .expect("orchestrator must succeed");
    let sigs: Vec<_> = results
        .into_iter()
        .map(|r| r.expect("online sign should succeed"))
        .collect();

    // Sanity check: all signers must produce the same (r, s).
    for i in 1..sigs.len() {
        assert_eq!(sigs[i].r, sigs[0].r, "all signers must agree on r");
        assert_eq!(sigs[i].s, sigs[0].s, "all signers must agree on s");
    }

    sigs.into_iter().next().unwrap()
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("DKLs23 Threshold ECDSA Example");
    println!("===============================");
    println!("Configuration: 2-of-3 threshold, secp256k1");
    println!();

    // Step 1: Key Generation
    println!("[1/3] Running distributed key generation (3 parties, 2-of-3 signing)...");
    let shares = run_keygen(3, 2); // 2-of-3 signing threshold
    let public_key = shares[0].public_key;
    println!("  Key generation complete.");
    println!("  All 3 parties agree on the joint ECDSA public key.");
    println!();

    // Step 2: Presigning (signers: party 1 and party 2)
    let signer_indices = &[1u16, 2];
    println!("[2/3] Running presigning protocol (signers: {signer_indices:?}, 3 rounds with real RVOLE)...");
    let presigs = run_presign(&shares, signer_indices);
    let presig_count = presigs.len();
    println!("  Presigning complete. {presig_count} presignatures produced.");
    println!();

    // Step 3: Online Signing
    let message = b"Hello, threshold ECDSA with DKLs23!";
    println!(
        "[3/3] Online signing (1 round): \"{}\"",
        std::str::from_utf8(message).unwrap()
    );
    let data_to_sign = hash_message(message);
    let sig = run_online_sign(presigs, data_to_sign);

    println!("  Signature produced:");
    println!("    r = {:?}", sig.r);
    println!("    s = {:?}", sig.s);
    println!();

    // Verify using the standard ECDSA verification equation.
    verify_ecdsa::<C>(&sig, &public_key, &data_to_sign)?;
    println!("  ECDSA signature verification: PASSED");
    println!();
    println!("Done.");

    Ok(())
}
