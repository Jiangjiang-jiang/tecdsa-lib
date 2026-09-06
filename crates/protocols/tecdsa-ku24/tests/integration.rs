// SPDX-License-Identifier: MIT OR Apache-2.0
//! KU24 end-to-end integration tests.
//!
//! Covers PRSS setup -> keygen -> batch presign -> online sign -> ECDSA verify,
//! plus the two properties the paper is about: presignatures are
//! *key-independent* and they are produced in *batches* at a constant round
//! cost.

use elliptic_curve::PrimeField;
use k256::{ProjectivePoint, Scalar, Secp256k1};
use sha2::{Digest, Sha256};
use tecdsa_curve::TecdsaCurve;
use tecdsa_ku24::{
    error::Ku24Error,
    keygen::Ku24KeygenMachine,
    presign::{Ku24PresignBatch, Ku24PresignMachine, Ku24Presignature},
    prss::PrssKeys,
    setup::Ku24SetupMachine,
    sign::Ku24SignMachine,
    Ku24KeyShare, Ku24Protocol,
};
use tecdsa_protocol::{
    ecdsa::{verify_ecdsa, DataToSign, Signature},
    PartyId, Protocol, StateMachine,
};
use tecdsa_testkit::Orchestrator;

type C = Secp256k1;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn party_ids(n: u16) -> Vec<PartyId> {
    (1..=n).map(PartyId).collect()
}

fn run<M>(machines: Vec<(PartyId, M)>, max_rounds: u16) -> Vec<M::Output>
where
    M: StateMachine,
    M::Outbound: Clone + Into<M::Inbound> + serde::Serialize + serde::de::DeserializeOwned,
    M::Inbound: Clone + serde::Serialize + serde::de::DeserializeOwned,
{
    Orchestrator::new(machines, max_rounds)
        .run()
        .expect("orchestrator must succeed")
        .into_iter()
        .enumerate()
        .map(|(i, r)| r.unwrap_or_else(|e| panic!("party {} finish() failed: {e}", i + 1)))
        .collect()
}

fn run_setup(n: u16, threshold: u16) -> Vec<PrssKeys<C>> {
    let parties = party_ids(n);
    let machines = parties
        .iter()
        .map(|&pid| {
            (
                pid,
                Ku24SetupMachine::<C>::new(pid, parties.clone(), threshold)
                    .expect("PRSS setup machine"),
            )
        })
        .collect();
    run(machines, 4)
}

fn run_keygen(n: u16, prss: &[PrssKeys<C>], key_id: &[u8; 32]) -> Vec<Ku24KeyShare<C>> {
    let parties = party_ids(n);
    let machines = parties
        .iter()
        .zip(prss)
        .map(|(&pid, keys)| {
            (
                pid,
                Ku24KeygenMachine::new(pid, parties.clone(), keys, key_id).expect("keygen machine"),
            )
        })
        .collect();
    run(machines, 4)
}

fn run_presign(
    n: u16,
    prss: &[PrssKeys<C>],
    m: usize,
    session: &[u8; 32],
) -> Vec<Ku24PresignBatch<C>> {
    let parties = party_ids(n);
    let machines = parties
        .iter()
        .zip(prss)
        .map(|(&pid, keys)| {
            (
                pid,
                Ku24PresignMachine::new_with_session(pid, parties.clone(), keys, m, session)
                    .expect("presign machine"),
            )
        })
        .collect();
    run(machines, 12)
}

fn run_sign(
    n: u16,
    shares: &[Ku24KeyShare<C>],
    presigs: Vec<Ku24Presignature<C>>,
    digest: DataToSign<C>,
) -> Vec<Signature<C>> {
    let parties = party_ids(n);
    let machines = parties
        .iter()
        .zip(shares)
        .zip(presigs)
        .map(|((&pid, share), presig)| {
            (
                pid,
                Ku24SignMachine::new(pid, parties.clone(), share, presig, digest)
                    .expect("sign machine"),
            )
        })
        .collect();
    run(machines, 4)
}

fn digest_of(msg: &[u8]) -> DataToSign<C> {
    let hash = Sha256::digest(msg);
    let mut repr = k256::FieldBytes::default();
    repr.copy_from_slice(&hash);
    let scalar = Option::<Scalar>::from(Scalar::from_repr(repr))
        .unwrap_or_else(|| C::scalar_from_bytes(&hash));
    DataToSign::from_digest(scalar)
}

/// Pull presignature `index` out of every party's batch.
fn take_presignature(batches: &[Ku24PresignBatch<C>], index: usize) -> Vec<Ku24Presignature<C>> {
    batches
        .iter()
        .map(|b| b.get(index).expect("presignature index in range").clone())
        .collect()
}

fn sign_and_verify(
    n: u16,
    shares: &[Ku24KeyShare<C>],
    presigs: Vec<Ku24Presignature<C>>,
    msg: &[u8],
) -> Signature<C> {
    let digest = digest_of(msg);
    let sigs = run_sign(n, shares, presigs, digest);
    for sig in &sigs[1..] {
        assert_eq!(sigs[0].r, sig.r, "parties disagree on r");
        assert_eq!(sigs[0].s, sig.s, "parties disagree on s");
    }
    verify_ecdsa::<C>(&sigs[0], &shares[0].public_key, &digest)
        .expect("the signature must verify under the public key");
    sigs.into_iter().next().expect("at least one signature")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn full_protocol_5_parties_threshold_3() {
    let (n, threshold) = (5u16, 3u16); // t = 2, n = 2t + 1

    let prss = run_setup(n, threshold);
    let shares = run_keygen(n, &prss, &[1u8; 32]);

    // Everyone agrees on the public key, and the shares interpolate to it.
    let public_key = shares[0].public_key;
    for share in &shares {
        assert_eq!(share.public_key, public_key);
        assert_eq!(share.threshold, threshold);
        assert_eq!(share.total, n);
        assert_eq!(
            share.public_shares[usize::from(share.party_index) - 1],
            ProjectivePoint::GENERATOR * share.secret_share
        );
    }
    // Only t + 1 = 3 shares are needed to reconstruct.
    let indices: Vec<u16> = (1..=threshold).collect();
    let lambdas = tecdsa_vss::lagrange::coefficients::<C>(&indices);
    let recovered = indices
        .iter()
        .zip(&lambdas)
        .fold(ProjectivePoint::IDENTITY, |acc, (&i, l)| {
            acc + shares[usize::from(i) - 1].public_shares[usize::from(i) - 1] * l
        });
    assert_eq!(recovered, public_key);

    let batches = run_presign(n, &prss, 3, &[2u8; 32]);
    for batch in &batches {
        assert_eq!(batch.len(), 3);
    }
    // All parties agree on every R_i and r_i.
    for i in 0..3 {
        let first = batches[0].get(i).unwrap();
        for batch in &batches {
            assert_eq!(batch.get(i).unwrap().r, first.r);
            assert_eq!(batch.get(i).unwrap().big_r, first.big_r);
        }
        assert_eq!(
            first.r,
            <C as TecdsaCurve>::xcoord_mod_q(&first.big_r.to_affine())
        );
    }

    sign_and_verify(n, &shares, take_presignature(&batches, 0), b"hello KU24");
}

#[test]
fn full_protocol_7_parties_threshold_4() {
    let (n, threshold) = (7u16, 4u16); // t = 3, n = 2t + 1
    let prss = run_setup(n, threshold);
    let shares = run_keygen(n, &prss, &[3u8; 32]);
    let batches = run_presign(n, &prss, 2, &[4u8; 32]);
    sign_and_verify(n, &shares, take_presignature(&batches, 0), b"seven parties");
}

#[test]
fn works_with_more_than_2t_plus_1_parties() {
    // n = 6 > 2t + 1 = 5: the extra point gives redundancy for the degree-t
    // consistency checks, and the degree-2t openings become checkable too.
    let (n, threshold) = (6u16, 3u16);
    let prss = run_setup(n, threshold);
    let shares = run_keygen(n, &prss, &[5u8; 32]);
    let batches = run_presign(n, &prss, 1, &[6u8; 32]);
    sign_and_verify(n, &shares, take_presignature(&batches, 0), b"n > 2t+1");
}

/// The headline property: one presignature batch, many *different* keys.
#[test]
fn presignatures_are_key_independent() {
    let (n, threshold) = (5u16, 3u16);
    let prss = run_setup(n, threshold);

    // Three distinct keys hosted by the same network.
    let key_a = run_keygen(n, &prss, &[0xAA; 32]);
    let key_b = run_keygen(n, &prss, &[0xBB; 32]);
    let key_c = run_keygen(n, &prss, &[0xCC; 32]);
    assert_ne!(key_a[0].public_key, key_b[0].public_key);
    assert_ne!(key_b[0].public_key, key_c[0].public_key);

    // One batch of presignatures, generated with no knowledge of any of them.
    let batches = run_presign(n, &prss, 3, &[7u8; 32]);

    // Each presignature can be spent under whichever key we like.
    sign_and_verify(n, &key_b, take_presignature(&batches, 0), b"msg for key B");
    sign_and_verify(n, &key_a, take_presignature(&batches, 1), b"msg for key A");
    sign_and_verify(n, &key_c, take_presignature(&batches, 2), b"msg for key C");
}

/// The other headline property: `m` presignatures at a constant round cost.
#[test]
fn batch_presigning_is_constant_round_and_all_entries_usable() {
    let (n, threshold, m) = (5u16, 3u16, 8usize);
    let prss = run_setup(n, threshold);
    let shares = run_keygen(n, &prss, &[8u8; 32]);

    let parties = party_ids(n);
    let machines: Vec<_> = parties
        .iter()
        .zip(&prss)
        .map(|(&pid, keys)| {
            (
                pid,
                Ku24PresignMachine::new_with_session(pid, parties.clone(), keys, m, &[9u8; 32])
                    .expect("presign machine"),
            )
        })
        .collect();
    // The presign phase advertises four rounds; give the orchestrator exactly
    // that many and confirm the batch still completes regardless of m.
    let batches: Vec<Ku24PresignBatch<C>> = Orchestrator::new(machines, 4)
        .run()
        .expect("presign must complete within 4 rounds")
        .into_iter()
        .map(|r| r.expect("presign output"))
        .collect();

    // Every presignature is distinct and usable.
    let mut seen = Vec::new();
    for i in 0..m {
        let presigs = take_presignature(&batches, i);
        assert!(!seen.contains(&presigs[0].r), "presignature {i} repeats r");
        seen.push(presigs[0].r);
        sign_and_verify(n, &shares, presigs, format!("message {i}").as_bytes());
    }
}

#[test]
fn distinct_sessions_yield_distinct_presignatures() {
    let (n, threshold) = (5u16, 3u16);
    let prss = run_setup(n, threshold);
    let first = run_presign(n, &prss, 1, &[0x10; 32]);
    let second = run_presign(n, &prss, 1, &[0x11; 32]);
    assert_ne!(first[0].get(0).unwrap().r, second[0].get(0).unwrap().r);
}

#[test]
fn signing_rejects_a_mismatched_presignature() {
    let (n, threshold) = (5u16, 3u16);
    let prss = run_setup(n, threshold);
    let shares = run_keygen(n, &prss, &[0x20; 32]);
    let batch_a = run_presign(n, &prss, 1, &[0x21; 32]);
    let batch_b = run_presign(n, &prss, 1, &[0x22; 32]);

    // Party 1 uses a presignature from a different batch than everybody else.
    let mut presigs = take_presignature(&batch_a, 0);
    presigs[0] = batch_b[0].get(0).unwrap().clone();

    let parties = party_ids(n);
    let digest = digest_of(b"mismatched");
    let machines: Vec<_> = parties
        .iter()
        .zip(&shares)
        .zip(presigs)
        .map(|((&pid, share), presig)| {
            (
                pid,
                Ku24SignMachine::new(pid, parties.clone(), share, presig, digest)
                    .expect("sign machine"),
            )
        })
        .collect();
    assert!(
        Orchestrator::new(machines, 4).run().is_err(),
        "an r mismatch must abort signing"
    );
}

#[test]
fn keygen_rejects_an_inconsistent_broadcast() {
    // A party that broadcasts a wrong g^{x_j} is caught by the degree-t
    // consistency check across all n points.
    use tecdsa_ku24::keygen::Ku24KeygenMsg;

    let (n, threshold) = (5u16, 3u16);
    let prss = run_setup(n, threshold);
    let parties = party_ids(n);

    let mut machines: Vec<(PartyId, Ku24KeygenMachine<C>)> = parties
        .iter()
        .zip(&prss)
        .map(|(&pid, keys)| {
            (
                pid,
                Ku24KeygenMachine::new(pid, parties.clone(), keys, &[0x30; 32]).unwrap(),
            )
        })
        .collect();

    // Collect the honest broadcasts, then have party 5 lie to party 1.
    let mut broadcasts = Vec::new();
    for (pid, m) in &mut machines {
        let out = m.drain_outgoing();
        assert_eq!(out.len(), 1);
        broadcasts.push((*pid, out.into_iter().next().unwrap().msg));
    }
    let bogus = Ku24KeygenMsg::Round1(<C as TecdsaCurve>::point_to_bytes(
        &(ProjectivePoint::GENERATOR * Scalar::from(1234u64)).to_affine(),
    ));

    let mut err = None;
    for (from, msg) in &broadcasts {
        if *from == PartyId(1) {
            continue;
        }
        let msg = if *from == PartyId(5) {
            bogus.clone()
        } else {
            msg.clone()
        };
        if let Err(e) = machines[0].1.handle(*from, msg) {
            err = Some(e);
        }
    }
    assert!(
        err.is_some(),
        "an inconsistent g^{{x_j}} broadcast must be rejected"
    );
}

/// A party mounting the additive attack that `F_wmult` permits must be caught
/// before any presignature is released (Section 4 / Lemma 1).
#[test]
fn presign_detects_an_additive_attack_on_f_wmult() {
    use tecdsa_ku24::presign::Ku24PresignMsg;
    use tecdsa_protocol::Recipient;

    let (n, threshold) = (5u16, 3u16);
    let prss = run_setup(n, threshold);
    let parties = party_ids(n);
    let cheater = PartyId(n);

    let mut machines: Vec<(PartyId, Ku24PresignMachine<C>)> = parties
        .iter()
        .zip(&prss)
        .map(|(&pid, keys)| {
            (
                pid,
                Ku24PresignMachine::new_with_session(pid, parties.clone(), keys, 2, &[0x40; 32])
                    .unwrap(),
            )
        })
        .collect();

    let mut failed = false;
    'outer: for _ in 0..8 {
        if machines.iter().all(|(_, m)| m.is_done()) {
            break;
        }
        let mut pending = Vec::new();
        for (pid, m) in &mut machines {
            for out in m.drain_outgoing() {
                pending.push((*pid, out));
            }
        }
        if pending.is_empty() {
            break;
        }
        for (from, out) in pending {
            // The cheater shifts its first F_wmult share by 1, which shifts the
            // reconstructed product k_1 a_1 by a non-zero multiple of that.
            let msg = match (from == cheater, &out.msg) {
                (true, Ku24PresignMsg::Round1(e)) => {
                    let mut e = e.clone();
                    e[31] ^= 1;
                    Ku24PresignMsg::Round1(e)
                }
                _ => out.msg.clone(),
            };
            let targets: Vec<PartyId> = match out.to {
                Recipient::Broadcast => parties.iter().copied().filter(|p| *p != from).collect(),
                Recipient::Party(p) => vec![p],
            };
            for to in targets {
                let entry = machines.iter_mut().find(|(p, _)| *p == to).unwrap();
                if entry.1.handle(from, msg.clone()).is_err() {
                    failed = true;
                    break 'outer;
                }
            }
        }
    }

    assert!(
        failed,
        "the batch check must reject a tampered F_wmult broadcast"
    );
    assert!(
        machines.iter().all(|(_, m)| !m.is_done()),
        "no party may output a presignature after cheating is detected"
    );
}

#[test]
fn rejects_dishonest_majority_configurations() {
    fn setup_err(me: PartyId, parties: Vec<PartyId>, threshold: u16) -> Ku24Error {
        match Ku24SetupMachine::<C>::new(me, parties, threshold) {
            Ok(_) => panic!("expected the configuration to be rejected"),
            Err(e) => e,
        }
    }

    let parties = party_ids(5);
    // t = 3 needs n >= 7.
    let err = setup_err(PartyId(1), parties.clone(), 4);
    assert!(matches!(err, Ku24Error::InvalidThreshold { .. }), "{err}");

    // A party outside the set.
    let err = setup_err(PartyId(9), parties, 3);
    assert!(matches!(err, Ku24Error::NotAParticipant(_)), "{err}");

    // Committees beyond the PRSS blow-up limit are refused outright.
    let err = setup_err(PartyId(1), party_ids(24), 12);
    assert!(matches!(err, Ku24Error::TooManyParties { .. }), "{err}");
}

#[test]
fn protocol_metadata_is_consistent() {
    let meta = <Ku24Protocol<C> as Protocol>::METADATA;
    assert_eq!(meta.name, "KU24");
    assert_eq!(meta.presign_rounds, 4);
    assert_eq!(meta.online_sign_rounds, 1);
    assert_eq!(meta.keygen_rounds, 1);
    assert!(!meta.has_refresh);
    assert_eq!(
        meta.signing_rounds_impl,
        meta.presign_rounds + meta.online_sign_rounds
    );
}
