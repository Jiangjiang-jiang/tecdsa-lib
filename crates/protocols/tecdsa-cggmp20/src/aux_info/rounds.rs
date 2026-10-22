// SPDX-License-Identifier: MIT OR Apache-2.0
//! Round state structs and transition logic for CGGMP20 auxiliary-info generation.

use std::collections::BTreeMap;

use rand_core::CryptoRngCore;
use rug::Integer;
use tecdsa_commit::HashCommitment;
use tecdsa_core::TecdsaError;
use tecdsa_paillier::{
    zk::{pi_fac, pi_mod},
    BigIntExt, DecryptionKey, EncryptionKey,
};
use tecdsa_pedersen_mod::{PedersenModParams, PiPrm};
use tecdsa_protocol::{Outgoing, PartyId, Recipient, SessionConfig};

use super::msg::{AuxInfoMsg, MsgRound1, MsgRound2, MsgRound3, PI_MOD_REPS};
use crate::{bridge::pedersen_to_aux, key_share::AuxInfo, security_level::Cggmp20SecurityParams};

/// Fiat-Shamir domain separation tag for aux-info ZK proofs.
#[derive(udigest::Digestable)]
struct AuxInfoProofTag {
    context: &'static str,
    prover: u16,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Serialise the commitment payload: ek || pedersen_params || pi_prm || rho.
///
/// We concatenate deterministic byte representations of the public data.
/// The PiPrm proof is hashed via SHA-256 of its bincode encoding to avoid
/// needing serde_json.
fn commitment_data(msg: &MsgRound2) -> Vec<u8> {
    use sha2::{Digest, Sha256};

    let mut data = Vec::new();
    // EncryptionKey → serialise N as big-endian bytes
    data.extend_from_slice(&msg.paillier_ek.n().to_bytes_msf());
    // PedersenModParams → serialise n, s, t
    data.extend_from_slice(&msg.pedersen_params.n.to_bytes_msf());
    data.extend_from_slice(&msg.pedersen_params.s.to_bytes_msf());
    data.extend_from_slice(&msg.pedersen_params.t.to_bytes_msf());
    // PiPrm → hash the debug representation as a deterministic fingerprint.
    // Both prover and verifier call this function with the same data, so
    // determinism is all that matters.
    let pi_prm_hash = {
        let mut h = Sha256::new();
        h.update(format!("{:?}", msg.pi_prm).as_bytes());
        h.finalize()
    };
    data.extend_from_slice(&pi_prm_hash);
    data.extend_from_slice(&msg.rho);
    data
}

// ---------------------------------------------------------------------------
// Round enum
// ---------------------------------------------------------------------------

#[derive(Default)]
pub(crate) enum AuxInfoRound<L: Cggmp20SecurityParams> {
    Round1(Round1State<L>),
    Round2(Round2State<L>),
    Round3(Round3State),
    Done(AuxInfo),
    /// Sentinel so we can `std::mem::take` without leaving an invalid state.
    #[default]
    Gone,
}

// ---------------------------------------------------------------------------
// Round 1 state
// ---------------------------------------------------------------------------

pub(crate) struct Round1State<L: Cggmp20SecurityParams> {
    // Configuration
    pub my_id: PartyId,
    pub parties: Vec<PartyId>,
    pub party_index: u16,

    // Own secrets generated at construction
    pub dk: DecryptionKey,
    pub ek: EncryptionKey,
    pub pedersen_params: PedersenModParams,
    pub pi_prm: PiPrm,
    pub rho: [u8; 32],
    pub decommit_nonce: [u8; 32],

    // Outgoing messages queued at construction
    pub outgoing: Vec<Outgoing<AuxInfoMsg>>,

    // Received messages
    pub round1_msgs: BTreeMap<PartyId, MsgRound1>,

    pub _level: std::marker::PhantomData<L>,
}

impl<L: Cggmp20SecurityParams> Round1State<L> {
    /// Create the initial Round1 state: generate secrets and queue Round1 broadcast.
    pub fn new(config: &SessionConfig, rng: &mut impl CryptoRngCore) -> Self {
        let my_id = config.local_party.id;
        let parties = config.parties.clone();
        let party_index = config.local_party.index;

        // 1+2. Generate the Paillier key pair and the ring-Pedersen parameters.
        // These are four independent safe-prime searches, by far the dominant
        // cost of the whole protocol, so they are all started concurrently.
        // Each branch gets its own seeded stream so the result stays a
        // deterministic function of `rng`.
        let mut paillier_seed = [0u8; 32];
        let mut pedersen_seed = [0u8; 32];
        rng.fill_bytes(&mut paillier_seed);
        rng.fill_bytes(&mut pedersen_seed);
        let ((p, q), (pedersen_params, pedersen_secret)) = tecdsa_bigint::par::join(
            || {
                use rand::SeedableRng;
                let mut r = rand::rngs::StdRng::from_seed(paillier_seed);
                tecdsa_bigint::par::gen_two_primes(&mut r, L::RSA_PRIME_BITS)
            },
            || {
                use rand::SeedableRng;
                let mut r = rand::rngs::StdRng::from_seed(pedersen_seed);
                PedersenModParams::generate(u64::from(L::RSA_PRIME_BITS), &mut r)
            },
        );
        let dk = DecryptionKey::from_primes(p, q).expect("valid paillier key");
        let ek = dk.encryption_key().clone();

        // 3. Generate PiPrm proof
        let pi_prm = PiPrm::prove(&pedersen_params, &pedersen_secret, rng);

        // 4. Sample rho (32 random bytes)
        let mut rho = [0u8; 32];
        rng.fill_bytes(&mut rho);

        // 5. Compute hash commitment over (ek || pedersen_params || pi_prm || rho)
        let round2_preview = MsgRound2 {
            paillier_ek: ek.clone(),
            pedersen_params: pedersen_params.clone(),
            pi_prm: pi_prm.clone(),
            rho,
            decommit_nonce: [0u8; 32], // placeholder, not included in commitment
        };
        let commit_data = commitment_data(&round2_preview);
        let (hash_commitment, decommit_nonce) = HashCommitment::commit(&commit_data, rng);

        // 6. Queue broadcast of MsgRound1
        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: AuxInfoMsg::Round1(MsgRound1 {
                commitment: hash_commitment,
            }),
        }];

        Self {
            my_id,
            parties,
            party_index,
            dk,
            ek,
            pedersen_params,
            pi_prm,
            rho,
            decommit_nonce,
            outgoing,
            round1_msgs: BTreeMap::new(),
            _level: std::marker::PhantomData,
        }
    }

    /// Number of messages we expect to receive (from all other parties).
    fn expected_count(&self) -> usize {
        self.parties.len() - 1
    }

    /// Handle a Round1 message from another party.
    pub fn handle(&mut self, from: PartyId, msg: MsgRound1) -> tecdsa_core::Result<()> {
        if from == self.my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }
        if !self.parties.contains(&from) {
            return Err(TecdsaError::UnknownSender(from.0));
        }
        if self.round1_msgs.contains_key(&from) {
            return Err(TecdsaError::DuplicateMessage(from.0));
        }
        self.round1_msgs.insert(from, msg);
        Ok(())
    }

    /// Check if all expected Round1 messages have been received.
    pub fn is_ready(&self) -> bool {
        self.round1_msgs.len() == self.expected_count()
    }

    /// Transition to Round2: queue decommitment broadcast.
    pub fn advance(self) -> Round2State<L> {
        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: AuxInfoMsg::Round2(MsgRound2 {
                paillier_ek: self.ek.clone(),
                pedersen_params: self.pedersen_params.clone(),
                pi_prm: self.pi_prm.clone(),
                rho: self.rho,
                decommit_nonce: self.decommit_nonce,
            }),
        }];

        Round2State {
            my_id: self.my_id,
            parties: self.parties,
            party_index: self.party_index,
            dk: self.dk,
            ek: self.ek,
            pedersen_params: self.pedersen_params,
            rho: self.rho,
            round1_commitments: self.round1_msgs,
            outgoing,
            round2_msgs: BTreeMap::new(),
            _level: std::marker::PhantomData,
        }
    }
}

// ---------------------------------------------------------------------------
// Round 2 state
// ---------------------------------------------------------------------------

pub(crate) struct Round2State<L: Cggmp20SecurityParams> {
    // Config
    pub my_id: PartyId,
    pub parties: Vec<PartyId>,
    pub party_index: u16,

    // Own secrets
    pub dk: DecryptionKey,
    pub ek: EncryptionKey,
    pub pedersen_params: PedersenModParams,
    pub rho: [u8; 32],

    // Round 1 data
    pub round1_commitments: BTreeMap<PartyId, MsgRound1>,

    // Outgoing
    pub outgoing: Vec<Outgoing<AuxInfoMsg>>,

    // Received
    pub round2_msgs: BTreeMap<PartyId, MsgRound2>,

    pub _level: std::marker::PhantomData<L>,
}

impl<L: Cggmp20SecurityParams> Round2State<L> {
    fn expected_count(&self) -> usize {
        self.parties.len() - 1
    }

    pub fn handle(&mut self, from: PartyId, msg: MsgRound2) -> tecdsa_core::Result<()> {
        if from == self.my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }
        if !self.parties.contains(&from) {
            return Err(TecdsaError::UnknownSender(from.0));
        }
        if self.round2_msgs.contains_key(&from) {
            return Err(TecdsaError::DuplicateMessage(from.0));
        }
        self.round2_msgs.insert(from, msg);
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.round2_msgs.len() == self.expected_count()
    }

    /// Verify all hash commitments and PiPrm proofs, then transition to Round 3.
    pub fn advance(self) -> tecdsa_core::Result<Round3State> {
        // 1. Verify hash commitments against decommitted data.
        for (&pid, round2) in &self.round2_msgs {
            let round1 = self
                .round1_commitments
                .get(&pid)
                .ok_or_else(|| TecdsaError::Other(format!("missing round1 from {pid}")))?;

            let commit_data = commitment_data(round2);
            if !round1
                .commitment
                .verify(&commit_data, &round2.decommit_nonce)
            {
                return Err(TecdsaError::InvalidCommitment(format!(
                    "party {pid} commitment verification failed"
                )));
            }
        }

        // 2. Verify all PiPrm proofs. One peer's proof does not depend on any
        //    other's, and each is m = 80 independent exponentiations, so this
        //    parallelises both across peers and (inside `verify`) within a peer.
        let peers: Vec<PartyId> = self.round2_msgs.keys().copied().collect();
        tecdsa_bigint::par::try_for_each(&peers, |&pid| {
            let round2 = &self.round2_msgs[&pid];
            if round2.pi_prm.verify(&round2.pedersen_params) {
                Ok(())
            } else {
                Err(TecdsaError::InvalidProof(format!(
                    "party {pid} PiPrm proof verification failed"
                )))
            }
        })?;

        // 3. Compute combined rho = XOR(all rhos).
        let mut combined_rho = self.rho;
        for round2 in self.round2_msgs.values() {
            for (i, b) in round2.rho.iter().enumerate() {
                combined_rho[i] ^= b;
            }
        }

        // 4. Generate π_mod proof (same for all peers — only depends on own N).
        let pi_mod_tag = AuxInfoProofTag {
            context: "pi_mod",
            prover: self.my_id.0,
        };
        let pi_mod_proof = pi_mod::non_interactive::prove::<PI_MOD_REPS, sha2::Sha256>(
            &pi_mod_tag,
            pi_mod::Data { n: self.dk.n() },
            pi_mod::PrivateData {
                p: self.dk.p(),
                q: self.dk.q(),
            },
            &mut tecdsa_core::Csprng::new(),
        )
        .map_err(|e| TecdsaError::Other(format!("pi_mod proof generation failed: {e}")))?;

        // 5. Generate per-peer π_fac proofs and queue P2P MsgRound3 messages.
        let own_n = self.dk.n().clone();
        // `sqrt_ref` panics on a negative operand (unlike the old newtype's
        // `Option`-returning version); `own_n` is this party's own freshly
        // generated Paillier modulus (always positive), but we still guard
        // explicitly so the predicate matches the pre-refactor behaviour
        // exactly rather than relying on that invariant.
        let n_root = if own_n.cmp0() == std::cmp::Ordering::Less {
            None
        } else {
            Some(Integer::from(own_n.sqrt_ref()))
        }
        .expect("sqrt of Paillier modulus must succeed");

        let pi_fac_tag = AuxInfoProofTag {
            context: "pi_fac",
            prover: self.my_id.0,
        };
        let security_params = pi_fac::SecurityParams {
            l: L::ELL,
            epsilon: L::EPSILON,
        };

        // One π_fac proof per peer, each bound to that peer's Ring-Pedersen
        // parameters, so they are independent of one another.
        let outgoing = tecdsa_bigint::par::try_map(&peers, |&peer_pid| {
            let peer_round2 = self
                .round2_msgs
                .get(&peer_pid)
                .ok_or_else(|| TecdsaError::Other(format!("missing round2 from {peer_pid}")))?;
            let peer_aux = pedersen_to_aux(&peer_round2.pedersen_params);

            let pi_fac_proof = pi_fac::non_interactive::prove::<sha2::Sha256>(
                &pi_fac_tag,
                &peer_aux,
                pi_fac::Data {
                    n: &own_n,
                    n_root: &n_root,
                },
                pi_fac::PrivateData {
                    p: self.dk.p(),
                    q: self.dk.q(),
                },
                &security_params,
                &mut tecdsa_core::Csprng::new(),
            )
            .map_err(|e| TecdsaError::Other(format!("pi_fac proof generation failed: {e}")))?;

            Ok(Outgoing {
                to: Recipient::Party(peer_pid),
                msg: AuxInfoMsg::Round3(MsgRound3 {
                    pi_mod: pi_mod_proof.clone(),
                    pi_fac: pi_fac_proof,
                }),
            })
        })?;

        Ok(Round3State {
            my_id: self.my_id,
            parties: self.parties,
            party_index: self.party_index,
            dk: self.dk,
            ek: self.ek,
            pedersen_params: self.pedersen_params,
            combined_rho,
            round2_msgs: self.round2_msgs,
            outgoing,
            round3_msgs: BTreeMap::new(),
            ell: L::ELL,
            epsilon: L::EPSILON,
        })
    }
}

// ---------------------------------------------------------------------------
// Round 3 state
// ---------------------------------------------------------------------------

pub(crate) struct Round3State {
    // Config
    pub my_id: PartyId,
    pub parties: Vec<PartyId>,
    pub party_index: u16,

    // Own data
    pub dk: DecryptionKey,
    pub ek: EncryptionKey,
    pub pedersen_params: PedersenModParams,
    #[allow(dead_code)]
    pub combined_rho: [u8; 32],

    // Security parameters for π_fac verification
    pub ell: usize,
    pub epsilon: usize,

    // Round 2 data (needed for collecting all parties' ek/params)
    pub round2_msgs: BTreeMap<PartyId, MsgRound2>,

    // Outgoing
    pub outgoing: Vec<Outgoing<AuxInfoMsg>>,

    // Received
    pub round3_msgs: BTreeMap<PartyId, MsgRound3>,
}

impl Round3State {
    fn expected_count(&self) -> usize {
        self.parties.len() - 1
    }

    pub fn handle(&mut self, from: PartyId, msg: MsgRound3) -> tecdsa_core::Result<()> {
        if from == self.my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }
        if !self.parties.contains(&from) {
            return Err(TecdsaError::UnknownSender(from.0));
        }
        if self.round3_msgs.contains_key(&from) {
            return Err(TecdsaError::DuplicateMessage(from.0));
        }
        self.round3_msgs.insert(from, msg);
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.round3_msgs.len() == self.expected_count()
    }

    /// Verify all π_mod and π_fac proofs, then produce the final `AuxInfo`.
    pub fn finish(self) -> tecdsa_core::Result<AuxInfo> {
        // Use own ring-Pedersen params as verifier for π_fac.
        let own_aux = pedersen_to_aux(&self.pedersen_params);
        let security_params = pi_fac::SecurityParams {
            l: self.ell,
            epsilon: self.epsilon,
        };

        // 1. Verify all π_mod and π_fac proofs. Independent across peers, and
        //    π_mod is itself 80 independent point checks.
        let peers: Vec<PartyId> = self.round3_msgs.keys().copied().collect();
        tecdsa_bigint::par::try_for_each(&peers, |&pid| {
            let round3 = &self.round3_msgs[&pid];
            let round2 = self
                .round2_msgs
                .get(&pid)
                .ok_or_else(|| TecdsaError::Other(format!("missing round2 from {pid}")))?;

            // Verify π_mod (Paillier-Blum modulus proof). The tag binds the
            // proof to the prover's party id, so a peer cannot replay another
            // party's proof for a modulus it does not know the factors of.
            let pi_mod_tag = AuxInfoProofTag {
                context: "pi_mod",
                prover: pid.0,
            };
            pi_mod::non_interactive::verify::<PI_MOD_REPS, sha2::Sha256>(
                &pi_mod_tag,
                pi_mod::Data {
                    n: round2.paillier_ek.n(),
                },
                &round3.pi_mod,
                &mut tecdsa_core::Csprng::new(),
            )
            .map_err(|e| {
                TecdsaError::InvalidProof(format!("party {pid} pi_mod verification failed: {e}"))
            })?;

            // Verify π_fac (no-small-factor proof).
            let pi_fac_tag = AuxInfoProofTag {
                context: "pi_fac",
                prover: pid.0,
            };
            let peer_n = round2.paillier_ek.n();
            // `peer_n` comes from a wire message sent by another (possibly
            // malicious) party, so unlike the `own_n` case above this really
            // is attacker-controlled. Old behaviour: the newtype's
            // `sqrt_ref` returned `None` for negative input, which the
            // `.expect(...)` below then turned into a panic — i.e. a
            // negative peer modulus was already fatal, just via `Option`
            // rather than a native rug panic. We reproduce that `None` path
            // explicitly so the externally observable behaviour (panic with
            // this message on a negative `peer_n`) is unchanged.
            let peer_n_root = if peer_n.cmp0() == std::cmp::Ordering::Less {
                None
            } else {
                Some(Integer::from(peer_n.sqrt_ref()))
            }
            .expect("sqrt of peer Paillier modulus must succeed");

            pi_fac::non_interactive::verify::<sha2::Sha256>(
                &pi_fac_tag,
                &own_aux,
                pi_fac::Data {
                    n: peer_n,
                    n_root: &peer_n_root,
                },
                &security_params,
                &round3.pi_fac,
            )
            .map_err(|e| TecdsaError::InvalidProof(format!("party {pid} pi_fac: {e}")))?;
            Ok(())
        })?;

        // 2. Collect all parties' EncryptionKeys and PedersenModParams, ordered by party id.
        let n = self.parties.len();
        let mut paillier_eks = Vec::with_capacity(n);
        let mut pedersen_params_vec = Vec::with_capacity(n);

        for &pid in &self.parties {
            if pid == self.my_id {
                paillier_eks.push(self.ek.clone());
                pedersen_params_vec.push(self.pedersen_params.clone());
            } else {
                let round2 = self
                    .round2_msgs
                    .get(&pid)
                    .ok_or_else(|| TecdsaError::Other(format!("missing round2 from {pid}")))?;
                paillier_eks.push(round2.paillier_ek.clone());
                pedersen_params_vec.push(round2.pedersen_params.clone());
            }
        }

        // party_index is 0-based in AuxInfo.
        let party_index = self.party_index - 1;

        Ok(AuxInfo {
            party_index,
            dk: self.dk,
            paillier_eks,
            pedersen_params: pedersen_params_vec,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A π_mod proof is bound to the prover's party id, so party `j` cannot
    /// republish party `i`'s modulus and reuse `i`'s proof. Before the proof
    /// was migrated onto `tecdsa_paillier::zk::pi_mod` its challenges were
    /// derived from `(N, w)` alone, making exactly this replay possible.
    #[test]
    fn pi_mod_proof_is_bound_to_prover_id() {
        let mut rng = tecdsa_core::Csprng::new();
        let p = Integer::generate_safe_prime(&mut rng, 256);
        let q = Integer::generate_safe_prime(&mut rng, 256);
        let dk = DecryptionKey::from_primes(p, q).expect("valid paillier key");

        let tag_of = |prover| AuxInfoProofTag {
            context: "pi_mod",
            prover,
        };
        let data = || pi_mod::Data { n: dk.n() };

        let proof = pi_mod::non_interactive::prove::<PI_MOD_REPS, sha2::Sha256>(
            &tag_of(1),
            data(),
            pi_mod::PrivateData {
                p: dk.p(),
                q: dk.q(),
            },
            &mut rng,
        )
        .expect("prove must succeed for a valid Blum modulus");

        assert!(
            pi_mod::non_interactive::verify::<PI_MOD_REPS, sha2::Sha256>(
                &tag_of(1),
                data(),
                &proof,
                &mut rng,
            )
            .is_ok(),
            "honest proof must verify under the prover's own tag"
        );

        assert!(
            pi_mod::non_interactive::verify::<PI_MOD_REPS, sha2::Sha256>(
                &tag_of(2),
                data(),
                &proof,
                &mut rng,
            )
            .is_err(),
            "proof must not verify under a different prover id"
        );
    }
}
