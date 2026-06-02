// SPDX-License-Identifier: MIT OR Apache-2.0
//! Round state structs and transition logic for CGGMP20 auxiliary-info generation.

use std::collections::BTreeMap;

use rand_core::CryptoRngCore;
use tecdsa_commit::HashCommitment;
use tecdsa_core::TecdsaError;
use tecdsa_paillier::{DecryptionKey, EncryptionKey};
use tecdsa_pedersen_mod::{PedersenModParams, PiPrm};
use tecdsa_protocol::{Outgoing, PartyId, Recipient, SessionConfig};

use tecdsa_bigint::DynInt;
use tecdsa_paillier::zk::paillier_zk::no_small_factor as pi_fac;
use tecdsa_pedersen_mod::PiMod;

use crate::bridge::pedersen_to_aux;
use crate::key_share::AuxInfo;
use crate::security_level::Cggmp20SecurityParams;

use super::msg::{AuxInfoMsg, MsgRound1, MsgRound2, MsgRound3};

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
    data.extend_from_slice(&msg.pedersen_params.n.to_bytes_be());
    data.extend_from_slice(&msg.pedersen_params.s.to_bytes_be());
    data.extend_from_slice(&msg.pedersen_params.t.to_bytes_be());
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

        // 1. Generate Paillier key pair with primes of the configured size
        let p = tecdsa_paillier::backend::Integer::generate_safe_prime(rng, L::RSA_PRIME_BITS);
        let q = tecdsa_paillier::backend::Integer::generate_safe_prime(rng, L::RSA_PRIME_BITS);
        let dk = DecryptionKey::from_primes(p, q).expect("valid paillier key");
        let ek = dk.encryption_key().clone();

        // 2. Generate ring-Pedersen parameters
        let (pedersen_params, pedersen_secret) =
            PedersenModParams::generate(L::RSA_PRIME_BITS as u64, rng);

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

        // 2. Verify all PiPrm proofs.
        for (&pid, round2) in &self.round2_msgs {
            if !round2.pi_prm.verify(&round2.pedersen_params) {
                return Err(TecdsaError::InvalidProof(format!(
                    "party {pid} PiPrm proof verification failed"
                )));
            }
        }

        // 3. Compute combined rho = XOR(all rhos).
        let mut combined_rho = self.rho;
        for round2 in self.round2_msgs.values() {
            for (i, b) in round2.rho.iter().enumerate() {
                combined_rho[i] ^= b;
            }
        }

        // 4. Generate π_mod proof (same for all peers — only depends on own N).
        let mut rng = tecdsa_core::Csprng::new();
        let paillier_n = DynInt::from_bytes_be(&self.dk.n().to_bytes_msf());
        let paillier_p = DynInt::from_bytes_be(&self.dk.p().to_bytes_msf());
        let paillier_q = DynInt::from_bytes_be(&self.dk.q().to_bytes_msf());
        let pi_mod_proof = PiMod::prove_modulus(&paillier_n, &paillier_p, &paillier_q, &mut rng)
            .ok_or_else(|| TecdsaError::Other("pi_mod proof generation failed".into()))?;

        // 5. Generate per-peer π_fac proofs and queue P2P MsgRound3 messages.
        let own_n = self.dk.n().clone();
        let n_root = own_n
            .sqrt_ref()
            .expect("sqrt of Paillier modulus must succeed");

        let pi_fac_tag = AuxInfoProofTag {
            context: "pi_fac",
            prover: self.my_id.0,
        };
        let security_params = pi_fac::SecurityParams {
            l: L::ELL,
            epsilon: L::EPSILON,
        };

        let mut outgoing = Vec::new();
        for &peer_pid in &self.parties {
            if peer_pid == self.my_id {
                continue;
            }
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
                &mut rng,
            )
            .map_err(|e| TecdsaError::Other(format!("pi_fac proof generation failed: {e}")))?;

            outgoing.push(Outgoing {
                to: Recipient::Party(peer_pid),
                msg: AuxInfoMsg::Round3(MsgRound3 {
                    pi_mod: pi_mod_proof.clone(),
                    pi_fac: pi_fac_proof,
                }),
            });
        }

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
        let mut rng = tecdsa_core::Csprng::new();

        // Use own ring-Pedersen params as verifier for π_fac.
        let own_aux = pedersen_to_aux(&self.pedersen_params);
        let security_params = pi_fac::SecurityParams {
            l: self.ell,
            epsilon: self.epsilon,
        };

        // 1. Verify all π_mod and π_fac proofs.
        for (&pid, round3) in &self.round3_msgs {
            let round2 = self
                .round2_msgs
                .get(&pid)
                .ok_or_else(|| TecdsaError::Other(format!("missing round2 from {pid}")))?;

            // Verify π_mod (Paillier-Blum modulus proof).
            let peer_n_dyn = DynInt::from_bytes_be(&round2.paillier_ek.n().to_bytes_msf());
            if !round3.pi_mod.verify_modulus(&peer_n_dyn, &mut rng) {
                return Err(TecdsaError::InvalidProof(format!(
                    "party {pid} pi_mod verification failed"
                )));
            }

            // Verify π_fac (no-small-factor proof).
            let pi_fac_tag = AuxInfoProofTag {
                context: "pi_fac",
                prover: pid.0,
            };
            let peer_n = round2.paillier_ek.n();
            let peer_n_root = peer_n
                .sqrt_ref()
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
        }

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
