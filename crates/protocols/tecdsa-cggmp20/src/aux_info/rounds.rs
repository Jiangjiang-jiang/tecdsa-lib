use std::collections::BTreeMap;

use rand_core::CryptoRngCore;
use rug::{integer::Order, Integer};
use tecdsa_commit::HashCommitment;
use tecdsa_core::TecdsaError;
use tecdsa_paillier::{zk::paillier_zk::no_small_factor as pi_fac, DecryptionKey, EncryptionKey};
use tecdsa_pedersen_mod::{PedersenModParams, PiMod, PiPrm};
use tecdsa_protocol::{Outgoing, PartyId, Recipient, SessionConfig};

use super::msg::{AuxInfoMsg, MsgRound1, MsgRound2, MsgRound3};
use crate::{bridge::pedersen_to_aux, key_share::AuxInfo, security_level::Cggmp20SecurityParams};

#[derive(udigest::Digestable)]
struct AuxInfoProofTag {
    context: &'static str,
    prover: u16,
}

fn integer_to_bytes(val: &Integer) -> Vec<u8> {
    let n = val.significant_digits::<u8>();
    let mut bytes = vec![0u8; n];
    val.write_digits(&mut bytes, Order::Msf);
    bytes
}

fn commitment_data(msg: &MsgRound2) -> Vec<u8> {
    use sha2::{Digest, Sha256};

    let mut data = Vec::new();
    data.extend_from_slice(&msg.paillier_ek.n().to_bytes_msf());
    data.extend_from_slice(&integer_to_bytes(&msg.pedersen_params.n));
    data.extend_from_slice(&integer_to_bytes(&msg.pedersen_params.s));
    data.extend_from_slice(&integer_to_bytes(&msg.pedersen_params.t));
    let pi_prm_hash = {
        let mut h = Sha256::new();
        h.update(format!("{:?}", msg.pi_prm).as_bytes());
        h.finalize()
    };
    data.extend_from_slice(&pi_prm_hash);
    data.extend_from_slice(&msg.rho);
    data
}

#[derive(Default)]
pub(crate) enum AuxInfoRound<L: Cggmp20SecurityParams> {
    Round1(Round1State<L>),
    Round2(Round2State<L>),
    Round3(Round3State),
    Done(AuxInfo),
    #[default]
    Gone,
}

pub(crate) struct Round1State<L: Cggmp20SecurityParams> {
    pub my_id: PartyId,
    pub parties: Vec<PartyId>,
    pub party_index: u16,

    pub dk: DecryptionKey,
    pub ek: EncryptionKey,
    pub pedersen_params: PedersenModParams,
    pub pi_prm: PiPrm,
    pub rho: [u8; 32],
    pub decommit_nonce: [u8; 32],

    pub outgoing: Vec<Outgoing<AuxInfoMsg>>,

    pub round1_msgs: BTreeMap<PartyId, MsgRound1>,

    pub _level: std::marker::PhantomData<L>,
}

impl<L: Cggmp20SecurityParams> Round1State<L> {
    pub fn new(config: &SessionConfig, rng: &mut impl CryptoRngCore) -> Self {
        let my_id = config.local_party.id;
        let parties = config.parties.clone();
        let party_index = config.local_party.index;

        let p = tecdsa_paillier::backend::Integer::generate_safe_prime(rng, L::RSA_PRIME_BITS);
        let q = tecdsa_paillier::backend::Integer::generate_safe_prime(rng, L::RSA_PRIME_BITS);
        let dk = DecryptionKey::from_primes(p, q).expect("valid paillier key");
        let ek = dk.encryption_key().clone();

        let (pedersen_params, pedersen_secret) =
            PedersenModParams::generate(L::RSA_PRIME_BITS as u64, rng);

        let pi_prm = PiPrm::prove(&pedersen_params, &pedersen_secret, rng);

        let mut rho = [0u8; 32];
        rng.fill_bytes(&mut rho);

        let round2_preview = MsgRound2 {
            paillier_ek: ek.clone(),
            pedersen_params: pedersen_params.clone(),
            pi_prm: pi_prm.clone(),
            rho,
            decommit_nonce: [0u8; 32],
        };
        let commit_data = commitment_data(&round2_preview);
        let (hash_commitment, decommit_nonce) = HashCommitment::commit(&commit_data, rng);

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

    fn expected_count(&self) -> usize {
        self.parties.len() - 1
    }

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

    pub fn is_ready(&self) -> bool {
        self.round1_msgs.len() == self.expected_count()
    }

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

pub(crate) struct Round2State<L: Cggmp20SecurityParams> {
    pub my_id: PartyId,
    pub parties: Vec<PartyId>,
    pub party_index: u16,

    pub dk: DecryptionKey,
    pub ek: EncryptionKey,
    pub pedersen_params: PedersenModParams,
    pub rho: [u8; 32],

    pub round1_commitments: BTreeMap<PartyId, MsgRound1>,

    pub outgoing: Vec<Outgoing<AuxInfoMsg>>,

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

    pub fn advance(self) -> tecdsa_core::Result<Round3State> {
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

        for (&pid, round2) in &self.round2_msgs {
            if !round2.pi_prm.verify(&round2.pedersen_params) {
                return Err(TecdsaError::InvalidProof(format!(
                    "party {pid} PiPrm proof verification failed"
                )));
            }
        }

        let mut combined_rho = self.rho;
        for round2 in self.round2_msgs.values() {
            for (i, b) in round2.rho.iter().enumerate() {
                combined_rho[i] ^= b;
            }
        }

        let mut rng = tecdsa_core::Csprng::new();
        let paillier_n = Integer::from_digits(&self.dk.n().to_bytes_msf(), Order::Msf);
        let paillier_p = Integer::from_digits(&self.dk.p().to_bytes_msf(), Order::Msf);
        let paillier_q = Integer::from_digits(&self.dk.q().to_bytes_msf(), Order::Msf);
        let pi_mod_proof = PiMod::prove_modulus(&paillier_n, &paillier_p, &paillier_q, &mut rng)
            .ok_or_else(|| TecdsaError::Other("pi_mod proof generation failed".into()))?;

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

pub(crate) struct Round3State {
    pub my_id: PartyId,
    pub parties: Vec<PartyId>,
    pub party_index: u16,

    pub dk: DecryptionKey,
    pub ek: EncryptionKey,
    pub pedersen_params: PedersenModParams,
    #[allow(dead_code)]
    pub combined_rho: [u8; 32],

    pub ell: usize,
    pub epsilon: usize,

    pub round2_msgs: BTreeMap<PartyId, MsgRound2>,

    pub outgoing: Vec<Outgoing<AuxInfoMsg>>,

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

    pub fn finish(self) -> tecdsa_core::Result<AuxInfo> {
        let mut rng = tecdsa_core::Csprng::new();

        let own_aux = pedersen_to_aux(&self.pedersen_params);
        let security_params = pi_fac::SecurityParams {
            l: self.ell,
            epsilon: self.epsilon,
        };

        for (&pid, round3) in &self.round3_msgs {
            let round2 = self
                .round2_msgs
                .get(&pid)
                .ok_or_else(|| TecdsaError::Other(format!("missing round2 from {pid}")))?;

            let peer_n_rug =
                Integer::from_digits(&round2.paillier_ek.n().to_bytes_msf(), Order::Msf);
            if !round3.pi_mod.verify_modulus(&peer_n_rug, &mut rng) {
                return Err(TecdsaError::InvalidProof(format!(
                    "party {pid} pi_mod verification failed"
                )));
            }

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

        let party_index = self.party_index - 1;

        Ok(AuxInfo {
            party_index,
            dk: self.dk,
            paillier_eks,
            pedersen_params: pedersen_params_vec,
        })
    }
}
