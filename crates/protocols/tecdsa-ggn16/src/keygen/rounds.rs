#![allow(non_snake_case)]

use std::{collections::BTreeMap, marker::PhantomData};

use elliptic_curve::{
    group::{Group, GroupEncoding},
    sec1::ModulusSize,
    FieldBytes, FieldBytesSize, PrimeField,
};
use rand_core::CryptoRngCore;
use tecdsa_commit::HashCommitment;
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_paillier::{
    backend::Integer,
    threshold::{DecryptionShare, ThresholdSetup},
    zk::pdl_slack::{PdlSlackProof, PdlSlackStatement, PdlSlackWitness},
};
use tecdsa_protocol::{Outgoing, PartyId, Recipient};

use super::msg::{Ggn16KeygenMsg, KeygenRound1Msg, KeygenRound2Msg};
use crate::key_share::Ggn16KeyShare;

pub(crate) struct KeygenConfig {
    pub my_id: PartyId,
    pub all_parties: Vec<PartyId>,
    pub threshold: u16,
    pub total: u16,
    pub threshold_setup: ThresholdSetup,
    pub decryption_share: DecryptionShare,
    pub h1: Integer,
    pub h2: Integer,
    pub N_tilde: Integer,
}

#[derive(Default)]
pub(crate) enum KeygenRound<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    Round1(Round1State<C>),
    Round2(Round2State<C>),
    Done(Ggn16KeyShare<C>),
    #[default]
    Poisoned,
}

pub(crate) struct Round1State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub my_id: PartyId,
    pub parties: Vec<PartyId>,
    pub threshold: u16,
    pub total: u16,

    pub threshold_setup: ThresholdSetup,
    pub decryption_share: DecryptionShare,

    pub h1: Integer,
    pub h2: Integer,
    pub N_tilde: Integer,

    pub x_i: C::Scalar,
    pub y_i: C::ProjectivePoint,
    pub y_i_bytes: Vec<u8>,
    pub decommit_nonce: [u8; 32],
    pub alpha_i: Integer,
    pub alpha_i_nonce: Integer,

    pub outgoing: Vec<Outgoing<Ggn16KeygenMsg<C>>>,

    pub round1_msgs: BTreeMap<PartyId, KeygenRound1Msg>,
}

impl<C: TecdsaCurve> Round1State<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    pub fn new(config: KeygenConfig, rng: &mut impl CryptoRngCore) -> Self {
        let my_id = config.my_id;
        let parties = config.all_parties;
        let threshold = config.threshold;
        let total = config.total;

        let x_i = C::random_scalar(rng);
        let y_i = C::generator() * x_i;

        let y_i_bytes: Vec<u8> = y_i.to_bytes().as_ref().to_vec();

        let (hash_commitment, decommit_nonce) = HashCommitment::commit(&y_i_bytes, rng);

        let x_i_repr = x_i.to_repr();
        let x_i_integer = Integer::from_bytes_msf(x_i_repr.as_ref());
        let (alpha_i, alpha_i_nonce) = config
            .threshold_setup
            .ek
            .encrypt_with_random(rng, &x_i_integer)
            .expect("Paillier encryption must succeed for valid plaintext");

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Ggn16KeygenMsg::Round1(KeygenRound1Msg {
                commitment: hash_commitment,
            }),
        }];

        Self {
            my_id,
            parties,
            threshold,
            total,
            threshold_setup: config.threshold_setup,
            decryption_share: config.decryption_share,
            h1: config.h1,
            h2: config.h2,
            N_tilde: config.N_tilde,
            x_i,
            y_i,
            y_i_bytes,
            decommit_nonce,
            alpha_i,
            alpha_i_nonce,
            outgoing,
            round1_msgs: BTreeMap::new(),
        }
    }

    fn expected_count(&self) -> usize {
        self.parties.len() - 1
    }

    pub fn handle(&mut self, from: PartyId, msg: KeygenRound1Msg) -> tecdsa_core::Result<()> {
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

    pub fn advance(mut self, rng: &mut impl CryptoRngCore) -> Round2State<C> {
        let ek = &self.threshold_setup.ek;
        let statement = PdlSlackStatement::<C> {
            ciphertext: self.alpha_i.clone(),
            ek_n: ek.n().clone(),
            ek_nn: ek.nn().clone(),
            Q: self.y_i,
            G: C::generator(),
            h1: self.h1.clone(),
            h2: self.h2.clone(),
            N_tilde: self.N_tilde.clone(),
        };

        let x_i_repr = self.x_i.to_repr();
        let x_i_integer = Integer::from_bytes_msf(x_i_repr.as_ref());
        let witness = PdlSlackWitness {
            x: x_i_integer,
            r: self.alpha_i_nonce.clone(),
        };

        let proof = PdlSlackProof::prove(&witness, &statement, rng);
        let proof_bytes = proof.to_bytes();

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Ggn16KeygenMsg::Round2(KeygenRound2Msg {
                y_i_bytes: self.y_i_bytes.clone(),
                nonce: self.decommit_nonce,
                alpha_i: self.alpha_i.clone(),
                alpha_i_nonce: self.alpha_i_nonce.clone(),
                proof: proof_bytes,
                _marker: PhantomData,
            }),
        }];

        self.alpha_i_nonce = Integer::from(0u32);

        Round2State {
            my_id: self.my_id,
            parties: self.parties,
            threshold: self.threshold,
            total: self.total,
            threshold_setup: self.threshold_setup,
            decryption_share: self.decryption_share,
            h1: self.h1,
            h2: self.h2,
            N_tilde: self.N_tilde,
            x_i: self.x_i,
            y_i: self.y_i,
            alpha_i: self.alpha_i,
            round1_commitments: self.round1_msgs,
            outgoing,
            round2_msgs: BTreeMap::new(),
        }
    }
}

pub(crate) struct Round2State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub my_id: PartyId,
    pub parties: Vec<PartyId>,
    pub threshold: u16,
    pub total: u16,

    pub threshold_setup: ThresholdSetup,
    pub decryption_share: DecryptionShare,

    pub h1: Integer,
    pub h2: Integer,
    pub N_tilde: Integer,

    pub x_i: C::Scalar,
    pub y_i: C::ProjectivePoint,
    pub alpha_i: Integer,

    pub round1_commitments: BTreeMap<PartyId, KeygenRound1Msg>,

    pub outgoing: Vec<Outgoing<Ggn16KeygenMsg<C>>>,

    pub round2_msgs: BTreeMap<PartyId, KeygenRound2Msg<C>>,
}

impl<C: TecdsaCurve> Round2State<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    fn expected_count(&self) -> usize {
        self.parties.len() - 1
    }

    pub fn handle(&mut self, from: PartyId, msg: KeygenRound2Msg<C>) -> tecdsa_core::Result<()> {
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

    pub fn finish(self) -> tecdsa_core::Result<Ggn16KeyShare<C>> {
        let ek = &self.threshold_setup.ek;

        let mut public_shares: Vec<C::ProjectivePoint> = Vec::with_capacity(self.total as usize);
        let mut all_alpha: Vec<Integer> = Vec::with_capacity(self.total as usize);

        for pid_val in 1..=self.total {
            let pid = PartyId(pid_val);
            if pid == self.my_id {
                public_shares.push(self.y_i);
                all_alpha.push(self.alpha_i.clone());
            } else {
                let r2 = self.round2_msgs.get(&pid).ok_or_else(|| {
                    TecdsaError::Other(format!("missing round2 message from party {pid}"))
                })?;

                let r1 = self.round1_commitments.get(&pid).ok_or_else(|| {
                    TecdsaError::Other(format!("missing round1 commitment from party {pid}"))
                })?;
                if !r1.commitment.verify(&r2.y_i_bytes, &r2.nonce) {
                    return Err(TecdsaError::InvalidCommitment(format!(
                        "party {pid} commitment verification failed"
                    )));
                }

                let y_j = deserialize_point::<C>(&r2.y_i_bytes).map_err(|_| {
                    TecdsaError::Other(format!("party {pid} sent invalid y_i point encoding"))
                })?;

                if y_j == C::ProjectivePoint::identity() {
                    return Err(TecdsaError::InvalidShare(format!(
                        "party {pid} sent identity point as public share"
                    )));
                }

                let proof = PdlSlackProof::<C>::from_bytes(&r2.proof).ok_or_else(|| {
                    TecdsaError::InvalidProof(format!(
                        "party {pid} PdlSlack proof deserialization failed"
                    ))
                })?;

                let statement = PdlSlackStatement::<C> {
                    ciphertext: r2.alpha_i.clone(),
                    ek_n: ek.n().clone(),
                    ek_nn: ek.nn().clone(),
                    Q: y_j,
                    G: C::generator(),
                    h1: self.h1.clone(),
                    h2: self.h2.clone(),
                    N_tilde: self.N_tilde.clone(),
                };

                proof.verify(&statement).map_err(|_| {
                    TecdsaError::InvalidProof(format!(
                        "party {pid} PdlSlack proof verification failed"
                    ))
                })?;

                public_shares.push(y_j);
                all_alpha.push(r2.alpha_i.clone());
            }
        }

        let mut public_key = C::ProjectivePoint::identity();
        for y_j in &public_shares {
            public_key += *y_j;
        }

        let mut alpha = all_alpha[0].clone();
        for a_j in &all_alpha[1..] {
            alpha = ek
                .oadd(&alpha, a_j)
                .map_err(|e| TecdsaError::Other(format!("homomorphic addition failed: {e}")))?;
        }

        Ok(Ggn16KeyShare {
            party_index: self.my_id.0,
            secret_share: self.x_i,
            public_key,
            public_shares,
            alpha,
            threshold_setup: self.threshold_setup,
            decryption_share: self.decryption_share,
            h1: self.h1,
            h2: self.h2,
            N_tilde: self.N_tilde,
            threshold: self.threshold,
            total: self.total,
        })
    }
}

fn deserialize_point<C: TecdsaCurve>(bytes: &[u8]) -> Result<C::ProjectivePoint, ()>
where
    FieldBytesSize<C>: ModulusSize,
{
    let repr = <C::ProjectivePoint as GroupEncoding>::Repr::default();
    let buf_len = repr.as_ref().len();
    if bytes.len() != buf_len {
        return Err(());
    }
    let mut repr = repr;
    repr.as_mut().copy_from_slice(bytes);
    let opt = C::ProjectivePoint::from_bytes(&repr);
    Option::from(opt).ok_or(())
}
