#![allow(non_snake_case)]

use std::collections::BTreeMap;

use elliptic_curve::{
    group::GroupEncoding, sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField,
};
use rand_core::CryptoRngCore;
use tecdsa_commit::HashCommitment;
use tecdsa_core::TecdsaError;
use tecdsa_curve::{zk::dlog::DlogProof, TecdsaCurve};
use tecdsa_paillier::{
    backend::Integer,
    conv::{integer_to_scalar, scalar_to_integer},
    mta::{Gg18ProofSetup, Gg18Proofs, PaillierMtaProofs},
    zk::mta_range::BobProofExt,
};
use tecdsa_protocol::{Outgoing, PartyId, Recipient};
use tecdsa_vss::lagrange;
use zeroize::Zeroize;

use super::types::Gg18Presignature;
use crate::{
    key_share::Gg18KeyShare,
    sign::{msg::*, sign_keys::SignKeys},
};

#[derive(Default)]
pub(crate) enum PresignRound<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    Round1(Round1State<C>),
    Round2(Round2State<C>),
    Round3(Round3State<C>),
    Done(Gg18Presignature<C>),
    #[default]
    Gone,
}

pub struct PresignConfig<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub key_share: Gg18KeyShare<C>,
    pub signers: Vec<u16>,
}

#[allow(dead_code)]
struct SharedState<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    my_id: PartyId,
    signer_parties: Vec<PartyId>,
    key_share: Gg18KeyShare<C>,
    signers: Vec<u16>,
    sign_keys: SignKeys<C>,
}

pub(crate) struct Round1State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    shared: SharedState<C>,
    decommit_nonce: [u8; 32],
    gamma_schnorr_eph: C::Scalar,
    #[allow(dead_code)]
    c_a: Integer,
    pub outgoing: Vec<Outgoing<Gg18SignMsg<C>>>,
    round1_broadcasts: BTreeMap<PartyId, MsgSignRound1Broadcast>,
    round1_p2ps: BTreeMap<PartyId, MsgSignRound1P2p>,
    beta_shares: BTreeMap<PartyId, C::Scalar>,
    nu_shares: BTreeMap<PartyId, C::Scalar>,
}

impl<C: TecdsaCurve> Round1State<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    pub fn new(config: PresignConfig<C>, rng: &mut impl CryptoRngCore) -> Self {
        let my_1based = config.key_share.party_index + 1;
        let my_id = PartyId(my_1based);
        let signer_parties: Vec<PartyId> = config.signers.iter().map(|&i| PartyId(i)).collect();

        let lagrange_coeffs = lagrange::coefficients::<C>(&config.signers);
        let my_signer_pos = config
            .signers
            .iter()
            .position(|&i| i == my_1based)
            .expect("this party must be in the signing subset");
        let lambda_i = lagrange_coeffs[my_signer_pos];

        let sign_keys = SignKeys::create(&config.key_share.secret_share, &lambda_i, rng);

        let commit_data = point_to_bytes::<C>(&sign_keys.g_gamma_i);
        let (commitment, decommit_nonce) = HashCommitment::commit(&commit_data, rng);

        let gamma_schnorr_eph = C::random_scalar(rng);

        let my_idx = (my_id.0 - 1) as usize;
        let my_ek = &config.key_share.paillier_eks[my_idx];
        let k_i_int = scalar_to_integer::<C>(&sign_keys.k_i);
        let (c_a, r_a) = my_ek
            .encrypt_with_random(rng, &k_i_int)
            .expect("Paillier encrypt must succeed");

        let mut outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Gg18SignMsg::Round1Broadcast(MsgSignRound1Broadcast { commitment }),
        }];

        for &pid in &signer_parties {
            if pid == my_id {
                continue;
            }
            let receiver_ntilde = &config.key_share.n_tilde_params[(pid.0 - 1) as usize];
            let proof_setup = Gg18ProofSetup {
                ntilde: receiver_ntilde.clone(),
            };
            let q_dummy = Integer::zero();
            let alice_proof =
                Gg18Proofs::prove_sender(my_ek, &k_i_int, &c_a, &r_a, &proof_setup, &q_dummy, rng);
            outgoing.push(Outgoing {
                to: Recipient::Party(pid),
                msg: Gg18SignMsg::Round1P2p(MsgSignRound1P2p {
                    c_a: crate::keygen::msg::SerInteger(c_a.clone()),
                    alice_proof,
                }),
            });
        }

        Self {
            shared: SharedState {
                my_id,
                signer_parties,
                key_share: config.key_share,
                signers: config.signers,
                sign_keys,
            },
            decommit_nonce,
            gamma_schnorr_eph,
            c_a,
            outgoing,
            round1_broadcasts: BTreeMap::new(),
            round1_p2ps: BTreeMap::new(),
            beta_shares: BTreeMap::new(),
            nu_shares: BTreeMap::new(),
        }
    }

    fn expected_count(&self) -> usize {
        self.shared.signer_parties.len() - 1
    }

    pub fn handle_broadcast(
        &mut self,
        from: PartyId,
        msg: MsgSignRound1Broadcast,
    ) -> tecdsa_core::Result<()> {
        validate_sender(from, self.shared.my_id, &self.shared.signer_parties)?;
        if self.round1_broadcasts.contains_key(&from) {
            return Err(TecdsaError::DuplicateMessage(from.0));
        }
        self.round1_broadcasts.insert(from, msg);
        Ok(())
    }

    pub fn handle_p2p(
        &mut self,
        from: PartyId,
        msg: MsgSignRound1P2p,
        rng: &mut impl CryptoRngCore,
    ) -> tecdsa_core::Result<()> {
        validate_sender(from, self.shared.my_id, &self.shared.signer_parties)?;
        if self.round1_p2ps.contains_key(&from) {
            return Err(TecdsaError::DuplicateMessage(from.0));
        }

        let my_idx = (self.shared.my_id.0 - 1) as usize;
        let my_ntilde = &self.shared.key_share.n_tilde_params[my_idx];
        let sender_ek = &self.shared.key_share.paillier_eks[(from.0 - 1) as usize];

        let proof_setup = Gg18ProofSetup {
            ntilde: my_ntilde.clone(),
        };
        let q_dummy = Integer::zero();
        if !Gg18Proofs::verify_sender(
            sender_ek,
            &msg.c_a.0,
            &msg.alice_proof,
            &proof_setup,
            &q_dummy,
        ) {
            return Err(TecdsaError::InvalidProof(format!(
                "party {from} Alice range proof verification failed"
            )));
        }

        let c_a_j = &msg.c_a.0;
        let sender_ntilde = &self.shared.key_share.n_tilde_params[(from.0 - 1) as usize];

        let gamma_i_int = scalar_to_integer::<C>(&self.shared.sign_keys.gamma_i);
        let beta_prim = sender_ek.half_n().random_below_ref(rng);
        let r_bob_gamma = Integer::sample_in_mult_group_of(rng, sender_ek.n());

        let b_times_ca = sender_ek.omul(&gamma_i_int, c_a_j).expect("omul");
        let enc_beta = sender_ek
            .encrypt_with(&beta_prim, &r_bob_gamma)
            .expect("encrypt beta");
        let c_b_gamma = sender_ek.oadd(&b_times_ca, &enc_beta).expect("oadd");

        let w_i_int = scalar_to_integer::<C>(&self.shared.sign_keys.w_i);
        let nu_prim = sender_ek.half_n().random_below_ref(rng);
        let r_bob_w = Integer::sample_in_mult_group_of(rng, sender_ek.n());

        let w_times_ca = sender_ek.omul(&w_i_int, c_a_j).expect("omul");
        let enc_nu = sender_ek
            .encrypt_with(&nu_prim, &r_bob_w)
            .expect("encrypt nu");
        let c_b_w = sender_ek.oadd(&w_times_ca, &enc_nu).expect("oadd");

        let bob_proof_gamma = BobProofExt::<C>::prove(
            c_a_j,
            &c_b_gamma,
            &gamma_i_int,
            &beta_prim,
            sender_ek.n(),
            sender_ek.nn(),
            sender_ntilde,
            &r_bob_gamma,
            rng,
        );

        let bob_proof_w = BobProofExt::<C>::prove(
            c_a_j,
            &c_b_w,
            &w_i_int,
            &nu_prim,
            sender_ek.n(),
            sender_ek.nn(),
            sender_ntilde,
            &r_bob_w,
            rng,
        );

        let neg_beta_scalar = -integer_to_scalar::<C>(&beta_prim);
        let neg_nu_scalar = -integer_to_scalar::<C>(&nu_prim);
        self.beta_shares.insert(from, neg_beta_scalar);
        self.nu_shares.insert(from, neg_nu_scalar);

        let w_i_scalar = integer_to_scalar::<C>(&w_i_int);
        let w_j_point = C::generator() * w_i_scalar;

        self.outgoing.push(Outgoing {
            to: Recipient::Party(from),
            msg: Gg18SignMsg::Round2(MsgSignRound2 {
                c_b_gamma: crate::keygen::msg::SerInteger(c_b_gamma),
                c_b_w: crate::keygen::msg::SerInteger(c_b_w),
                bob_proof_gamma,
                bob_proof_w,
                w_j_point,
            }),
        });

        self.round1_p2ps.insert(from, msg);
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.round1_broadcasts.len() == self.expected_count()
            && self.round1_p2ps.len() == self.expected_count()
    }

    pub fn advance(mut self) -> Round2State<C> {
        let mut beta_vec = Vec::new();
        let mut nu_vec = Vec::new();
        for &pid in &self.shared.signer_parties {
            if pid == self.shared.my_id {
                continue;
            }
            beta_vec.push(self.beta_shares[&pid]);
            nu_vec.push(self.nu_shares[&pid]);
        }

        for v in self.beta_shares.values_mut() {
            v.zeroize();
        }
        for v in self.nu_shares.values_mut() {
            v.zeroize();
        }

        Round2State {
            shared: self.shared,
            decommit_nonce: self.decommit_nonce,
            gamma_schnorr_eph: self.gamma_schnorr_eph,
            round1_broadcasts: self.round1_broadcasts,
            c_a: self.c_a,
            beta_vec,
            nu_vec,
            outgoing: self.outgoing,
            round2_msgs: BTreeMap::new(),
        }
    }
}

pub(crate) struct Round2State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    shared: SharedState<C>,
    decommit_nonce: [u8; 32],
    gamma_schnorr_eph: C::Scalar,
    round1_broadcasts: BTreeMap<PartyId, MsgSignRound1Broadcast>,
    c_a: Integer,
    beta_vec: Vec<C::Scalar>,
    nu_vec: Vec<C::Scalar>,
    pub outgoing: Vec<Outgoing<Gg18SignMsg<C>>>,
    round2_msgs: BTreeMap<PartyId, MsgSignRound2<C>>,
}

impl<C: TecdsaCurve> Round2State<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    fn expected_count(&self) -> usize {
        self.shared.signer_parties.len() - 1
    }

    pub fn handle(&mut self, from: PartyId, msg: MsgSignRound2<C>) -> tecdsa_core::Result<()> {
        validate_sender(from, self.shared.my_id, &self.shared.signer_parties)?;
        if self.round2_msgs.contains_key(&from) {
            return Err(TecdsaError::DuplicateMessage(from.0));
        }

        let my_ek = &self.shared.key_share.paillier_eks[(self.shared.my_id.0 - 1) as usize];
        let my_ntilde = &self.shared.key_share.n_tilde_params[(self.shared.my_id.0 - 1) as usize];

        msg.bob_proof_w
            .verify(
                &self.c_a,
                &msg.c_b_w.0,
                my_ek.n(),
                my_ek.nn(),
                my_ntilde,
                &msg.w_j_point,
            )
            .map_err(|e| {
                TecdsaError::InvalidProof(format!("party {from} Bob w range proof failed: {e}"))
            })?;

        self.round2_msgs.insert(from, msg);
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.round2_msgs.len() == self.expected_count()
    }

    pub fn advance(mut self) -> Round3State<C> {
        let mut alpha_vec = Vec::new();
        let mut mu_vec = Vec::new();

        for &pid in &self.shared.signer_parties {
            if pid == self.shared.my_id {
                continue;
            }
            let bob_msg = &self.round2_msgs[&pid];

            let alpha_int = self
                .shared
                .key_share
                .dk
                .decrypt(&bob_msg.c_b_gamma.0)
                .expect("decrypt c_b_gamma");
            let alpha = signed_integer_to_scalar::<C>(&alpha_int);
            alpha_vec.push(alpha);

            let mu_int = self
                .shared
                .key_share
                .dk
                .decrypt(&bob_msg.c_b_w.0)
                .expect("decrypt c_b_w");
            let mu = signed_integer_to_scalar::<C>(&mu_int);
            mu_vec.push(mu);
        }

        let delta_i = self
            .shared
            .sign_keys
            .compute_delta_i(&alpha_vec, &self.beta_vec);
        let sigma_i = self.shared.sign_keys.compute_sigma_i(&mu_vec, &self.nu_vec);

        let gamma_proof = DlogProof::<C>::prove(
            &self.shared.sign_keys.gamma_i,
            &self.gamma_schnorr_eph,
            &self.shared.sign_keys.g_gamma_i,
            &[],
        );

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Gg18SignMsg::Round3(MsgSignRound3 {
                delta_i,
                g_gamma_i: self.shared.sign_keys.g_gamma_i,
                decommit_nonce: self.decommit_nonce,
                gamma_proof,
            }),
        }];

        self.gamma_schnorr_eph.zeroize();
        for s in &mut self.beta_vec {
            s.zeroize();
        }
        for s in &mut self.nu_vec {
            s.zeroize();
        }

        Round3State {
            shared: self.shared,
            round1_broadcasts: self.round1_broadcasts,
            c_a: self.c_a,
            round2_bob_msgs: self.round2_msgs,
            delta_i,
            sigma_i,
            outgoing,
            round3_msgs: BTreeMap::new(),
        }
    }
}

pub(crate) struct Round3State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    shared: SharedState<C>,
    round1_broadcasts: BTreeMap<PartyId, MsgSignRound1Broadcast>,
    c_a: Integer,
    round2_bob_msgs: BTreeMap<PartyId, MsgSignRound2<C>>,
    delta_i: C::Scalar,
    sigma_i: C::Scalar,
    pub outgoing: Vec<Outgoing<Gg18SignMsg<C>>>,
    round3_msgs: BTreeMap<PartyId, MsgSignRound3<C>>,
}

impl<C: TecdsaCurve> Round3State<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    fn expected_count(&self) -> usize {
        self.shared.signer_parties.len() - 1
    }

    pub fn handle(&mut self, from: PartyId, msg: MsgSignRound3<C>) -> tecdsa_core::Result<()> {
        validate_sender(from, self.shared.my_id, &self.shared.signer_parties)?;
        if self.round3_msgs.contains_key(&from) {
            return Err(TecdsaError::DuplicateMessage(from.0));
        }
        self.round3_msgs.insert(from, msg);
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.round3_msgs.len() == self.expected_count()
    }

    pub fn finish(mut self) -> tecdsa_core::Result<Gg18Presignature<C>> {
        for (&pid, decom) in &self.round3_msgs {
            let commit = self.round1_broadcasts.get(&pid).ok_or_else(|| {
                TecdsaError::Other(format!("missing round1 broadcast from {pid}"))
            })?;

            let commit_data = decom.g_gamma_i.to_bytes();
            if !commit
                .commitment
                .verify(commit_data.as_ref(), &decom.decommit_nonce)
            {
                return Err(TecdsaError::InvalidCommitment(format!(
                    "party {pid} g_gamma_i decommitment failed"
                )));
            }

            if !decom.gamma_proof.verify(&decom.g_gamma_i, &[]) {
                return Err(TecdsaError::InvalidProof(format!(
                    "party {pid} Schnorr proof for gamma_i failed"
                )));
            }

            if let Some(bob_msg) = self.round2_bob_msgs.get(&pid) {
                let my_ek = &self.shared.key_share.paillier_eks[(self.shared.my_id.0 - 1) as usize];
                let my_ntilde =
                    &self.shared.key_share.n_tilde_params[(self.shared.my_id.0 - 1) as usize];
                bob_msg
                    .bob_proof_gamma
                    .verify(
                        &self.c_a,
                        &bob_msg.c_b_gamma.0,
                        my_ek.n(),
                        my_ek.nn(),
                        my_ntilde,
                        &decom.g_gamma_i,
                    )
                    .map_err(|e| {
                        TecdsaError::InvalidProof(format!(
                            "party {pid} Bob gamma range proof failed: {e}"
                        ))
                    })?;
            }
        }

        let mut g_gamma_vec = vec![self.shared.sign_keys.g_gamma_i];
        let mut all_deltas = vec![self.delta_i];
        for &pid in &self.shared.signer_parties {
            if pid == self.shared.my_id {
                continue;
            }
            g_gamma_vec.push(self.round3_msgs[&pid].g_gamma_i);
            all_deltas.push(self.round3_msgs[&pid].delta_i);
        }

        let delta_inv = SignKeys::<C>::reconstruct_delta_inv(&all_deltas)?;
        let (R, r) = SignKeys::<C>::compute_R(&delta_inv, &g_gamma_vec);

        self.delta_i.zeroize();

        Ok(Gg18Presignature {
            R,
            r,
            k_i: self.shared.sign_keys.k_i,
            sigma_i: self.sigma_i,
            public_key: self.shared.key_share.public_key,
            my_id: self.shared.my_id,
            signer_parties: self.shared.signer_parties.clone(),
        })
    }
}

fn point_to_bytes<C: TecdsaCurve>(p: &C::ProjectivePoint) -> Vec<u8>
where
    FieldBytesSize<C>: ModulusSize,
{
    p.to_bytes().as_ref().to_vec()
}

fn signed_integer_to_scalar<C: TecdsaCurve>(
    i: &Integer,
) -> <C as elliptic_curve::CurveArithmetic>::Scalar
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    if i.cmp0().is_lt() {
        let abs_val = -i.clone();
        let pos_scalar = integer_to_scalar::<C>(&abs_val);
        -pos_scalar
    } else {
        integer_to_scalar::<C>(i)
    }
}

fn validate_sender(from: PartyId, my_id: PartyId, parties: &[PartyId]) -> tecdsa_core::Result<()> {
    if from == my_id {
        return Err(TecdsaError::Other("received message from self".into()));
    }
    if !parties.contains(&from) {
        return Err(TecdsaError::UnknownSender(from.0));
    }
    Ok(())
}
