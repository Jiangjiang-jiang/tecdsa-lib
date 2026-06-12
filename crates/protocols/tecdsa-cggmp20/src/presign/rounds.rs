use std::collections::BTreeMap;

use elliptic_curve::{
    group::GroupEncoding, sec1::ModulusSize, Field, FieldBytes, FieldBytesSize, PrimeField,
};
use generic_ec::curves::Secp256k1 as GE;
use rand_core::CryptoRngCore;
use sha2::Sha256;
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_paillier::{
    backend::Integer,
    conv::scalar_to_integer,
    zk::paillier_zk::{
        dlog_with_el_gamal_commitment as pi_elog, paillier_affine_operation_in_range as pi_aff,
        paillier_encryption_in_range_with_el_gamal as pi_enc_elg,
    },
    Ciphertext, DecryptionKey, EncryptionKey,
};
use tecdsa_pedersen_mod::PedersenModParams;
use tecdsa_protocol::{Outgoing, PartyId, Recipient, SessionConfig};
use tecdsa_vss::lagrange;
use zeroize::Zeroize;

use super::msg::{MsgRound1, MsgRound2, MsgRound3, PresignMsg};
use crate::{
    bridge::pedersen_to_aux,
    key_share::{AuxInfo, Cggmp20CoreKeyShare},
    sign::types::{Presignature, PresignaturePublicData},
};

fn to_ge_point<C: TecdsaCurve>(p: &C::ProjectivePoint) -> generic_ec::Point<GE>
where
    FieldBytesSize<C>: ModulusSize,
{
    let bytes = p.to_bytes();
    generic_ec::Point::from_bytes(bytes.as_ref()).expect("valid point must decode")
}

fn to_ge_scalar<C: TecdsaCurve>(s: &C::Scalar) -> generic_ec::Scalar<GE>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let repr = s.to_repr();
    let bytes: &[u8] = repr.as_ref();
    generic_ec::Scalar::from_be_bytes_mod_order(bytes)
}

#[derive(udigest::Digestable)]
#[udigest(tag = "tecdsa.cggmp20.presign.proof_enc")]
struct ProofEncTag {
    session_id: [u8; 32],
    prover: u16,
    num: u8,
}

#[derive(udigest::Digestable)]
#[udigest(tag = "tecdsa.cggmp20.presign.proof_psi")]
struct ProofPsiTag {
    session_id: [u8; 32],
    prover: u16,
    hat: bool,
}

#[derive(udigest::Digestable)]
#[udigest(tag = "tecdsa.cggmp20.presign.proof_elog")]
struct ProofElogTag {
    session_id: [u8; 32],
    prover: u16,
    prime: bool,
}

fn paillier_int_to_scalar<C>(i: &Integer) -> C::Scalar
where
    C: TecdsaCurve,
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let neg_one = -C::Scalar::ONE;
    let q = scalar_to_integer::<C>(&neg_one) + Integer::one();
    let reduced = i.modulo_ref(&q);
    let red_bytes = reduced.to_bytes_msf();
    let fb = bytes_to_field_bytes::<C>(&red_bytes);
    <C::Scalar as PrimeField>::from_repr(fb)
        .into_option()
        .expect("modular-reduced value must be < group order")
}

fn bytes_to_field_bytes<C: TecdsaCurve>(bytes: &[u8]) -> FieldBytes<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    let scalar_len = C::SCALAR_BYTES;
    let mut fb = FieldBytes::<C>::default();
    let out = fb.as_mut_slice();
    if bytes.len() >= scalar_len {
        out.copy_from_slice(&bytes[bytes.len() - scalar_len..]);
    } else {
        out[scalar_len - bytes.len()..].copy_from_slice(bytes);
    }
    fb
}

#[derive(Default)]
pub(crate) enum PresignRound<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    Round1(Round1State<C>),
    Round2(Round2State<C>),
    Round3(Round3State<C>),
    Done((Presignature<C>, PresignaturePublicData<C>)),
    #[default]
    Gone,
}

pub(crate) struct Round1State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub my_id: PartyId,
    pub my_index: u16,
    pub signers_pids: Vec<PartyId>,
    pub session_id: [u8; 32],

    pub k_i: C::Scalar,
    pub gamma_i: C::Scalar,
    #[allow(dead_code)]
    pub y_i: C::Scalar,
    pub a_i: C::Scalar,
    pub b_i: C::Scalar,
    pub big_k_i: Ciphertext,
    pub big_g_i: Ciphertext,
    pub rho_i: Integer,
    pub gamma_nonce: Integer,

    pub x_i_additive: C::Scalar,

    pub own_round1: MsgRound1<C>,

    pub public_key: C::ProjectivePoint,
    pub public_shares: Vec<C::ProjectivePoint>,

    pub dk: DecryptionKey,
    pub ek_own: EncryptionKey,
    pub paillier_eks: Vec<EncryptionKey>,

    pub pedersen_params: Vec<PedersenModParams>,

    pub ell: usize,
    pub epsilon: usize,
    pub ell_prime: usize,

    pub signer_party_indices: BTreeMap<PartyId, u16>,

    pub outgoing: Vec<Outgoing<PresignMsg<C>>>,

    pub round1_msgs: BTreeMap<PartyId, MsgRound1<C>>,
}

impl<C: TecdsaCurve> Round1State<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    pub fn new(
        config: &SessionConfig,
        core_share: &Cggmp20CoreKeyShare<C>,
        aux: &AuxInfo,
        signers: &[u16],
        ell: usize,
        epsilon: usize,
        ell_prime: usize,
        rng: &mut impl CryptoRngCore,
    ) -> Self {
        let my_id = config.local_party.id;
        let my_index = config.local_party.index;
        let signers_pids: Vec<PartyId> = signers.iter().map(|&i| PartyId(i)).collect();
        let session_id = config.session_id.0;

        let signer_party_indices: BTreeMap<PartyId, u16> =
            signers.iter().map(|&s| (PartyId(s), s - 1)).collect();

        let lagrange_coeffs = lagrange::coefficients::<C>(signers);
        let my_signer_pos = signers
            .iter()
            .position(|&s| s == my_id.0)
            .expect("own party must be in signers list");
        let lambda_i = lagrange_coeffs[my_signer_pos];
        let x_i_additive = lambda_i * core_share.secret_share;

        let k_i = C::random_scalar(rng);
        let gamma_i = C::random_scalar(rng);

        let own_ek = &aux.paillier_eks[aux.party_index as usize];
        let plaintext_k = scalar_to_integer::<C>(&k_i);
        let (big_k_i, rho_i) = own_ek
            .encrypt_with_random(rng, &plaintext_k)
            .expect("encryption of k_i must succeed");

        let plaintext_gamma = scalar_to_integer::<C>(&gamma_i);
        let (big_g_i, gamma_nonce) = own_ek
            .encrypt_with_random(rng, &plaintext_gamma)
            .expect("encryption of gamma_i must succeed");

        let y_i = C::random_scalar(rng);
        let a_i = C::random_scalar(rng);
        let b_i = C::random_scalar(rng);

        let big_y = C::generator() * y_i;
        let a1 = C::generator() * a_i;
        let a2 = big_y * a_i + C::generator() * k_i;
        let b1 = C::generator() * b_i;
        let b2 = big_y * b_i + C::generator() * gamma_i;

        let own_round1 = MsgRound1 {
            big_k: big_k_i.clone(),
            big_g: big_g_i.clone(),
            big_y,
            a1,
            a2,
            b1,
            b2,
        };

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: PresignMsg::Round1(own_round1.clone()),
        }];

        Self {
            my_id,
            my_index,
            signers_pids,
            session_id,
            k_i,
            gamma_i,
            y_i,
            a_i,
            b_i,
            big_k_i,
            big_g_i,
            rho_i,
            gamma_nonce,
            x_i_additive,
            own_round1,
            public_key: core_share.public_key,
            public_shares: core_share.public_shares.clone(),
            dk: aux.dk.clone(),
            ek_own: own_ek.clone(),
            paillier_eks: aux.paillier_eks.clone(),
            pedersen_params: aux.pedersen_params.clone(),
            ell,
            epsilon,
            ell_prime,
            signer_party_indices,
            outgoing,
            round1_msgs: BTreeMap::new(),
        }
    }

    fn expected_count(&self) -> usize {
        self.signers_pids.len() - 1
    }

    pub fn handle(&mut self, from: PartyId, msg: MsgRound1<C>) -> tecdsa_core::Result<()> {
        if from == self.my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }
        if !self.signers_pids.contains(&from) {
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

    pub fn advance(mut self) -> Round2State<C> {
        let mut rng = tecdsa_core::Csprng::new();
        let mut outgoing: Vec<Outgoing<PresignMsg<C>>> = Vec::new();

        let big_gamma_i = C::generator() * self.gamma_i;

        let gamma_i_int = scalar_to_integer::<C>(&self.gamma_i);
        let x_i_int = scalar_to_integer::<C>(&self.x_i_additive);

        let mut beta_map: BTreeMap<PartyId, C::Scalar> = BTreeMap::new();
        let mut hat_beta_map: BTreeMap<PartyId, C::Scalar> = BTreeMap::new();

        let security_enc = pi_enc_elg::SecurityParams {
            l: self.ell,
            epsilon: self.epsilon,
        };
        let security_aff = pi_aff::SecurityParams {
            l_x: self.ell,
            l_y: self.ell_prime,
            epsilon: self.epsilon,
        };

        let ge_big_y = to_ge_point::<C>(&self.own_round1.big_y);
        let ge_a1 = to_ge_point::<C>(&self.own_round1.a1);
        let ge_a2 = to_ge_point::<C>(&self.own_round1.a2);
        let ge_b1 = to_ge_point::<C>(&self.own_round1.b1);
        let ge_b2 = to_ge_point::<C>(&self.own_round1.b2);
        let ge_gamma_i = to_ge_point::<C>(&big_gamma_i);
        let ge_a_i = to_ge_scalar::<C>(&self.a_i);
        let ge_b_i = to_ge_scalar::<C>(&self.b_i);

        let tilde_psi = pi_elog::non_interactive::prove::<GE, Sha256>(
            &ProofElogTag {
                session_id: self.session_id,
                prover: self.my_index,
                prime: false,
            },
            pi_elog::Data {
                l: &ge_b1,
                m: &ge_b2,
                x: &ge_big_y,
                y: &ge_gamma_i,
                h: &generic_ec::Point::generator().to_point(),
            },
            pi_elog::PrivateData {
                y: &to_ge_scalar::<C>(&self.gamma_i),
                lambda: &ge_b_i,
            },
            &mut rng,
        )
        .expect("tilde_psi proof generation must succeed");

        let x_i_public = C::generator() * self.x_i_additive;
        let ge_x_i_public = to_ge_point::<C>(&x_i_public);

        let k_i_int = scalar_to_integer::<C>(&self.k_i);

        for &peer_pid in &self.signers_pids {
            if peer_pid == self.my_id {
                continue;
            }

            let peer_round1 = self
                .round1_msgs
                .get(&peer_pid)
                .expect("round1 msg must exist for all peers");

            let peer_party_idx = self.signer_party_indices[&peer_pid] as usize;
            let peer_ek = &self.paillier_eks[peer_party_idx];
            let peer_aux = pedersen_to_aux(&self.pedersen_params[peer_party_idx]);

            let beta_ij = C::random_scalar(&mut rng);
            let beta_ij_int = scalar_to_integer::<C>(&beta_ij);
            let neg_beta_ij_int = -&beta_ij_int;

            let d_step1 = peer_ek
                .omul(&gamma_i_int, &peer_round1.big_k)
                .expect("omul must succeed");
            let (enc_neg_beta, s_ij) = peer_ek
                .encrypt_with_random(&mut rng, &neg_beta_ij_int)
                .expect("encrypt must succeed");
            let big_d = peer_ek
                .oadd(&d_step1, &enc_neg_beta)
                .expect("oadd must succeed");

            let (big_f, r_ij) = self
                .ek_own
                .encrypt_with_random(&mut rng, &neg_beta_ij_int)
                .expect("encrypt must succeed");

            let hat_beta_ij = C::random_scalar(&mut rng);
            let hat_beta_ij_int = scalar_to_integer::<C>(&hat_beta_ij);
            let neg_hat_beta_ij_int = -&hat_beta_ij_int;

            let hat_d_step1 = peer_ek
                .omul(&x_i_int, &peer_round1.big_k)
                .expect("omul must succeed");
            let (enc_neg_hat_beta, hat_s_ij) = peer_ek
                .encrypt_with_random(&mut rng, &neg_hat_beta_ij_int)
                .expect("encrypt must succeed");
            let hat_big_d = peer_ek
                .oadd(&hat_d_step1, &enc_neg_hat_beta)
                .expect("oadd must succeed");

            let (hat_big_f, hat_r_ij) = self
                .ek_own
                .encrypt_with_random(&mut rng, &neg_hat_beta_ij_int)
                .expect("encrypt must succeed");

            beta_map.insert(peer_pid, beta_ij);
            hat_beta_map.insert(peer_pid, hat_beta_ij);

            let psi0 = pi_enc_elg::non_interactive::prove::<GE, Sha256>(
                &ProofEncTag {
                    session_id: self.session_id,
                    prover: self.my_index,
                    num: 0,
                },
                &peer_aux,
                pi_enc_elg::Data {
                    key: &self.ek_own,
                    ciphertext: &self.big_k_i,
                    a: &ge_big_y,
                    b: &ge_a1,
                    x: &ge_a2,
                },
                pi_enc_elg::PrivateData {
                    plaintext: &k_i_int,
                    nonce: &self.rho_i,
                    b: &ge_a_i,
                },
                &security_enc,
                &mut rng,
            )
            .expect("psi0 proof generation must succeed");

            let psi1 = pi_enc_elg::non_interactive::prove::<GE, Sha256>(
                &ProofEncTag {
                    session_id: self.session_id,
                    prover: self.my_index,
                    num: 1,
                },
                &peer_aux,
                pi_enc_elg::Data {
                    key: &self.ek_own,
                    ciphertext: &self.big_g_i,
                    a: &ge_big_y,
                    b: &ge_b1,
                    x: &ge_b2,
                },
                pi_enc_elg::PrivateData {
                    plaintext: &scalar_to_integer::<C>(&self.gamma_i),
                    nonce: &self.gamma_nonce,
                    b: &ge_b_i,
                },
                &security_enc,
                &mut rng,
            )
            .expect("psi1 proof generation must succeed");

            let psi = pi_aff::non_interactive::prove::<GE, Sha256>(
                &ProofPsiTag {
                    session_id: self.session_id,
                    prover: self.my_index,
                    hat: false,
                },
                &peer_aux,
                pi_aff::Data {
                    key_j: peer_ek,
                    key_i: &self.ek_own,
                    c: &peer_round1.big_k,
                    d: &big_d,
                    y: &big_f,
                    x: &ge_gamma_i,
                },
                pi_aff::PrivateData {
                    x: &gamma_i_int,
                    y: &neg_beta_ij_int,
                    nonce: &s_ij,
                    nonce_y: &r_ij,
                },
                &security_aff,
                &mut rng,
            )
            .expect("psi proof generation must succeed");

            let hat_psi = pi_aff::non_interactive::prove::<GE, Sha256>(
                &ProofPsiTag {
                    session_id: self.session_id,
                    prover: self.my_index,
                    hat: true,
                },
                &peer_aux,
                pi_aff::Data {
                    key_j: peer_ek,
                    key_i: &self.ek_own,
                    c: &peer_round1.big_k,
                    d: &hat_big_d,
                    y: &hat_big_f,
                    x: &ge_x_i_public,
                },
                pi_aff::PrivateData {
                    x: &x_i_int,
                    y: &neg_hat_beta_ij_int,
                    nonce: &hat_s_ij,
                    nonce_y: &hat_r_ij,
                },
                &security_aff,
                &mut rng,
            )
            .expect("hat_psi proof generation must succeed");

            outgoing.push(Outgoing {
                to: Recipient::Party(peer_pid),
                msg: PresignMsg::Round2(MsgRound2 {
                    big_gamma: big_gamma_i,
                    big_d,
                    big_f,
                    hat_big_d,
                    hat_big_f,
                    psi0,
                    psi1,
                    tilde_psi: tilde_psi.clone(),
                    psi,
                    hat_psi,
                }),
            });
        }

        self.y_i.zeroize();
        self.b_i.zeroize();

        Round2State {
            my_id: self.my_id,
            my_index: self.my_index,
            signers_pids: self.signers_pids,
            session_id: self.session_id,
            k_i: self.k_i,
            gamma_i: self.gamma_i,
            a_i: self.a_i,
            x_i_additive: self.x_i_additive,
            big_gamma_i,
            dk: self.dk,
            ek_own: self.ek_own,
            paillier_eks: self.paillier_eks,
            pedersen_params: self.pedersen_params,
            beta_map,
            hat_beta_map,
            signer_party_indices: self.signer_party_indices,
            round1_msgs: self.round1_msgs,
            own_round1: self.own_round1,
            public_key: self.public_key,
            public_shares: self.public_shares,
            ell: self.ell,
            epsilon: self.epsilon,
            ell_prime: self.ell_prime,
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
    pub my_index: u16,
    pub signers_pids: Vec<PartyId>,
    pub session_id: [u8; 32],

    pub k_i: C::Scalar,
    pub gamma_i: C::Scalar,
    pub a_i: C::Scalar,
    pub x_i_additive: C::Scalar,
    pub big_gamma_i: C::ProjectivePoint,

    pub dk: DecryptionKey,
    #[allow(dead_code)]
    pub ek_own: EncryptionKey,
    pub paillier_eks: Vec<EncryptionKey>,
    pub pedersen_params: Vec<PedersenModParams>,

    pub beta_map: BTreeMap<PartyId, C::Scalar>,
    pub hat_beta_map: BTreeMap<PartyId, C::Scalar>,

    pub signer_party_indices: BTreeMap<PartyId, u16>,
    pub round1_msgs: BTreeMap<PartyId, MsgRound1<C>>,
    pub own_round1: MsgRound1<C>,
    pub public_key: C::ProjectivePoint,
    pub public_shares: Vec<C::ProjectivePoint>,

    pub ell: usize,
    pub epsilon: usize,
    pub ell_prime: usize,

    pub outgoing: Vec<Outgoing<PresignMsg<C>>>,
    pub round2_msgs: BTreeMap<PartyId, MsgRound2<C>>,
}

impl<C: TecdsaCurve> Round2State<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    fn expected_count(&self) -> usize {
        self.signers_pids.len() - 1
    }

    pub fn handle(&mut self, from: PartyId, msg: MsgRound2<C>) -> tecdsa_core::Result<()> {
        if from == self.my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }
        if !self.signers_pids.contains(&from) {
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

    pub fn advance(mut self) -> tecdsa_core::Result<Round3State<C>> {
        let mut rng = tecdsa_core::Csprng::new();

        let own_party_idx = self.signer_party_indices[&self.my_id] as usize;
        let own_aux = pedersen_to_aux(&self.pedersen_params[own_party_idx]);

        let security_enc = pi_enc_elg::SecurityParams {
            l: self.ell,
            epsilon: self.epsilon,
        };
        let security_aff = pi_aff::SecurityParams {
            l_x: self.ell,
            l_y: self.ell_prime,
            epsilon: self.epsilon,
        };

        let signers_1based: Vec<u16> = self.signers_pids.iter().map(|p| p.0).collect();
        let lagrange_coeffs = lagrange::coefficients::<C>(&signers_1based);

        let mut alpha_sum = C::Scalar::ZERO;
        let mut hat_alpha_sum = C::Scalar::ZERO;

        for (&peer_pid, round2) in &self.round2_msgs {
            let peer_party_idx = self.signer_party_indices[&peer_pid] as usize;
            let peer_ek = &self.paillier_eks[peer_party_idx];
            let peer_round1 = &self.round1_msgs[&peer_pid];
            let peer_index = peer_pid.0;

            let ge_peer_y = to_ge_point::<C>(&peer_round1.big_y);
            let ge_peer_a1 = to_ge_point::<C>(&peer_round1.a1);
            let ge_peer_a2 = to_ge_point::<C>(&peer_round1.a2);
            let ge_peer_b1 = to_ge_point::<C>(&peer_round1.b1);
            let ge_peer_b2 = to_ge_point::<C>(&peer_round1.b2);
            let ge_peer_gamma = to_ge_point::<C>(&round2.big_gamma);

            pi_enc_elg::non_interactive::verify::<GE, Sha256>(
                &ProofEncTag {
                    session_id: self.session_id,
                    prover: peer_index,
                    num: 0,
                },
                &own_aux,
                pi_enc_elg::Data {
                    key: peer_ek,
                    ciphertext: &peer_round1.big_k,
                    a: &ge_peer_y,
                    b: &ge_peer_a1,
                    x: &ge_peer_a2,
                },
                &round2.psi0,
                &security_enc,
            )
            .map_err(|e| {
                TecdsaError::Other(format!(
                    "psi0 verification failed for party {peer_index}: {e}"
                ))
            })?;

            pi_enc_elg::non_interactive::verify::<GE, Sha256>(
                &ProofEncTag {
                    session_id: self.session_id,
                    prover: peer_index,
                    num: 1,
                },
                &own_aux,
                pi_enc_elg::Data {
                    key: peer_ek,
                    ciphertext: &peer_round1.big_g,
                    a: &ge_peer_y,
                    b: &ge_peer_b1,
                    x: &ge_peer_b2,
                },
                &round2.psi1,
                &security_enc,
            )
            .map_err(|e| {
                TecdsaError::Other(format!(
                    "psi1 verification failed for party {peer_index}: {e}"
                ))
            })?;

            pi_elog::non_interactive::verify::<GE, Sha256>(
                &ProofElogTag {
                    session_id: self.session_id,
                    prover: peer_index,
                    prime: false,
                },
                pi_elog::Data {
                    l: &ge_peer_b1,
                    m: &ge_peer_b2,
                    x: &ge_peer_y,
                    y: &ge_peer_gamma,
                    h: &generic_ec::Point::generator().to_point(),
                },
                &round2.tilde_psi,
            )
            .map_err(|e| {
                TecdsaError::Other(format!(
                    "tilde_psi verification failed for party {peer_index}: {e}"
                ))
            })?;

            pi_aff::non_interactive::verify::<GE, Sha256>(
                &ProofPsiTag {
                    session_id: self.session_id,
                    prover: peer_index,
                    hat: false,
                },
                &own_aux,
                pi_aff::Data {
                    key_j: &self.dk,
                    key_i: peer_ek,
                    c: &self.own_round1.big_k,
                    d: &round2.big_d,
                    y: &round2.big_f,
                    x: &ge_peer_gamma,
                },
                &security_aff,
                &round2.psi,
            )
            .map_err(|e| {
                TecdsaError::Other(format!(
                    "psi verification failed for party {peer_index}: {e}"
                ))
            })?;

            let peer_signer_pos = signers_1based
                .iter()
                .position(|&s| s == peer_pid.0)
                .expect("peer must be in signers list");
            let peer_lambda = lagrange_coeffs[peer_signer_pos];
            let peer_additive_public = self.public_shares[peer_party_idx] * peer_lambda;
            let ge_peer_x_public = to_ge_point::<C>(&peer_additive_public);

            pi_aff::non_interactive::verify::<GE, Sha256>(
                &ProofPsiTag {
                    session_id: self.session_id,
                    prover: peer_index,
                    hat: true,
                },
                &own_aux,
                pi_aff::Data {
                    key_j: &self.dk,
                    key_i: peer_ek,
                    c: &self.own_round1.big_k,
                    d: &round2.hat_big_d,
                    y: &round2.hat_big_f,
                    x: &ge_peer_x_public,
                },
                &security_aff,
                &round2.hat_psi,
            )
            .map_err(|e| {
                TecdsaError::Other(format!(
                    "hat_psi verification failed for party {peer_index}: {e}"
                ))
            })?;

            let alpha_int = self
                .dk
                .decrypt(&round2.big_d)
                .map_err(|e| TecdsaError::Other(format!("decrypt alpha from {peer_index}: {e}")))?;
            let alpha_ij = paillier_int_to_scalar::<C>(&alpha_int);
            alpha_sum += alpha_ij;

            let hat_alpha_int = self.dk.decrypt(&round2.hat_big_d).map_err(|e| {
                TecdsaError::Other(format!("decrypt hat_alpha from {peer_index}: {e}"))
            })?;
            let hat_alpha_ij = paillier_int_to_scalar::<C>(&hat_alpha_int);
            hat_alpha_sum += hat_alpha_ij;
        }

        let beta_sum: C::Scalar = self
            .beta_map
            .values()
            .copied()
            .fold(C::Scalar::ZERO, |a, b| a + b);
        let hat_beta_sum: C::Scalar = self
            .hat_beta_map
            .values()
            .copied()
            .fold(C::Scalar::ZERO, |a, b| a + b);

        let delta_i = self.gamma_i * self.k_i + alpha_sum + beta_sum;
        let chi_i = self.x_i_additive * self.k_i + hat_alpha_sum + hat_beta_sum;

        let mut big_gamma = self.big_gamma_i;
        for round2 in self.round2_msgs.values() {
            big_gamma += round2.big_gamma;
        }

        let big_delta_i = big_gamma * self.k_i;
        let big_s_i = big_gamma * chi_i;

        let ge_own_a1 = to_ge_point::<C>(&self.own_round1.a1);
        let ge_own_a2 = to_ge_point::<C>(&self.own_round1.a2);
        let ge_own_y = to_ge_point::<C>(&self.own_round1.big_y);
        let ge_delta_i = to_ge_point::<C>(&big_delta_i);
        let ge_big_gamma = to_ge_point::<C>(&big_gamma);

        let psi_prime = pi_elog::non_interactive::prove::<GE, Sha256>(
            &ProofElogTag {
                session_id: self.session_id,
                prover: self.my_index,
                prime: true,
            },
            pi_elog::Data {
                l: &ge_own_a1,
                m: &ge_own_a2,
                x: &ge_own_y,
                y: &ge_delta_i,
                h: &ge_big_gamma,
            },
            pi_elog::PrivateData {
                y: &to_ge_scalar::<C>(&self.k_i),
                lambda: &to_ge_scalar::<C>(&self.a_i),
            },
            &mut rng,
        )
        .map_err(|e| TecdsaError::Other(format!("psi_prime proof generation failed: {e}")))?;

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: PresignMsg::Round3(MsgRound3 {
                delta: delta_i,
                big_delta: big_delta_i,
                big_s: big_s_i,
                psi_prime,
            }),
        }];

        self.gamma_i.zeroize();
        self.a_i.zeroize();
        self.x_i_additive.zeroize();
        for v in self.beta_map.values_mut() {
            v.zeroize();
        }
        for v in self.hat_beta_map.values_mut() {
            v.zeroize();
        }

        Ok(Round3State {
            my_id: self.my_id,
            signers_pids: self.signers_pids,
            session_id: self.session_id,
            k_i: self.k_i,
            chi_i,
            delta_i,
            big_gamma,
            big_delta_i,
            big_s_i,
            public_key: self.public_key,
            round1_msgs: self.round1_msgs,
            outgoing,
            round3_msgs: BTreeMap::new(),
        })
    }
}

pub(crate) struct Round3State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub my_id: PartyId,
    pub signers_pids: Vec<PartyId>,
    pub session_id: [u8; 32],

    pub k_i: C::Scalar,
    pub chi_i: C::Scalar,
    pub delta_i: C::Scalar,
    pub big_gamma: C::ProjectivePoint,
    pub big_delta_i: C::ProjectivePoint,
    pub big_s_i: C::ProjectivePoint,
    pub public_key: C::ProjectivePoint,

    pub round1_msgs: BTreeMap<PartyId, MsgRound1<C>>,

    pub outgoing: Vec<Outgoing<PresignMsg<C>>>,
    pub round3_msgs: BTreeMap<PartyId, MsgRound3<C>>,
}

impl<C: TecdsaCurve> Round3State<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    fn expected_count(&self) -> usize {
        self.signers_pids.len() - 1
    }

    pub fn handle(&mut self, from: PartyId, msg: MsgRound3<C>) -> tecdsa_core::Result<()> {
        if from == self.my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }
        if !self.signers_pids.contains(&from) {
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

    pub fn finish(mut self) -> tecdsa_core::Result<(Presignature<C>, PresignaturePublicData<C>)> {
        let ge_big_gamma = to_ge_point::<C>(&self.big_gamma);

        for (&peer_pid, round3) in &self.round3_msgs {
            let peer_index = peer_pid.0;
            let peer_round1 = &self.round1_msgs[&peer_pid];

            let ge_peer_a1 = to_ge_point::<C>(&peer_round1.a1);
            let ge_peer_a2 = to_ge_point::<C>(&peer_round1.a2);
            let ge_peer_y = to_ge_point::<C>(&peer_round1.big_y);
            let ge_peer_delta = to_ge_point::<C>(&round3.big_delta);

            pi_elog::non_interactive::verify::<GE, Sha256>(
                &ProofElogTag {
                    session_id: self.session_id,
                    prover: peer_index,
                    prime: true,
                },
                pi_elog::Data {
                    l: &ge_peer_a1,
                    m: &ge_peer_a2,
                    x: &ge_peer_y,
                    y: &ge_peer_delta,
                    h: &ge_big_gamma,
                },
                &round3.psi_prime,
            )
            .map_err(|e| {
                TecdsaError::Other(format!(
                    "psi_prime verification failed for party {peer_index}: {e}"
                ))
            })?;
        }

        let mut delta = self.delta_i;
        for round3 in self.round3_msgs.values() {
            delta += round3.delta;
        }

        let mut big_delta_sum = self.big_delta_i;
        for round3 in self.round3_msgs.values() {
            big_delta_sum += round3.big_delta;
        }

        let delta_g = C::generator() * delta;
        if delta_g != big_delta_sum {
            return Err(TecdsaError::Other(
                "presign consistency check failed: delta * G != sum(Delta_i)".into(),
            ));
        }

        let mut big_s_sum = self.big_s_i;
        for round3 in self.round3_msgs.values() {
            big_s_sum += round3.big_s;
        }

        let pk_delta = self.public_key * delta;
        if pk_delta != big_s_sum {
            return Err(TecdsaError::Other(
                "presign consistency check failed: pk * delta != sum(S_i)".into(),
            ));
        }

        let delta_inv = delta
            .invert()
            .into_option()
            .ok_or_else(|| TecdsaError::Other("delta is zero (degenerate presignature)".into()))?;

        let k_tilde_i = self.k_i * delta_inv;
        let chi_tilde_i = self.chi_i * delta_inv;

        let mut all_deltas: BTreeMap<PartyId, (C::ProjectivePoint, C::ProjectivePoint)> =
            BTreeMap::new();
        all_deltas.insert(self.my_id, (self.big_delta_i, self.big_s_i));
        for (&pid, round3) in &self.round3_msgs {
            all_deltas.insert(pid, (round3.big_delta, round3.big_s));
        }
        let commitments: Vec<_> = all_deltas
            .values()
            .map(
                |(big_delta, big_s)| crate::sign::types::PresignatureCommitment {
                    tilde_delta: *big_delta * delta_inv,
                    tilde_s: *big_s * delta_inv,
                },
            )
            .collect();

        let presig = Presignature {
            big_r: self.big_gamma,
            k_tilde: k_tilde_i,
            chi_tilde: chi_tilde_i,
        };
        let public_data = PresignaturePublicData {
            big_r: self.big_gamma,
            commitments,
        };

        self.k_i.zeroize();
        self.delta_i.zeroize();
        self.chi_i.zeroize();

        Ok((presig, public_data))
    }
}
