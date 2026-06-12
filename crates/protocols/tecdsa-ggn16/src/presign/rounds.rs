#![allow(non_snake_case)]

use std::collections::BTreeMap;

use elliptic_curve::{
    group::{Curve as CurveGroup, GroupEncoding},
    sec1::ModulusSize,
    Field, FieldBytes, FieldBytesSize, PrimeField,
};
use rand_core::CryptoRngCore;
use tecdsa_commit::HashCommitment;
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_paillier::{
    backend::Integer,
    conv::{group_order_integer, integer_to_scalar, scalar_to_integer},
    threshold::{combine_partials, partial_decrypt, PartialDecryption},
    zk::{
        homo_mult::{HomoMultProof, HomoMultStatement, HomoMultWitness},
        nonce_consist::{NonceConsistProof, NonceConsistStatement, NonceConsistWitness},
    },
};
use tecdsa_protocol::{Outgoing, PartyId, Recipient};
use zeroize::Zeroize;

use crate::{
    key_share::Ggn16KeyShare,
    presign::types::Ggn16Presignature,
    sign::msg::{
        Ggn16SignMsg, SignRound1Msg, SignRound2Msg, SignRound3Msg, SignRound4Msg, SignRound5Msg,
    },
    utils::{deserialize_point, serialize_for_commit_r1, serialize_for_commit_r3},
};

pub(crate) struct PresignConfig<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub key_share: Ggn16KeyShare<C>,
    pub my_id: PartyId,
    pub signer_parties: Vec<PartyId>,
}

#[derive(Default)]
pub(crate) enum PresignRound<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    Round1(Round1State<C>),
    Round2(Round2State<C>),
    Round3(Round3State<C>),
    Round4(Round4State<C>),
    Round5(Round5State<C>),
    Done(Ggn16Presignature<C>),
    #[default]
    Poisoned,
}

pub(crate) struct Round1State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub config: PresignConfig<C>,

    pub rho_i: Integer,
    pub u_i: Integer,
    pub v_i: Integer,
    pub r_u: Integer,
    pub r_v: Integer,
    pub decommit_nonce: [u8; 32],

    pub outgoing: Vec<Outgoing<Ggn16SignMsg>>,
    pub round1_msgs: BTreeMap<PartyId, SignRound1Msg>,
}

impl<C: TecdsaCurve> Round1State<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    pub fn new(config: PresignConfig<C>, rng: &mut impl CryptoRngCore) -> Self {
        let ek = &config.key_share.threshold_setup.ek;
        let alpha = &config.key_share.alpha;

        let q = group_order_integer::<C>();
        let rho_i = q.random_below_ref(rng);

        let (u_i, r_u) = ek
            .encrypt_with_random(rng, &rho_i)
            .expect("Paillier encryption of rho_i must succeed");

        let v_i_raw = ek
            .omul(&rho_i, alpha)
            .expect("homomorphic scalar-mul must succeed");
        let r_v = Integer::sample_in_mult_group_of(rng, ek.n());
        let r_v_n = r_v
            .pow_mod_ref(ek.n(), ek.nn())
            .expect("r_v^N mod N^2 must succeed");
        let v_i = (&v_i_raw * &r_v_n).modulo(ek.nn());

        let commit_data = serialize_for_commit_r1(&u_i, &v_i);
        let (hash_commitment, decommit_nonce) = HashCommitment::commit(&commit_data, rng);

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Ggn16SignMsg::Round1(SignRound1Msg {
                commitment: hash_commitment,
            }),
        }];

        Self {
            config,
            rho_i,
            u_i,
            v_i,
            r_u,
            r_v,
            decommit_nonce,
            outgoing,
            round1_msgs: BTreeMap::new(),
        }
    }

    fn expected_count(&self) -> usize {
        self.config.signer_parties.len() - 1
    }

    pub fn handle(&mut self, from: PartyId, msg: SignRound1Msg) -> tecdsa_core::Result<()> {
        if from == self.config.my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }
        if !self.config.signer_parties.contains(&from) {
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
        let ek = &self.config.key_share.threshold_setup.ek;

        let statement = HomoMultStatement {
            c1: self.u_i.clone(),
            c2: self.config.key_share.alpha.clone(),
            c3: self.v_i.clone(),
            ek_n: ek.n().clone(),
            ek_nn: ek.nn().clone(),
            h1: self.config.key_share.h1.clone(),
            h2: self.config.key_share.h2.clone(),
            N_tilde: self.config.key_share.N_tilde.clone(),
        };
        let witness = HomoMultWitness {
            eta: self.rho_i.clone(),
            r_c1: self.r_u.clone(),
            r_c3: self.r_v.clone(),
        };
        let proof = HomoMultProof::prove::<C>(&witness, &statement, rng);

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Ggn16SignMsg::Round2(SignRound2Msg {
                u_i: self.u_i.clone(),
                v_i: self.v_i.clone(),
                nonce: self.decommit_nonce,
                homo_mult_proof: proof.to_bytes(),
            }),
        }];

        self.r_u = Integer::from(0u32);
        self.r_v = Integer::from(0u32);

        Round2State {
            config: self.config,
            rho_i: self.rho_i,
            u_i: self.u_i,
            v_i: self.v_i,
            round1_commitments: self.round1_msgs,
            outgoing,
            round2_msgs: BTreeMap::new(),
        }
    }
}

#[allow(dead_code)]
pub(crate) struct Round2State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub config: PresignConfig<C>,
    pub rho_i: Integer,
    pub u_i: Integer,
    pub v_i: Integer,
    pub round1_commitments: BTreeMap<PartyId, SignRound1Msg>,
    pub outgoing: Vec<Outgoing<Ggn16SignMsg>>,
    pub round2_msgs: BTreeMap<PartyId, SignRound2Msg>,
}

impl<C: TecdsaCurve> Round2State<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    fn expected_count(&self) -> usize {
        self.config.signer_parties.len() - 1
    }

    pub fn handle(&mut self, from: PartyId, msg: SignRound2Msg) -> tecdsa_core::Result<()> {
        if from == self.config.my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }
        if !self.config.signer_parties.contains(&from) {
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

    pub fn advance(mut self, rng: &mut impl CryptoRngCore) -> tecdsa_core::Result<Round3State<C>> {
        let ek = &self.config.key_share.threshold_setup.ek;

        let mut u = self.u_i.clone();
        let mut v = self.v_i.clone();

        for pid in &self.config.signer_parties {
            if *pid == self.config.my_id {
                continue;
            }
            let r2 = self.round2_msgs.get(pid).ok_or_else(|| {
                TecdsaError::Other(format!("missing round2 message from party {pid}"))
            })?;
            let r1 = self.round1_commitments.get(pid).ok_or_else(|| {
                TecdsaError::Other(format!("missing round1 commitment from party {pid}"))
            })?;

            let commit_data = serialize_for_commit_r1(&r2.u_i, &r2.v_i);
            if !r1.commitment.verify(&commit_data, &r2.nonce) {
                return Err(TecdsaError::InvalidCommitment(format!(
                    "party {pid} round 1 commitment verification failed"
                )));
            }

            let proof = HomoMultProof::from_bytes(&r2.homo_mult_proof).ok_or_else(|| {
                TecdsaError::Other(format!("party {pid} sent malformed HomoMultProof"))
            })?;
            let statement = HomoMultStatement {
                c1: r2.u_i.clone(),
                c2: self.config.key_share.alpha.clone(),
                c3: r2.v_i.clone(),
                ek_n: ek.n().clone(),
                ek_nn: ek.nn().clone(),
                h1: self.config.key_share.h1.clone(),
                h2: self.config.key_share.h2.clone(),
                N_tilde: self.config.key_share.N_tilde.clone(),
            };
            proof.verify::<C>(&statement).map_err(|e| {
                TecdsaError::Other(format!(
                    "party {pid} HomoMultProof verification failed: {e}"
                ))
            })?;

            u = ek
                .oadd(&u, &r2.u_i)
                .map_err(|e| TecdsaError::Other(format!("oadd u failed: {e}")))?;
            v = ek
                .oadd(&v, &r2.v_i)
                .map_err(|e| TecdsaError::Other(format!("oadd v failed: {e}")))?;
        }

        let q = group_order_integer::<C>();

        let k_i_scalar = C::random_scalar(rng);
        let k_i = scalar_to_integer::<C>(&k_i_scalar);

        let r_i = C::generator() * k_i_scalar;
        let r_i_bytes: Vec<u8> = r_i.to_bytes().as_ref().to_vec();

        let c_i_bound = &q * &q;
        let c_i = c_i_bound.random_below_ref(rng);

        let ki_times_u = ek
            .omul(&k_i, &u)
            .map_err(|e| TecdsaError::Other(format!("omul k_i*u failed: {e}")))?;
        let c_i_q = &c_i * &q;
        let (enc_ciq, enc_nonce) = ek
            .encrypt_with_random(rng, &c_i_q)
            .map_err(|e| TecdsaError::Other(format!("encrypt c_i*q failed: {e}")))?;
        let w_i = ek
            .oadd(&ki_times_u, &enc_ciq)
            .map_err(|e| TecdsaError::Other(format!("oadd w_i failed: {e}")))?;

        let commit_data = serialize_for_commit_r3(&r_i_bytes, &w_i);
        let (hash_commitment, decommit_nonce) = HashCommitment::commit(&commit_data, rng);

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Ggn16SignMsg::Round3(SignRound3Msg {
                commitment: hash_commitment,
            }),
        }];

        self.rho_i = Integer::from(0u32);

        Ok(Round3State {
            config: self.config,
            u,
            v,
            k_i_scalar,
            k_i,
            c_i,
            r_w: enc_nonce,
            r_i,
            r_i_bytes,
            w_i,
            decommit_nonce,
            outgoing,
            round3_msgs: BTreeMap::new(),
        })
    }
}

#[allow(dead_code)]
pub(crate) struct Round3State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub config: PresignConfig<C>,

    pub u: Integer,
    pub v: Integer,

    pub k_i_scalar: C::Scalar,
    pub k_i: Integer,
    pub c_i: Integer,
    pub r_w: Integer,
    pub r_i: C::ProjectivePoint,
    pub r_i_bytes: Vec<u8>,
    pub w_i: Integer,
    pub decommit_nonce: [u8; 32],

    pub outgoing: Vec<Outgoing<Ggn16SignMsg>>,
    pub round3_msgs: BTreeMap<PartyId, SignRound3Msg>,
}

impl<C: TecdsaCurve> Round3State<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    fn expected_count(&self) -> usize {
        self.config.signer_parties.len() - 1
    }

    pub fn handle(&mut self, from: PartyId, msg: SignRound3Msg) -> tecdsa_core::Result<()> {
        if from == self.config.my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }
        if !self.config.signer_parties.contains(&from) {
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

    pub fn advance(mut self, rng: &mut impl CryptoRngCore) -> Round4State<C> {
        let ek = &self.config.key_share.threshold_setup.ek;

        let statement = NonceConsistStatement::<C> {
            G: C::generator(),
            r_i: self.r_i,
            w_i: self.w_i.clone(),
            u: self.u.clone(),
            ek_n: ek.n().clone(),
            ek_nn: ek.nn().clone(),
            h1: self.config.key_share.h1.clone(),
            h2: self.config.key_share.h2.clone(),
            N_tilde: self.config.key_share.N_tilde.clone(),
        };
        let witness = NonceConsistWitness {
            eta1: self.k_i.clone(),
            eta2: self.c_i.clone(),
            r_c: self.r_w.clone(),
        };
        let proof = NonceConsistProof::<C>::prove(&witness, &statement, rng);

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Ggn16SignMsg::Round4(SignRound4Msg {
                r_i_bytes: self.r_i_bytes.clone(),
                w_i: self.w_i.clone(),
                nonce: self.decommit_nonce,
                nonce_consist_proof: proof.to_bytes(),
            }),
        }];

        self.k_i_scalar.zeroize();
        self.k_i = Integer::from(0u32);
        self.c_i = Integer::from(0u32);
        self.r_w = Integer::from(0u32);

        Round4State {
            config: self.config,
            u: self.u,
            v: self.v,
            r_i: self.r_i,
            r_i_bytes: self.r_i_bytes,
            w_i: self.w_i,
            round3_commitments: self.round3_msgs,
            outgoing,
            round4_msgs: BTreeMap::new(),
        }
    }
}

#[allow(dead_code)]
pub(crate) struct Round4State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub config: PresignConfig<C>,

    pub u: Integer,
    pub v: Integer,

    pub r_i: C::ProjectivePoint,
    pub r_i_bytes: Vec<u8>,
    pub w_i: Integer,

    pub round3_commitments: BTreeMap<PartyId, SignRound3Msg>,
    pub outgoing: Vec<Outgoing<Ggn16SignMsg>>,
    pub round4_msgs: BTreeMap<PartyId, SignRound4Msg>,
}

impl<C: TecdsaCurve> Round4State<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    fn expected_count(&self) -> usize {
        self.config.signer_parties.len() - 1
    }

    pub fn handle(&mut self, from: PartyId, msg: SignRound4Msg) -> tecdsa_core::Result<()> {
        if from == self.config.my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }
        if !self.config.signer_parties.contains(&from) {
            return Err(TecdsaError::UnknownSender(from.0));
        }
        if self.round4_msgs.contains_key(&from) {
            return Err(TecdsaError::DuplicateMessage(from.0));
        }
        self.round4_msgs.insert(from, msg);
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.round4_msgs.len() == self.expected_count()
    }

    pub fn advance(self) -> tecdsa_core::Result<Round5State<C>> {
        let ek = &self.config.key_share.threshold_setup.ek;
        let setup = &self.config.key_share.threshold_setup;

        let mut R = self.r_i;
        let mut w = self.w_i.clone();

        for pid in &self.config.signer_parties {
            if *pid == self.config.my_id {
                continue;
            }
            let r4 = self.round4_msgs.get(pid).ok_or_else(|| {
                TecdsaError::Other(format!("missing round4 message from party {pid}"))
            })?;
            let r3 = self.round3_commitments.get(pid).ok_or_else(|| {
                TecdsaError::Other(format!("missing round3 commitment from party {pid}"))
            })?;

            let commit_data = serialize_for_commit_r3(&r4.r_i_bytes, &r4.w_i);
            if !r3.commitment.verify(&commit_data, &r4.nonce) {
                return Err(TecdsaError::InvalidCommitment(format!(
                    "party {pid} round 3 commitment verification failed"
                )));
            }

            let r_j = deserialize_point::<C>(&r4.r_i_bytes).map_err(|_| {
                TecdsaError::Other(format!("party {pid} sent invalid r_i point encoding"))
            })?;

            let proof =
                NonceConsistProof::<C>::from_bytes(&r4.nonce_consist_proof).ok_or_else(|| {
                    TecdsaError::Other(format!("party {pid} sent malformed NonceConsistProof"))
                })?;
            let nc_statement = NonceConsistStatement::<C> {
                G: C::generator(),
                r_i: r_j,
                w_i: r4.w_i.clone(),
                u: self.u.clone(),
                ek_n: ek.n().clone(),
                ek_nn: ek.nn().clone(),
                h1: self.config.key_share.h1.clone(),
                h2: self.config.key_share.h2.clone(),
                N_tilde: self.config.key_share.N_tilde.clone(),
            };
            proof.verify(&nc_statement).map_err(|e| {
                TecdsaError::Other(format!(
                    "party {pid} NonceConsistProof verification failed: {e}"
                ))
            })?;

            R += r_j;
            w = ek
                .oadd(&w, &r4.w_i)
                .map_err(|e| TecdsaError::Other(format!("oadd w failed: {e}")))?;
        }

        let R_affine = R.to_affine();
        let r = C::xcoord_mod_q(&R_affine);

        let my_partial = partial_decrypt(&w, &self.config.key_share.decryption_share, setup);

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Ggn16SignMsg::Round5(SignRound5Msg {
                partial_w: my_partial.clone(),
            }),
        }];

        Ok(Round5State {
            config: self.config,
            u: self.u,
            v: self.v,
            R,
            r,
            w,
            my_partial,
            outgoing,
            round5_msgs: BTreeMap::new(),
        })
    }
}

#[allow(dead_code)]
pub(crate) struct Round5State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub config: PresignConfig<C>,

    pub u: Integer,
    pub v: Integer,
    pub R: C::ProjectivePoint,
    pub r: C::Scalar,
    pub w: Integer,

    pub my_partial: PartialDecryption,

    pub outgoing: Vec<Outgoing<Ggn16SignMsg>>,
    pub round5_msgs: BTreeMap<PartyId, SignRound5Msg>,
}

impl<C: TecdsaCurve> Round5State<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    fn expected_count(&self) -> usize {
        self.config.signer_parties.len() - 1
    }

    pub fn handle(&mut self, from: PartyId, msg: SignRound5Msg) -> tecdsa_core::Result<()> {
        if from == self.config.my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }
        if !self.config.signer_parties.contains(&from) {
            return Err(TecdsaError::UnknownSender(from.0));
        }
        if self.round5_msgs.contains_key(&from) {
            return Err(TecdsaError::DuplicateMessage(from.0));
        }
        self.round5_msgs.insert(from, msg);
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.round5_msgs.len() == self.expected_count()
    }

    pub fn finish(self) -> tecdsa_core::Result<Ggn16Presignature<C>> {
        let setup = &self.config.key_share.threshold_setup;

        let mut partials = vec![self.my_partial];
        for pid in &self.config.signer_parties {
            if *pid == self.config.my_id {
                continue;
            }
            let r5 = self.round5_msgs.get(pid).ok_or_else(|| {
                TecdsaError::Other(format!("missing round5 message from party {pid}"))
            })?;
            partials.push(r5.partial_w.clone());
        }

        let eta = combine_partials(&partials, setup)
            .map_err(|e| TecdsaError::Other(format!("threshold decryption of w failed: {e}")))?;

        let q = group_order_integer::<C>();
        let eta_mod_q = eta.modulo_ref(&q);

        let eta_scalar = integer_to_scalar::<C>(&eta_mod_q);
        let psi = eta_scalar
            .invert()
            .into_option()
            .ok_or_else(|| TecdsaError::Other("eta is zero, cannot invert for psi".into()))?;

        Ok(Ggn16Presignature {
            psi,
            u: self.u,
            v: self.v,
            R: self.R,
            r: self.r,
            key_share: self.config.key_share,
            my_id: self.config.my_id,
            signer_parties: self.config.signer_parties,
        })
    }
}
