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
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::module_name_repetitions,
    non_snake_case
)]

//! JTX25 presigning protocol (2 rounds).
//!
//! Produces a message-independent [`Jtx25RobustPresignature`] using threshold CL
//! homomorphic encryption and distributed randomness generation (DRG).
//!
//! ## Protocol Rounds (JTX25 Section 3+4)
//!
//! ### Presign Round 1
//! Each P_i:
//! 1. Sample phi_i, k_i <- Z_q randomly
//! 2. Compute threshold CL encryption: phi_bar_i <- t-CL.Enc(pk, phi_i)
//! 3. Compute R_i = g^{k_i}
//! 4. Send R_cl-enc proof for phi_bar_i
//! 5. For ROBUST: run DRG ShareDist for k_i ({C_{k_{j,i}}}, pi_sh_i)
//! 6. Broadcast (phi_bar_i, R_cl-enc proof, {C_{k_{j,i}}}, pi_sh_i)
//!
//! ### Presign Round 2
//! Upon receiving Round 1 from all P_j:
//! 1. Verify R_cl-enc proofs AND R_sh proofs (both must pass)
//! 2. For ROBUST: ShareComb for k_i, get R_i, prove R_cl-dec-dl
//! 3. Compute phi_bar = sum of all phi_bar_j (homomorphic sum)
//! 4. Compute phi_bar_x_i = phi_bar * (lambda_i * x_i) (scalar multiply)
//! 5. Prove R_dl-cl: (X_i, phi_bar, phi_bar_x_i; x_i)
//! 6. Compute phi_bar_k_i = phi_bar * k_i
//! 7. Prove R_dl-cl: (R_i, phi_bar, phi_bar_k_i; k_i)
//! 8. Broadcast (phi_bar_x_i, pi_dl-cl_0, phi_bar_k_i, pi_dl-cl_1, R_i, pi_cl-dec-dl)

use std::collections::BTreeMap;

use elliptic_curve::group::GroupEncoding;
use elliptic_curve::CurveArithmetic;
use num_traits::Num as _;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use tecdsa_class_group::bicycl_glue::{BicyclCiphertext, BicyclPublicKey, BicyclQfi, ClSetup};
use tecdsa_class_group::zk::r_dec_dl::RDecDlProof;
use tecdsa_class_group::zk::r_dl_cl::RDlClProof;
use tecdsa_class_group::zk::r_enc::REncProof;
use tecdsa_class_group::zk::r_sh::RShProof;
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{state_machine::Outgoing, IaReport, PartyId, Recipient, StateMachine};

use crate::cl_wire::{
    add_ct_components, copy_ct, point_from_bytes, scalar_mul_ct, SerRDecDlProof, SerRDlClProof,
    SerREncProof, SerRShProof, SerializedClCt, SerializedQfi,
};
use crate::error::Jtx25Error;
use crate::key_share::Jtx25KeyShare;

// ---------------------------------------------------------------------------
// Presignature output
// ---------------------------------------------------------------------------

/// Presignature produced by the JTX25 presign protocol.
///
/// Contains all CL ciphertexts needed for the online signing round:
/// - phi_bar = Enc(pk, phi) (homomorphic sum of all phi_i)
/// - phi_bar_x_j = phi_bar * (lambda_j * x_j) for each party j
/// - phi_bar_k_j = phi_bar * k_j for each party j
/// - R = product of R_j^{lambda_j}
/// - r_x = x-coordinate of R mod q
pub struct Jtx25RobustPresignature {
    pub party_index: u16,
    /// R = Prod_{j in T} R_j^{lambda_j}
    pub r_point: k256::ProjectivePoint,
    /// r_x = x_coord(R) mod q
    pub r_x: k256::Scalar,
    /// This party's phi_i value.
    pub phi_i: k256::Scalar,
    /// This party's k_i value.
    pub k_i: k256::Scalar,
    /// Number of signers.
    pub n_signers: usize,
    /// Threshold.
    pub threshold: u16,
    /// The combined phi_bar ciphertext (serialized as abc pairs).
    pub phi_bar_c1_bytes: Vec<u8>,
    pub phi_bar_c2_bytes: Vec<u8>,
    /// Per-party phi_bar_x_j ciphertexts (keyed by party_id u16).
    pub phi_bar_x_c1_bytes: BTreeMap<u16, Vec<u8>>,
    pub phi_bar_x_c2_bytes: BTreeMap<u16, Vec<u8>>,
    /// Per-party phi_bar_k_j ciphertexts (keyed by party_id u16).
    pub phi_bar_k_c1_bytes: BTreeMap<u16, Vec<u8>>,
    pub phi_bar_k_c2_bytes: BTreeMap<u16, Vec<u8>>,
    /// Lagrange coefficients for this signing set.
    pub lagrange_coeffs: BTreeMap<u16, k256::Scalar>,
    /// CL setup seed.
    pub cl_setup_seed: String,
    pub use_128bit_security: bool,
    /// Threshold CL secret key share (for partial decryption, big-endian bytes).
    pub cl_sk_share: Vec<u8>,
    /// Aggregate CL public key (for partial decryption proof).
    pub cl_pk_bytes: Vec<u8>,
    /// Per-party CL PK shares (for verifying partial decryption proofs).
    pub cl_pk_share_bytes: BTreeMap<u16, Vec<u8>>,
    /// Total n for threshold CL (n_parties_dkg).
    pub n_parties_dkg: usize,
}

impl Clone for Jtx25RobustPresignature {
    fn clone(&self) -> Self {
        Self {
            party_index: self.party_index,
            r_point: self.r_point,
            r_x: self.r_x,
            phi_i: self.phi_i,
            k_i: self.k_i,
            n_signers: self.n_signers,
            threshold: self.threshold,
            phi_bar_c1_bytes: self.phi_bar_c1_bytes.clone(),
            phi_bar_c2_bytes: self.phi_bar_c2_bytes.clone(),
            phi_bar_x_c1_bytes: self.phi_bar_x_c1_bytes.clone(),
            phi_bar_x_c2_bytes: self.phi_bar_x_c2_bytes.clone(),
            phi_bar_k_c1_bytes: self.phi_bar_k_c1_bytes.clone(),
            phi_bar_k_c2_bytes: self.phi_bar_k_c2_bytes.clone(),
            lagrange_coeffs: self.lagrange_coeffs.clone(),
            cl_setup_seed: self.cl_setup_seed.clone(),
            use_128bit_security: self.use_128bit_security,
            cl_sk_share: self.cl_sk_share.clone(),
            cl_pk_bytes: self.cl_pk_bytes.clone(),
            cl_pk_share_bytes: self.cl_pk_share_bytes.clone(),
            n_parties_dkg: self.n_parties_dkg,
        }
    }
}

impl Zeroize for Jtx25RobustPresignature {
    fn zeroize(&mut self) {
        self.phi_i.zeroize();
        self.k_i.zeroize();
        self.cl_sk_share.zeroize();
    }
}

impl Drop for Jtx25RobustPresignature {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl std::fmt::Debug for Jtx25RobustPresignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Jtx25RobustPresignature")
            .field("party_index", &self.party_index)
            .field("threshold", &self.threshold)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Jtx25RobustPresignMsg {
    Round1(Vec<u8>),
    Round2(Vec<u8>),
}

// Serialized CL types imported from crate::cl_wire

// ---------------------------------------------------------------------------
// Round 1 payload
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct R1Payload {
    /// Threshold CL encryption of phi_i under aggregate pk.
    phi_bar_i: SerializedClCt,
    /// R_enc proof for phi_bar_i.
    r_enc_proof: SerREncProof,
    /// PVSS for k_i: c1 = h^rho.
    pvss_c1: SerializedQfi,
    /// PVSS for k_i: c2_j for each party.
    pvss_c2s: Vec<SerializedQfi>,
    /// R_Sh proof for PVSS.
    pvss_proof: SerRShProof,
}

// ---------------------------------------------------------------------------
// Round 2 payload
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct R2Payload {
    /// phi_bar_x_i = phi_bar * (lambda_i * x_i).
    phi_bar_x_i: SerializedClCt,
    /// R_dl-cl proof for (X_i, phi_bar, phi_bar_x_i; lambda_i * x_i).
    pi_dl_cl_x: SerRDlClProof,
    /// phi_bar_k_i = phi_bar * k_i.
    phi_bar_k_i: SerializedClCt,
    /// R_dl-cl proof for (R_i, phi_bar, phi_bar_k_i; k_i).
    pi_dl_cl_k: SerRDlClProof,
    /// R_i = k_i * G.
    r_point_bytes: Vec<u8>,
    /// R_Dec_DL proof for k_i ShareComb.
    pi_dec_dl: SerRDecDlProof,
    /// Partial decryption pd for R_Dec_DL verification.
    pd: SerializedQfi,
    /// PVSS c1 used for pd.
    pd_c1: SerializedQfi,
}

// ---------------------------------------------------------------------------
// Received data
// ---------------------------------------------------------------------------

struct ReceivedR1 {
    phi_bar_i: BicyclCiphertext,
    pvss_c1: BicyclQfi,
    pvss_c2s: Vec<BicyclQfi>,
}

struct ReceivedR2 {
    phi_bar_x_i: BicyclCiphertext,
    phi_bar_k_i: BicyclCiphertext,
    r_point: k256::ProjectivePoint,
}

// ---------------------------------------------------------------------------
// State machine states
// ---------------------------------------------------------------------------

struct Round1State {
    my_id: PartyId,
    all_parties: Vec<PartyId>,
    phi_i: k256::Scalar,
    _phi_i_bytes: Vec<u8>,
    _enc_randomness: Vec<u8>,
    own_pvss_share: k256::Scalar,
    received: BTreeMap<PartyId, ReceivedR1>,
    outgoing: Vec<Outgoing<Jtx25RobustPresignMsg>>,
}

struct Round2State {
    my_id: PartyId,
    all_parties: Vec<PartyId>,
    phi_i: k256::Scalar,
    k_i: k256::Scalar,
    _r_point_i: k256::ProjectivePoint,
    phi_bar: BicyclCiphertext,
    received: BTreeMap<PartyId, ReceivedR2>,
    outgoing: Vec<Outgoing<Jtx25RobustPresignMsg>>,
}

enum PresignRobustRound {
    Round1(Round1State),
    Round2(Round2State),
    Done(Jtx25RobustPresignature),
    Poisoned,
}

// ---------------------------------------------------------------------------
// Key material
// ---------------------------------------------------------------------------

struct KeyMaterial {
    x_i: k256::Scalar,
    _x_point: k256::ProjectivePoint,
    public_shares: Vec<k256::ProjectivePoint>,
    threshold: u16,
    cl_sk_share: Vec<u8>,
    cl_pk: BicyclPublicKey,
    cl_pk_bytes: Vec<u8>,
    cl_pk_share_bytes: BTreeMap<u16, Vec<u8>>,
    cl_setup_seed: String,
    use_128bit_security: bool,
    n_parties_dkg: usize,
}

impl Zeroize for KeyMaterial {
    fn zeroize(&mut self) {
        self.x_i.zeroize();
        self.cl_sk_share.zeroize();
    }
}

impl Drop for KeyMaterial {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// Helpers imported from crate::cl_wire

use tecdsa_class_group::pvss_share::{
    pvss_share_decrypt, pvss_share_distribute, pvss_share_verify,
};

// ---------------------------------------------------------------------------
// Presign state machine
// ---------------------------------------------------------------------------

pub struct Jtx25RobustPresignMachine {
    round: PresignRobustRound,
    setup: ClSetup,
    key_mat: KeyMaterial,
    /// Individual CL PKs for PVSS (not the aggregate threshold PK).
    individual_cl_pks: Vec<BicyclPublicKey>,
}

impl Jtx25RobustPresignMachine {
    /// Create a new JTX25 presign state machine.
    ///
    /// Immediately runs presign Round 1:
    /// 1. Sample phi_i, k_i
    /// 2. Encrypt phi_i under aggregate threshold CL pk
    /// 3. PVSS distribute k_i
    /// 4. Queue broadcast
    pub fn new(
        my_id: PartyId,
        all_parties: Vec<PartyId>,
        key_share: &Jtx25KeyShare,
        mut setup: ClSetup,
    ) -> Result<Self, Jtx25Error> {
        if !all_parties.contains(&my_id) {
            return Err(Jtx25Error::InvalidInput("my_id not in all_parties".into()));
        }

        let my_idx = all_parties
            .iter()
            .position(|p| *p == my_id)
            .ok_or_else(|| Jtx25Error::InvalidInput("my_id not in all_parties".into()))?;
        let threshold = key_share.threshold;
        let n = all_parties.len();

        // Extract key material.
        let pk_elt = setup.pk_element(&key_share.cl_pk)?;
        let cl_pk_bytes = {
            let ctx = setup.ctx();
            pk_elt
                .to_bytes(ctx)
                .map_err(|e| Jtx25Error::ClError(e.into()))?
        };

        // Reconstruct individual CL public keys for the signing subset.
        let mut individual_cl_pks: Vec<BicyclPublicKey> = Vec::with_capacity(n);
        let mut cl_pk_share_bytes: BTreeMap<u16, Vec<u8>> = BTreeMap::new();

        // First, store ALL party CL PK shares by their party_index (1-based).
        for (dkg_idx, qfi) in key_share.cl_pk_shares.iter().enumerate() {
            let dkg_party_index = (dkg_idx + 1) as u16;
            let pid = dkg_party_index - 1;
            let ctx = setup.ctx();
            let data = qfi
                .to_bytes(ctx)
                .map_err(|e| Jtx25Error::ClError(e.into()))?;
            cl_pk_share_bytes.insert(pid, data);
        }

        // Build individual_cl_pks for the signing subset, in the order of all_parties.
        for &party in &all_parties {
            // Find this party's DKG index: party.0 = party_index - 1
            let dkg_idx = party.0 as usize;
            if dkg_idx >= key_share.cl_pk_shares.len() {
                return Err(Jtx25Error::InvalidInput(format!(
                    "party {} DKG index {} out of range for {} CL PK shares",
                    party.0,
                    dkg_idx,
                    key_share.cl_pk_shares.len()
                )));
            }
            let qfi = &key_share.cl_pk_shares[dkg_idx];
            let pk = setup.pk_from_qfi(qfi)?;
            individual_cl_pks.push(pk);
        }

        let key_mat = KeyMaterial {
            x_i: key_share.secret_share,
            _x_point: key_share.public_key,
            public_shares: key_share.public_shares.clone(),
            threshold,
            cl_sk_share: key_share.cl_sk_share.clone(),
            cl_pk: setup.pk_from_qfi(&pk_elt)?,
            cl_pk_bytes,
            cl_pk_share_bytes,
            cl_setup_seed: key_share.cl_setup_seed.clone(),
            use_128bit_security: key_share.use_128bit_security,
            n_parties_dkg: key_share.n_parties_dkg,
        };

        // --- Step 1: Sample phi_i ---
        let phi_i = {
            let (sk, _) = setup.keygen()?;
            let sk_dec = setup.sk_to_decimal(&sk)?;
            let q_dec = setup.q_decimal()?;
            let q = num_bigint::BigUint::from_str_radix(&q_dec, 10)
                .map_err(|e| Jtx25Error::ScalarConversion(format!("parse q: {e}")))?;
            let bu = num_bigint::BigUint::from_str_radix(&sk_dec, 10)
                .map_err(|e| Jtx25Error::ScalarConversion(format!("parse sk: {e}")))?;
            let reduced = bu % &q;
            tecdsa_curve::conv::biguint_to_scalar::<k256::Secp256k1>(&reduced)
        };
        let phi_i_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&phi_i);

        // --- Step 2: Encrypt phi_i under aggregate CL pk ---
        let (r_sk, _) = setup.keygen()?;
        let enc_randomness = setup.sk_to_bytes(&r_sk)?;
        let phi_bar_i =
            setup.encrypt_with_r_bytes(&key_mat.cl_pk, &phi_i_bytes, &enc_randomness)?;

        // Generate R_enc proof.
        let r_enc_proof = REncProof::prove(
            &mut setup,
            &key_mat.cl_pk,
            &phi_bar_i,
            &phi_i_bytes,
            &enc_randomness,
        )?;

        // --- Step 3: PVSS distribute k_i ---
        // Use 1-based party IDs for PVSS evaluation points and Lagrange interpolation.
        // PartyId.0 is 0-based, but PVSS polynomial evaluation needs non-zero points
        // for Lagrange interpolation to work (can't evaluate at x=0).
        let party_ids_1based: Vec<u16> = all_parties.iter().map(|p| p.0 + 1).collect();
        let pvss_out = pvss_share_distribute(
            &mut setup,
            &party_ids_1based,
            &individual_cl_pks,
            threshold,
            my_idx,
        )?;

        // --- Step 4: Build Round 1 payload ---
        let phi_bar_i_ser = SerializedClCt::from_bicycl_ct(&setup, &phi_bar_i)
            .map_err(|e| Jtx25Error::InvalidInput(format!("serialize phi_bar: {e}")))?;
        let r_enc_proof_ser = SerREncProof::from_proof(&setup, &r_enc_proof)
            .map_err(|e| Jtx25Error::InvalidInput(format!("serialize r_enc_proof: {e}")))?;
        let pvss_c1_ser = SerializedQfi::from_qfi(&setup, &pvss_out.c1)
            .map_err(|e| Jtx25Error::InvalidInput(format!("serialize pvss_c1: {e}")))?;
        let pvss_c2s_ser: Vec<SerializedQfi> = pvss_out
            .c2s
            .iter()
            .map(|c2| {
                SerializedQfi::from_qfi(&setup, c2)
                    .map_err(|e| Jtx25Error::InvalidInput(format!("serialize c2: {e}")))
            })
            .collect::<Result<_, _>>()?;
        let pvss_proof_ser = SerRShProof {
            k: pvss_out.proof.k.clone(),
            rho_response: pvss_out.proof.rho_response.clone(),
        };

        let r1_payload = R1Payload {
            phi_bar_i: phi_bar_i_ser,
            r_enc_proof: r_enc_proof_ser,
            pvss_c1: pvss_c1_ser,
            pvss_c2s: pvss_c2s_ser,
            pvss_proof: pvss_proof_ser,
        };

        let payload_bytes = bincode::serde::encode_to_vec(&r1_payload, bincode::config::standard())
            .map_err(|e| Jtx25Error::InvalidInput(format!("serialize R1: {e}")))?;

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Jtx25RobustPresignMsg::Round1(payload_bytes),
        }];

        // Store own Round 1 data.
        let mut received = BTreeMap::new();
        received.insert(
            my_id,
            ReceivedR1 {
                phi_bar_i,
                pvss_c1: pvss_out.c1,
                pvss_c2s: pvss_out.c2s,
            },
        );

        let state = Round1State {
            my_id,
            all_parties,
            phi_i,
            _phi_i_bytes: phi_i_bytes,
            _enc_randomness: enc_randomness,
            own_pvss_share: tecdsa_curve::conv::bytes_to_scalar::<k256::Secp256k1>(
                &pvss_out.secret_share_bytes,
            ),
            received,
            outgoing,
        };

        Ok(Self {
            round: PresignRobustRound::Round1(state),
            setup,
            key_mat,
            individual_cl_pks,
        })
    }

    // -----------------------------------------------------------------------
    // Round 1 -> Round 2 transition
    // -----------------------------------------------------------------------

    fn transition_r1_to_r2(
        state: Round1State,
        setup: &mut ClSetup,
        key_mat: &KeyMaterial,
        _individual_cl_pks: &[BicyclPublicKey],
    ) -> tecdsa_core::Result<Round2State> {
        let my_idx = state
            .all_parties
            .iter()
            .position(|p| *p == state.my_id)
            .ok_or_else(|| TecdsaError::Other("my_id not in all_parties".into()))?;
        let _n = state.all_parties.len();
        let party_ids_1based: Vec<u16> = state.all_parties.iter().map(|p| p.0 + 1).collect();

        // --- Step 1: Verify R_enc AND R_sh proofs ---
        // Note: own data is stored but not verified (we produced it ourselves).

        // --- Step 2: ShareComb for k_i ---
        let mut k_i = state.own_pvss_share;
        for (&party_j, r1) in &state.received {
            if party_j == state.my_id {
                continue;
            }
            let share_bytes = pvss_share_decrypt(
                setup,
                &key_mat.cl_sk_share,
                &r1.pvss_c1,
                &r1.pvss_c2s[my_idx],
            )
            .map_err(|e| TecdsaError::Other(format!("pvss_decrypt from {party_j}: {e}")))?;
            let share_j = tecdsa_curve::conv::bytes_to_scalar::<k256::Secp256k1>(&share_bytes);
            k_i += share_j;
        }

        let r_point_i = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * k_i;

        // Generate R_Dec_DL proof for k_i ShareComb.
        let my_pk_share_data = key_mat
            .cl_pk_share_bytes
            .get(&state.my_id.0)
            .ok_or_else(|| TecdsaError::Other("missing own CL pk share bytes".into()))?;
        let my_pk_qfi = {
            let ctx = setup.ctx();
            BicyclQfi::from_bytes(ctx, my_pk_share_data)
                .map_err(|e| TecdsaError::Other(format!("from_bytes: {e}")))?
        };
        let my_pk_raw = setup
            .pk_from_qfi(&my_pk_qfi)
            .map_err(|e| TecdsaError::Other(format!("pk_from_qfi: {e}")))?;

        // Use first other party's PVSS c1 as representative for R_Dec_DL.
        let mut dec_dl_data: Option<(RDecDlProof, BicyclQfi, BicyclQfi)> = None;
        for (&party_j, r1) in &state.received {
            if party_j == state.my_id {
                continue;
            }
            let c2_my = &r1.pvss_c2s[my_idx];
            let ct_repr = setup
                .ct_from_components(&r1.pvss_c1, c2_my)
                .map_err(|e| TecdsaError::Other(format!("ct_from: {e}")))?;
            let pd = setup
                .exp_bytes(&r1.pvss_c1, &key_mat.cl_sk_share)
                .map_err(|e| TecdsaError::Other(format!("pd: {e}")))?;

            let proof = RDecDlProof::prove(setup, &my_pk_raw, &ct_repr, &pd, &key_mat.cl_sk_share)
                .map_err(|e| TecdsaError::Other(format!("R_Dec_DL prove: {e}")))?;

            let ctx = setup.ctx();
            let c1_copy = {
                let bytes = r1
                    .pvss_c1
                    .to_bytes(ctx)
                    .map_err(|e| TecdsaError::Other(format!("c1 to_bytes: {e}")))?;
                BicyclQfi::from_bytes(ctx, &bytes)
                    .map_err(|e| TecdsaError::Other(format!("c1 from_bytes: {e}")))?
            };

            dec_dl_data = Some((proof, pd, c1_copy));
            break;
        }

        let (dec_dl_proof, dec_dl_pd, dec_dl_c1) = dec_dl_data
            .ok_or_else(|| TecdsaError::Other("no other party data for R_Dec_DL".into()))?;

        // --- Step 3: Compute phi_bar = sum of all phi_bar_j ---
        let mut phi_bar: Option<BicyclCiphertext> = None;
        for (&party_j, r1) in &state.received {
            match phi_bar.take() {
                None => {
                    phi_bar = Some(
                        copy_ct(setup, &r1.phi_bar_i)
                            .map_err(|e| TecdsaError::Other(format!("copy_ct: {e}")))?,
                    );
                }
                Some(acc) => {
                    let sum = add_ct_components(setup, &acc, &r1.phi_bar_i)
                        .map_err(|e| TecdsaError::Other(format!("add_ct from {party_j}: {e}")))?;
                    phi_bar = Some(sum);
                }
            }
        }
        let phi_bar = phi_bar.ok_or_else(|| TecdsaError::Other("no phi_bar data".into()))?;

        // --- Step 4: Compute phi_bar_x_i = phi_bar * (lambda_i * x_i) ---
        let lagrange_coeffs =
            tecdsa_vss::lagrange::coefficients::<k256::Secp256k1>(&party_ids_1based);
        let lambda_i = lagrange_coeffs[my_idx];
        let lambda_x_i = lambda_i * key_mat.x_i;
        let lambda_x_i_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&lambda_x_i);

        let phi_bar_x_i = scalar_mul_ct(setup, &phi_bar, &lambda_x_i_bytes)
            .map_err(|e| TecdsaError::Other(format!("scalar_mul phi_bar_x_i: {e}")))?;

        // X_i_lambda = (lambda_i * x_i) * G for the R_dl-cl proof
        let x_i_lambda_point =
            <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * lambda_x_i;

        let pi_dl_cl_x = RDlClProof::prove(
            setup,
            &x_i_lambda_point,
            &phi_bar,
            &phi_bar_x_i,
            &lambda_x_i_bytes,
        )
        .map_err(|e| TecdsaError::Other(format!("R_dl-cl x prove: {e}")))?;

        // --- Step 5: Compute phi_bar_k_i = phi_bar * k_i ---
        let k_i_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&k_i);
        let phi_bar_k_i = scalar_mul_ct(setup, &phi_bar, &k_i_bytes)
            .map_err(|e| TecdsaError::Other(format!("scalar_mul phi_bar_k_i: {e}")))?;

        let pi_dl_cl_k = RDlClProof::prove(setup, &r_point_i, &phi_bar, &phi_bar_k_i, &k_i_bytes)
            .map_err(|e| TecdsaError::Other(format!("R_dl-cl k prove: {e}")))?;

        // --- Step 6: Build Round 2 payload ---
        let phi_bar_x_i_ser = SerializedClCt::from_bicycl_ct(setup, &phi_bar_x_i)
            .map_err(|e| TecdsaError::Other(format!("ser phi_bar_x_i: {e}")))?;
        let pi_dl_cl_x_ser = SerRDlClProof::from_proof(setup, &pi_dl_cl_x)
            .map_err(|e| TecdsaError::Other(format!("ser pi_dl_cl_x: {e}")))?;
        let phi_bar_k_i_ser = SerializedClCt::from_bicycl_ct(setup, &phi_bar_k_i)
            .map_err(|e| TecdsaError::Other(format!("ser phi_bar_k_i: {e}")))?;
        let pi_dl_cl_k_ser = SerRDlClProof::from_proof(setup, &pi_dl_cl_k)
            .map_err(|e| TecdsaError::Other(format!("ser pi_dl_cl_k: {e}")))?;
        let pi_dec_dl_ser = SerRDecDlProof::from_proof(setup, &dec_dl_proof)
            .map_err(|e| TecdsaError::Other(format!("ser pi_dec_dl: {e}")))?;
        let pd_ser = SerializedQfi::from_qfi(setup, &dec_dl_pd)
            .map_err(|e| TecdsaError::Other(format!("ser pd: {e}")))?;
        let pd_c1_ser = SerializedQfi::from_qfi(setup, &dec_dl_c1)
            .map_err(|e| TecdsaError::Other(format!("ser pd_c1: {e}")))?;

        let r2_payload = R2Payload {
            phi_bar_x_i: phi_bar_x_i_ser,
            pi_dl_cl_x: pi_dl_cl_x_ser,
            phi_bar_k_i: phi_bar_k_i_ser,
            pi_dl_cl_k: pi_dl_cl_k_ser,
            r_point_bytes: r_point_i.to_bytes().to_vec(),
            pi_dec_dl: pi_dec_dl_ser,
            pd: pd_ser,
            pd_c1: pd_c1_ser,
        };

        let payload_bytes = bincode::serde::encode_to_vec(&r2_payload, bincode::config::standard())
            .map_err(|e| TecdsaError::Other(format!("serialize R2: {e}")))?;

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Jtx25RobustPresignMsg::Round2(payload_bytes),
        }];

        // Store own Round 2 data.
        let mut received = BTreeMap::new();
        received.insert(
            state.my_id,
            ReceivedR2 {
                phi_bar_x_i,
                phi_bar_k_i,
                r_point: r_point_i,
            },
        );

        Ok(Round2State {
            my_id: state.my_id,
            all_parties: state.all_parties,
            phi_i: state.phi_i,
            k_i,
            _r_point_i: r_point_i,
            phi_bar,
            received,
            outgoing,
        })
    }

    // -----------------------------------------------------------------------
    // Finalize (after Round 2)
    // -----------------------------------------------------------------------

    fn finalize(
        state: &Round2State,
        setup: &ClSetup,
        key_mat: &KeyMaterial,
    ) -> tecdsa_core::Result<Jtx25RobustPresignature> {
        let n = state.all_parties.len();
        let party_ids_1based: Vec<u16> = state.all_parties.iter().map(|p| p.0 + 1).collect();

        // Compute R = Prod R_j^{lambda_j}.
        let lagrange_coeffs =
            tecdsa_vss::lagrange::coefficients::<k256::Secp256k1>(&party_ids_1based);
        let mut r_combined = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::IDENTITY;
        for (idx, &party_j) in state.all_parties.iter().enumerate() {
            let r2 = state
                .received
                .get(&party_j)
                .ok_or_else(|| TecdsaError::Other(format!("missing R2 from {party_j}")))?;
            r_combined += r2.r_point * lagrange_coeffs[idx];
        }
        let r_x = <k256::Secp256k1 as TecdsaCurve>::xcoord_mod_q(&r_combined.to_affine());

        // Serialize phi_bar (compact binary).
        let (pb_c1, pb_c2) = setup
            .ct_components(&state.phi_bar)
            .map_err(|e| TecdsaError::Other(format!("phi_bar components: {e}")))?;
        let ctx = setup.ctx();
        let phi_bar_c1_bytes = pb_c1
            .to_bytes(ctx)
            .map_err(|e| TecdsaError::Other(format!("to_bytes: {e}")))?;
        let phi_bar_c2_bytes = pb_c2
            .to_bytes(ctx)
            .map_err(|e| TecdsaError::Other(format!("to_bytes: {e}")))?;

        // Serialize per-party phi_bar_x and phi_bar_k ciphertexts.
        let mut phi_bar_x_c1_bytes_map = BTreeMap::new();
        let mut phi_bar_x_c2_bytes_map = BTreeMap::new();
        let mut phi_bar_k_c1_bytes_map = BTreeMap::new();
        let mut phi_bar_k_c2_bytes_map = BTreeMap::new();

        for (&party_j, r2) in &state.received {
            let j_pid = party_j.0;

            let (xc1, xc2) = setup.ct_components(&r2.phi_bar_x_i).map_err(|e| {
                TecdsaError::Other(format!("phi_bar_x components from {party_j}: {e}"))
            })?;
            phi_bar_x_c1_bytes_map.insert(
                j_pid,
                xc1.to_bytes(ctx)
                    .map_err(|e| TecdsaError::Other(format!("to_bytes: {e}")))?,
            );
            phi_bar_x_c2_bytes_map.insert(
                j_pid,
                xc2.to_bytes(ctx)
                    .map_err(|e| TecdsaError::Other(format!("to_bytes: {e}")))?,
            );

            let (kc1, kc2) = setup.ct_components(&r2.phi_bar_k_i).map_err(|e| {
                TecdsaError::Other(format!("phi_bar_k components from {party_j}: {e}"))
            })?;
            phi_bar_k_c1_bytes_map.insert(
                j_pid,
                kc1.to_bytes(ctx)
                    .map_err(|e| TecdsaError::Other(format!("to_bytes: {e}")))?,
            );
            phi_bar_k_c2_bytes_map.insert(
                j_pid,
                kc2.to_bytes(ctx)
                    .map_err(|e| TecdsaError::Other(format!("to_bytes: {e}")))?,
            );
        }

        // Store lagrange coefficients keyed by PartyId.0 (0-based) for lookup
        // in the online sign phase.
        let lagrange_map: BTreeMap<u16, k256::Scalar> = state
            .all_parties
            .iter()
            .zip(lagrange_coeffs.iter())
            .map(|(p, &l)| (p.0, l))
            .collect();

        Ok(Jtx25RobustPresignature {
            party_index: state.my_id.0,
            r_point: r_combined,
            r_x,
            phi_i: state.phi_i,
            k_i: state.k_i,
            n_signers: n,
            threshold: key_mat.threshold,
            phi_bar_c1_bytes,
            phi_bar_c2_bytes,
            phi_bar_x_c1_bytes: phi_bar_x_c1_bytes_map,
            phi_bar_x_c2_bytes: phi_bar_x_c2_bytes_map,
            phi_bar_k_c1_bytes: phi_bar_k_c1_bytes_map,
            phi_bar_k_c2_bytes: phi_bar_k_c2_bytes_map,
            lagrange_coeffs: lagrange_map,
            cl_setup_seed: key_mat.cl_setup_seed.clone(),
            use_128bit_security: key_mat.use_128bit_security,
            cl_sk_share: key_mat.cl_sk_share.clone(),
            cl_pk_bytes: key_mat.cl_pk_bytes.clone(),
            cl_pk_share_bytes: key_mat.cl_pk_share_bytes.clone(),
            n_parties_dkg: key_mat.n_parties_dkg,
        })
    }
}

// ---------------------------------------------------------------------------
// StateMachine implementation
// ---------------------------------------------------------------------------

impl StateMachine for Jtx25RobustPresignMachine {
    type Output = Jtx25RobustPresignature;
    type Inbound = Jtx25RobustPresignMsg;
    type Outbound = Jtx25RobustPresignMsg;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        // Reject messages from self.
        let my_id = match &self.round {
            PresignRobustRound::Round1(s) => s.my_id,
            PresignRobustRound::Round2(s) => s.my_id,
            _ => PartyId(u16::MAX),
        };
        if from == my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }

        let round = std::mem::replace(&mut self.round, PresignRobustRound::Poisoned);

        match round {
            PresignRobustRound::Round1(mut state) => {
                if let Jtx25RobustPresignMsg::Round1(data) = msg {
                    if !state.all_parties.contains(&from) {
                        self.round = PresignRobustRound::Round1(state);
                        return Err(TecdsaError::Other(format!("unknown party: {from}")));
                    }

                    if state.received.contains_key(&from) {
                        self.round = PresignRobustRound::Round1(state);
                        return Err(TecdsaError::Other(format!(
                            "duplicate message from party {from}"
                        )));
                    }

                    let (payload, _): (R1Payload, _) =
                        bincode::serde::decode_from_slice(&data, bincode::config::standard())
                            .map_err(|e| TecdsaError::Other(format!("deser R1: {e}")))?;

                    // Reconstruct CL objects.
                    let phi_bar_i = payload
                        .phi_bar_i
                        .to_bicycl_ct(&self.setup)
                        .map_err(|e| TecdsaError::Other(format!("phi_bar from {from}: {e}")))?;

                    let r_enc_proof = payload
                        .r_enc_proof
                        .to_proof(&self.setup)
                        .map_err(|e| TecdsaError::Other(format!("r_enc from {from}: {e}")))?;

                    let pvss_c1 = payload
                        .pvss_c1
                        .to_qfi(&self.setup)
                        .map_err(|e| TecdsaError::Other(format!("pvss_c1 from {from}: {e}")))?;

                    let pvss_c2s: Vec<BicyclQfi> = payload
                        .pvss_c2s
                        .iter()
                        .map(|s| {
                            s.to_qfi(&self.setup).map_err(|e| {
                                TecdsaError::Other(format!("pvss_c2 from {from}: {e}"))
                            })
                        })
                        .collect::<Result<_, _>>()?;

                    let pvss_proof = RShProof {
                        k: payload.pvss_proof.k,
                        rho_response: payload.pvss_proof.rho_response,
                    };

                    // Verify R_enc proof AND R_sh proof (MUST use &&).
                    let r_enc_ok = r_enc_proof
                        .verify(&self.setup, &self.key_mat.cl_pk, &phi_bar_i)
                        .map_err(|e| {
                            TecdsaError::Other(format!("R_enc verify from {from}: {e}"))
                        })?;

                    let party_ids_1based: Vec<u16> =
                        state.all_parties.iter().map(|p| p.0 + 1).collect();
                    let r_sh_ok = pvss_share_verify(
                        &self.setup,
                        &party_ids_1based,
                        &self.individual_cl_pks,
                        self.key_mat.threshold,
                        &pvss_c1,
                        &pvss_c2s,
                        &pvss_proof,
                    )
                    .map_err(|e| TecdsaError::Other(format!("R_sh verify from {from}: {e}")))?;

                    // CRITICAL: Both proofs must pass (AND, not OR).
                    if !r_enc_ok || !r_sh_ok {
                        self.round = PresignRobustRound::Round1(state);
                        return Err(TecdsaError::Other(format!(
                            "proof verification failed for party {from}: r_enc={r_enc_ok}, r_sh={r_sh_ok}"
                        )));
                    }

                    state.received.insert(
                        from,
                        ReceivedR1 {
                            phi_bar_i,
                            pvss_c1,
                            pvss_c2s,
                        },
                    );

                    if state.received.len() == state.all_parties.len() {
                        let r2_state = Self::transition_r1_to_r2(
                            state,
                            &mut self.setup,
                            &self.key_mat,
                            &self.individual_cl_pks,
                        )?;
                        self.round = PresignRobustRound::Round2(r2_state);
                    } else {
                        self.round = PresignRobustRound::Round1(state);
                    }
                } else {
                    self.round = PresignRobustRound::Round1(state);
                    return Err(TecdsaError::Other("unexpected msg type in round 1".into()));
                }
            }

            PresignRobustRound::Round2(mut state) => {
                if let Jtx25RobustPresignMsg::Round2(data) = msg {
                    if !state.all_parties.contains(&from) {
                        self.round = PresignRobustRound::Round2(state);
                        return Err(TecdsaError::Other(format!("unknown party: {from}")));
                    }

                    if state.received.contains_key(&from) {
                        self.round = PresignRobustRound::Round2(state);
                        return Err(TecdsaError::Other(format!(
                            "duplicate message from party {from}"
                        )));
                    }

                    let (payload, _): (R2Payload, _) =
                        bincode::serde::decode_from_slice(&data, bincode::config::standard())
                            .map_err(|e| TecdsaError::Other(format!("deser R2: {e}")))?;

                    // Reconstruct CL objects.
                    let phi_bar_x_i = payload
                        .phi_bar_x_i
                        .to_bicycl_ct(&self.setup)
                        .map_err(|e| TecdsaError::Other(format!("phi_bar_x from {from}: {e}")))?;
                    let phi_bar_k_i = payload
                        .phi_bar_k_i
                        .to_bicycl_ct(&self.setup)
                        .map_err(|e| TecdsaError::Other(format!("phi_bar_k from {from}: {e}")))?;
                    let r_point =
                        point_from_bytes(&payload.r_point_bytes, &format!("R from {from}"))
                            .map_err(TecdsaError::Other)?;

                    // Verify R_dl-cl proofs AND R_cl-dec-dl proof.
                    let pi_dl_cl_x = payload
                        .pi_dl_cl_x
                        .to_proof(&self.setup)
                        .map_err(|e| TecdsaError::Other(format!("pi_dl_cl_x from {from}: {e}")))?;
                    let pi_dl_cl_k = payload
                        .pi_dl_cl_k
                        .to_proof(&self.setup)
                        .map_err(|e| TecdsaError::Other(format!("pi_dl_cl_k from {from}: {e}")))?;
                    let pi_dec_dl = payload
                        .pi_dec_dl
                        .to_proof(&self.setup)
                        .map_err(|e| TecdsaError::Other(format!("pi_dec_dl from {from}: {e}")))?;

                    // Verify R_dl-cl for x: (X_lambda_i, phi_bar, phi_bar_x_i; lambda_i * x_i)
                    let from_idx = state
                        .all_parties
                        .iter()
                        .position(|p| *p == from)
                        .ok_or_else(|| TecdsaError::Other(format!("party {from} not found")))?;

                    let party_ids_1based: Vec<u16> =
                        state.all_parties.iter().map(|p| p.0 + 1).collect();
                    let lagrange_coeffs =
                        tecdsa_vss::lagrange::coefficients::<k256::Secp256k1>(&party_ids_1based);
                    let lambda_j = lagrange_coeffs[from_idx];

                    // Map signing-set index to DKG index for public_shares lookup.
                    let from_dkg_idx = from.0 as usize;
                    let x_j_lambda_point = self.key_mat.public_shares[from_dkg_idx] * lambda_j;

                    let dl_cl_x_ok = pi_dl_cl_x
                        .verify(&self.setup, &x_j_lambda_point, &state.phi_bar, &phi_bar_x_i)
                        .map_err(|e| {
                            TecdsaError::Other(format!("R_dl-cl x verify from {from}: {e}"))
                        })?;

                    // Verify R_dl-cl for k: (R_i, phi_bar, phi_bar_k_i; k_i)
                    let dl_cl_k_ok = pi_dl_cl_k
                        .verify(&self.setup, &r_point, &state.phi_bar, &phi_bar_k_i)
                        .map_err(|e| {
                            TecdsaError::Other(format!("R_dl-cl k verify from {from}: {e}"))
                        })?;

                    // Verify R_Dec_DL proof.
                    let pd = payload
                        .pd
                        .to_qfi(&self.setup)
                        .map_err(|e| TecdsaError::Other(format!("pd from {from}: {e}")))?;
                    let pd_c1 = payload
                        .pd_c1
                        .to_qfi(&self.setup)
                        .map_err(|e| TecdsaError::Other(format!("pd_c1 from {from}: {e}")))?;

                    let from_pk_data =
                        self.key_mat.cl_pk_share_bytes.get(&from.0).ok_or_else(|| {
                            TecdsaError::Other(format!("missing CL pk share for {from}"))
                        })?;
                    let from_pk_qfi = {
                        let ctx = self.setup.ctx();
                        BicyclQfi::from_bytes(ctx, from_pk_data)
                            .map_err(|e| TecdsaError::Other(format!("from_bytes: {e}")))?
                    };
                    let from_pk_raw = self
                        .setup
                        .pk_from_qfi(&from_pk_qfi)
                        .map_err(|e| TecdsaError::Other(format!("pk_from_qfi: {e}")))?;

                    let dummy_c2 = self
                        .setup
                        .identity()
                        .map_err(|e| TecdsaError::Other(format!("identity: {e}")))?;
                    let ct_for_verify = self
                        .setup
                        .ct_from_components(&pd_c1, &dummy_c2)
                        .map_err(|e| TecdsaError::Other(format!("ct_from: {e}")))?;

                    let dec_dl_ok = pi_dec_dl
                        .verify(&self.setup, &from_pk_raw, &ct_for_verify, &pd)
                        .map_err(|e| {
                            TecdsaError::Other(format!("R_Dec_DL verify from {from}: {e}"))
                        })?;

                    // CRITICAL: All proofs must pass (AND).
                    if !dl_cl_x_ok || !dl_cl_k_ok || !dec_dl_ok {
                        self.round = PresignRobustRound::Round2(state);
                        return Err(TecdsaError::Other(format!(
                            "proof verification failed for party {from}: dl_cl_x={dl_cl_x_ok}, dl_cl_k={dl_cl_k_ok}, dec_dl={dec_dl_ok}"
                        )));
                    }

                    state.received.insert(
                        from,
                        ReceivedR2 {
                            phi_bar_x_i,
                            phi_bar_k_i,
                            r_point,
                        },
                    );

                    if state.received.len() == state.all_parties.len() {
                        let presignature = Self::finalize(&state, &self.setup, &self.key_mat)?;
                        self.round = PresignRobustRound::Done(presignature);
                    } else {
                        self.round = PresignRobustRound::Round2(state);
                    }
                } else {
                    self.round = PresignRobustRound::Round2(state);
                    return Err(TecdsaError::Other("unexpected msg type in round 2".into()));
                }
            }

            PresignRobustRound::Done(_) => {
                return Err(TecdsaError::Other("presign already complete".into()));
            }
            PresignRobustRound::Poisoned => {
                return Err(TecdsaError::Other("presign machine is poisoned".into()));
            }
        }

        Ok(())
    }

    fn drain_outgoing(&mut self) -> Vec<Outgoing<Self::Outbound>> {
        match &mut self.round {
            PresignRobustRound::Round1(s) => std::mem::take(&mut s.outgoing),
            PresignRobustRound::Round2(s) => std::mem::take(&mut s.outgoing),
            PresignRobustRound::Done(_) | PresignRobustRound::Poisoned => Vec::new(),
        }
    }

    fn is_done(&self) -> bool {
        matches!(self.round, PresignRobustRound::Done(_))
    }

    fn finish(self) -> tecdsa_core::Result<Self::Output> {
        match self.round {
            PresignRobustRound::Done(presig) => Ok(presig),
            _ => Err(TecdsaError::Other("presign not complete".into())),
        }
    }

    fn current_round(&self) -> u16 {
        match &self.round {
            PresignRobustRound::Round1(_) => 1,
            PresignRobustRound::Round2(_) => 2,
            PresignRobustRound::Done(_) => 3,
            PresignRobustRound::Poisoned => 0,
        }
    }

    fn ia_report(&self) -> Option<&IaReport> {
        None
    }
}
