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

//! JTX25 robust presigning protocol (2 rounds).
//!
//! Produces a message-independent [`Jtx25RobustPresignature`] using threshold CL
//! homomorphic encryption and DRG (Distributed Randomness Generation).
//!
//! ## Protocol Rounds (JTX25 Section 4)
//!
//! ### Presign Round 1
//! Each P_i:
//! 1. Sample phi_i, k_i <- Z_q randomly
//! 2. Compute threshold CL encryption: phi_bar_i <- t-CL.Enc(pk, phi_i)
//! 3. Prove R_enc for phi_bar_i
//! 4. DRG.Gen(k_i): Pedersen VSS + CL Enc(ek_i, k_i) + R_Enc-PC proof
//! 5. Broadcast (phi_bar_i, pi_enc, DRG.Gen output)
//!
//! ### Presign Round 2
//! Upon receiving Round 1 from all P_j:
//! 1. Verify R_enc proofs AND DRG.GenVf (Pedersen VSS + R_Enc-PC)
//! 2. DRG.Comb: combine received shares -> k_i + re-encrypt + R_Enc-PC
//! 3. DRG.RevealExp: R_i = g^{k_i} + R_PC-DL proof
//! 4. Compute phi_bar = sum of all phi_bar_j (homomorphic sum)
//! 5. Compute phi_bar_x_i = phi_bar * (lambda_i * x_i)
//! 6. Prove R_dl-cl: (X_lambda_i, phi_bar, phi_bar_x_i; lambda_i * x_i)
//! 7. Compute phi_bar_k_i = phi_bar * k_i
//! 8. Prove R_dl-cl: (R_i, phi_bar, phi_bar_k_i; k_i)
//! 9. Broadcast (phi_bar_x_i, pi_dl-cl_0, phi_bar_k_i, pi_dl-cl_1,
//!    R_i, DRG.Comb ct+proof, pi_pc-dl)

use std::collections::BTreeMap;

use elliptic_curve::{group::GroupEncoding, CurveArithmetic};
use num_traits::Num as _;
use serde::{Deserialize, Serialize};
use tecdsa_class_group::{
    cl::{ClCiphertext, ClPublicKey, ClSetup, Qfi},
    drg::{drg_comb, drg_gen_verify, drg_gen_with_secret, DrgGenOutput, PedersenVssShare},
    zk::{r_dl_cl::RDlClProof, r_enc::REncProof, r_pc_dl::RPcDlProof},
};
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{state_machine::Outgoing, IaReport, PartyId, Recipient, StateMachine};
use zeroize::Zeroize;

use crate::{
    cl_wire::{
        add_ct_components, copy_ct, point_from_bytes, scalar_mul_ct, SerRDlClProof, SerREncPcProof,
        SerREncProof, SerRPcDlProof, SerializedClCt, SerializedQfi,
    },
    error::Jtx25Error,
    key_share::Jtx25KeyShare,
};

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
    /// DRG.Gen: Pedersen VSS commitments (compressed EC points).
    drg_commitments: Vec<Vec<u8>>,
    /// DRG.Gen: CL ciphertext of k_i under own individual pk.
    drg_ciphertext: SerializedClCt,
    /// DRG.Gen: F-subgroup element Y = f^{k_i}.
    drg_y: SerializedQfi,
    /// DRG.Gen: R_Enc-PC proof.
    drg_proof: SerREncPcProof,
    /// DRG.Gen: Pedersen VSS shares (value, randomness) for each party.
    drg_shares: Vec<(Vec<u8>, Vec<u8>)>,
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
    /// R_i = k_i * G (from DRG.RevealExp).
    r_point_bytes: Vec<u8>,
    /// DRG.Comb: re-encrypted ciphertext of combined k_i.
    drg_comb_ct: SerializedClCt,
    /// DRG.Comb: R_Enc-PC proof for combined k_i ciphertext.
    drg_comb_proof: SerREncPcProof,
    /// DRG.Comb: F-subgroup element Y = f^{k_i} for combined share.
    drg_comb_y: SerializedQfi,
    /// DRG.RevealExp: R_PC-DL proof for R_i = g^{k_i}.
    pi_pc_dl: SerRPcDlProof,
}

// ---------------------------------------------------------------------------
// Received data
// ---------------------------------------------------------------------------

struct ReceivedR1 {
    phi_bar_i: ClCiphertext,
    /// DRG.Gen: Pedersen VSS commitments.
    drg_commitments: Vec<k256::ProjectivePoint>,
    /// DRG.Gen: CL ciphertext of k_i (stored for audit, not directly consumed).
    _drg_ciphertext: ClCiphertext,
    /// DRG.Gen: F-subgroup element Y = f^{k_i} (stored for audit).
    _drg_y: Qfi,
    /// DRG.Gen: Pedersen VSS share designated for us.
    drg_my_share: PedersenVssShare,
}

struct ReceivedR2 {
    phi_bar_x_i: ClCiphertext,
    phi_bar_k_i: ClCiphertext,
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
    /// Own k_i secret (from DRG.Gen, used in DRG.Comb via own_drg_gen).
    _own_k_i: k256::Scalar,
    /// Own DRG.Gen output (for DRG.Comb in Round 2).
    own_drg_gen: DrgGenOutput,
    received: BTreeMap<PartyId, ReceivedR1>,
    outgoing: Vec<Outgoing<Jtx25RobustPresignMsg>>,
}

struct Round2State {
    my_id: PartyId,
    all_parties: Vec<PartyId>,
    phi_i: k256::Scalar,
    k_i: k256::Scalar,
    _r_point_i: k256::ProjectivePoint,
    phi_bar: ClCiphertext,
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
    cl_pk: ClPublicKey,
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

// DRG operations imported from tecdsa_class_group::drg

// ---------------------------------------------------------------------------
// Presign state machine
// ---------------------------------------------------------------------------

pub struct Jtx25RobustPresignMachine {
    round: PresignRobustRound,
    setup: ClSetup,
    key_mat: KeyMaterial,
    /// Individual CL PKs for DRG (not the aggregate threshold PK).
    individual_cl_pks: Vec<ClPublicKey>,
}

impl Jtx25RobustPresignMachine {
    /// Create a new JTX25 robust presign state machine.
    ///
    /// Immediately runs presign Round 1:
    /// 1. Sample phi_i, k_i
    /// 2. Encrypt phi_i under aggregate threshold CL pk
    /// 3. DRG.Gen for k_i (Pedersen VSS + CL encrypt + R_Enc-PC)
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
        let pk_elt = &key_share.cl_pk.elt();
        let cl_pk_bytes = { pk_elt.to_bytes() };

        // Reconstruct individual CL public keys for the signing subset.
        let mut individual_cl_pks: Vec<ClPublicKey> = Vec::with_capacity(n);
        let mut cl_pk_share_bytes: BTreeMap<u16, Vec<u8>> = BTreeMap::new();

        // First, store ALL party CL PK shares by their party_index (1-based).
        for (dkg_idx, qfi) in key_share.cl_pk_shares.iter().enumerate() {
            let dkg_party_index = (dkg_idx + 1) as u16;
            let pid = dkg_party_index - 1;
            let data = qfi.to_bytes();
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
            let sk_dec = sk.to_string();
            let q_dec = setup.cl().q().to_string();
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

        // --- Step 3: DRG.Gen for k_i ---
        let k_i = <k256::Secp256k1 as TecdsaCurve>::random_scalar(&mut rand::rngs::OsRng);
        let my_cl_pk = setup
            .pk_from_qfi(individual_cl_pks[my_idx].elt())
            .map_err(Jtx25Error::ClError)?;
        let drg_out = drg_gen_with_secret(
            &mut setup,
            &my_cl_pk,
            &k_i,
            threshold,
            n as u16,
            &mut rand::rngs::OsRng,
        )
        .map_err(|e| Jtx25Error::InvalidInput(format!("drg_gen: {e}")))?;

        // --- Step 4: Build Round 1 payload ---
        let phi_bar_i_ser = SerializedClCt::from_bicycl_ct(&phi_bar_i)
            .map_err(|e| Jtx25Error::InvalidInput(format!("serialize phi_bar: {e}")))?;
        let r_enc_proof_ser = SerREncProof::from_proof(&r_enc_proof)
            .map_err(|e| Jtx25Error::InvalidInput(format!("serialize r_enc_proof: {e}")))?;

        // Serialize DRG commitments as compressed EC points.
        let drg_commits_ser: Vec<Vec<u8>> = drg_out
            .commitments
            .iter()
            .map(|c| c.to_bytes().to_vec())
            .collect();
        let drg_ct_ser = SerializedClCt::from_bicycl_ct(&drg_out.ciphertext)
            .map_err(|e| Jtx25Error::InvalidInput(format!("serialize drg_ct: {e}")))?;
        let drg_y_ser = SerializedQfi::from_qfi(&drg_out.y_element)
            .map_err(|e| Jtx25Error::InvalidInput(format!("serialize drg_y: {e}")))?;
        let drg_proof_ser = SerREncPcProof::from_proof(&drg_out.proof)
            .map_err(|e| Jtx25Error::InvalidInput(format!("serialize drg_proof: {e}")))?;

        // Serialize shares (value + randomness bytes for each party).
        let drg_shares_ser: Vec<(Vec<u8>, Vec<u8>)> = drg_out
            .vss_shares
            .iter()
            .map(|s| {
                let v = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&s.value);
                let r = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&s.randomness);
                (v, r)
            })
            .collect();

        let r1_payload = R1Payload {
            phi_bar_i: phi_bar_i_ser,
            r_enc_proof: r_enc_proof_ser,
            drg_commitments: drg_commits_ser,
            drg_ciphertext: drg_ct_ser,
            drg_y: drg_y_ser,
            drg_proof: drg_proof_ser,
            drg_shares: drg_shares_ser,
        };

        let payload_bytes = bincode::serde::encode_to_vec(&r1_payload, bincode::config::standard())
            .map_err(|e| Jtx25Error::InvalidInput(format!("serialize R1: {e}")))?;

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Jtx25RobustPresignMsg::Round1(payload_bytes),
        }];

        // Store own Round 1 data.
        let own_share = drg_out.vss_shares[my_idx].clone();
        let mut received = BTreeMap::new();
        received.insert(
            my_id,
            ReceivedR1 {
                phi_bar_i,
                drg_commitments: drg_out.commitments.clone(),
                _drg_ciphertext: copy_ct(&setup, &drg_out.ciphertext)
                    .map_err(|e| Jtx25Error::InvalidInput(format!("copy drg_ct: {e}")))?,
                _drg_y: {
                    let bytes = drg_out.y_element.to_bytes();
                    Qfi::from_bytes(&bytes)
                },
                drg_my_share: own_share,
            },
        );

        let state = Round1State {
            my_id,
            all_parties,
            phi_i,
            _phi_i_bytes: phi_i_bytes,
            _enc_randomness: enc_randomness,
            _own_k_i: k_i,
            own_drg_gen: drg_out,
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
        _individual_cl_pks: &[ClPublicKey],
    ) -> tecdsa_core::Result<Round2State> {
        let my_idx = state
            .all_parties
            .iter()
            .position(|p| *p == state.my_id)
            .ok_or_else(|| TecdsaError::Other("my_id not in all_parties".into()))?;
        let _n = state.all_parties.len();
        let party_ids_1based: Vec<u16> = state.all_parties.iter().map(|p| p.0 + 1).collect();

        // --- Step 1: (proofs already verified in handle) ---

        // --- Step 2: DRG.Comb — combine received shares into k_i ---
        let my_party_1based = (my_idx + 1) as u16;
        let my_pk_share_data = key_mat
            .cl_pk_share_bytes
            .get(&state.my_id.0)
            .ok_or_else(|| TecdsaError::Other("missing own CL pk share bytes".into()))?;
        let my_pk_qfi = { Qfi::from_bytes(my_pk_share_data) };
        let my_cl_pk = setup
            .pk_from_qfi(&my_pk_qfi)
            .map_err(|e| TecdsaError::Other(format!("pk_from_qfi: {e}")))?;

        // Collect shares and commitments from all parties (including self).
        let mut received_shares: Vec<(u16, PedersenVssShare)> = Vec::new();
        let mut all_commitments: Vec<(u16, Vec<k256::ProjectivePoint>)> = Vec::new();

        // Own share from own DRG.Gen output.
        received_shares.push((
            my_party_1based,
            state.own_drg_gen.vss_shares[my_idx].clone(),
        ));
        all_commitments.push((my_party_1based, state.own_drg_gen.commitments.clone()));

        // Other parties' shares (received in Round 1).
        for (&party_j, r1) in &state.received {
            if party_j == state.my_id {
                continue;
            }
            let j_1based = (state
                .all_parties
                .iter()
                .position(|p| *p == party_j)
                .unwrap()
                + 1) as u16;
            received_shares.push((j_1based, r1.drg_my_share.clone()));
            all_commitments.push((j_1based, r1.drg_commitments.clone()));
        }

        let drg_comb_out = drg_comb(
            setup,
            &my_cl_pk,
            my_party_1based,
            &received_shares,
            &all_commitments,
        )
        .map_err(|e| TecdsaError::Other(format!("drg_comb: {e}")))?;

        let k_i = drg_comb_out.combined_share;
        let r_point_i = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * k_i;

        // --- Step 2b: DRG.RevealExp — prove R_i = g^{k_i} via R_PC-DL ---
        let k_i_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&k_i);
        let y_k = setup
            .power_of_f_bytes(&k_i_bytes)
            .map_err(|e| TecdsaError::Other(format!("power_of_f: {e}")))?;
        let pi_pc_dl = RPcDlProof::prove(setup, &y_k, &k_i_bytes)
            .map_err(|e| TecdsaError::Other(format!("R_PC-DL prove: {e}")))?;

        // --- Step 3: Compute phi_bar = sum of all phi_bar_j ---
        let mut phi_bar: Option<ClCiphertext> = None;
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
        let phi_bar_x_i_ser = SerializedClCt::from_bicycl_ct(&phi_bar_x_i)
            .map_err(|e| TecdsaError::Other(format!("ser phi_bar_x_i: {e}")))?;
        let pi_dl_cl_x_ser = SerRDlClProof::from_proof(&pi_dl_cl_x)
            .map_err(|e| TecdsaError::Other(format!("ser pi_dl_cl_x: {e}")))?;
        let phi_bar_k_i_ser = SerializedClCt::from_bicycl_ct(&phi_bar_k_i)
            .map_err(|e| TecdsaError::Other(format!("ser phi_bar_k_i: {e}")))?;
        let pi_dl_cl_k_ser = SerRDlClProof::from_proof(&pi_dl_cl_k)
            .map_err(|e| TecdsaError::Other(format!("ser pi_dl_cl_k: {e}")))?;
        let drg_comb_ct_ser = SerializedClCt::from_bicycl_ct(&drg_comb_out.ciphertext)
            .map_err(|e| TecdsaError::Other(format!("ser drg_comb_ct: {e}")))?;
        let drg_comb_proof_ser = SerREncPcProof::from_proof(&drg_comb_out.proof)
            .map_err(|e| TecdsaError::Other(format!("ser drg_comb_proof: {e}")))?;
        let drg_comb_y_ser = SerializedQfi::from_qfi(&drg_comb_out.y_element)
            .map_err(|e| TecdsaError::Other(format!("ser drg_comb_y: {e}")))?;
        let pi_pc_dl_ser = SerRPcDlProof::from_proof(&pi_pc_dl)
            .map_err(|e| TecdsaError::Other(format!("ser pi_pc_dl: {e}")))?;

        let r2_payload = R2Payload {
            phi_bar_x_i: phi_bar_x_i_ser,
            pi_dl_cl_x: pi_dl_cl_x_ser,
            phi_bar_k_i: phi_bar_k_i_ser,
            pi_dl_cl_k: pi_dl_cl_k_ser,
            r_point_bytes: r_point_i.to_bytes().to_vec(),
            drg_comb_ct: drg_comb_ct_ser,
            drg_comb_proof: drg_comb_proof_ser,
            drg_comb_y: drg_comb_y_ser,
            pi_pc_dl: pi_pc_dl_ser,
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
        let phi_bar_c1_bytes = pb_c1.to_bytes();
        let phi_bar_c2_bytes = pb_c2.to_bytes();

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
            phi_bar_x_c1_bytes_map.insert(j_pid, xc1.to_bytes());
            phi_bar_x_c2_bytes_map.insert(j_pid, xc2.to_bytes());

            let (kc1, kc2) = setup.ct_components(&r2.phi_bar_k_i).map_err(|e| {
                TecdsaError::Other(format!("phi_bar_k components from {party_j}: {e}"))
            })?;
            phi_bar_k_c1_bytes_map.insert(j_pid, kc1.to_bytes());
            phi_bar_k_c2_bytes_map.insert(j_pid, kc2.to_bytes());
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
                        .to_bicycl_ct()
                        .map_err(|e| TecdsaError::Other(format!("phi_bar from {from}: {e}")))?;

                    let r_enc_proof = payload
                        .r_enc_proof
                        .to_proof()
                        .map_err(|e| TecdsaError::Other(format!("r_enc from {from}: {e}")))?;

                    // DRG data reconstruction.
                    let drg_commitments: Vec<k256::ProjectivePoint> = payload
                        .drg_commitments
                        .iter()
                        .map(|bytes| {
                            point_from_bytes(bytes, "drg_commit").map_err(TecdsaError::Other)
                        })
                        .collect::<Result<_, _>>()?;

                    let drg_ct = payload
                        .drg_ciphertext
                        .to_bicycl_ct()
                        .map_err(|e| TecdsaError::Other(format!("drg_ct from {from}: {e}")))?;

                    let drg_y = payload
                        .drg_y
                        .to_qfi()
                        .map_err(|e| TecdsaError::Other(format!("drg_y from {from}: {e}")))?;

                    let drg_proof = payload
                        .drg_proof
                        .to_proof()
                        .map_err(|e| TecdsaError::Other(format!("drg_proof from {from}: {e}")))?;

                    // Reconstruct my share from the sender.
                    let my_idx = state
                        .all_parties
                        .iter()
                        .position(|p| *p == state.my_id)
                        .ok_or_else(|| TecdsaError::Other("my_id not found".into()))?;
                    let (ref val_bytes, ref rand_bytes) = payload.drg_shares[my_idx];
                    let my_share = PedersenVssShare {
                        index: (my_idx + 1) as u16,
                        value: tecdsa_curve::conv::bytes_to_scalar::<k256::Secp256k1>(val_bytes),
                        randomness: tecdsa_curve::conv::bytes_to_scalar::<k256::Secp256k1>(
                            rand_bytes,
                        ),
                    };

                    // Verify R_enc proof for phi_bar_i.
                    let r_enc_ok = r_enc_proof
                        .verify(&self.setup, &self.key_mat.cl_pk, &phi_bar_i)
                        .map_err(|e| {
                            TecdsaError::Other(format!("R_enc verify from {from}: {e}"))
                        })?;

                    // Verify DRG.GenVf: Pedersen VSS + R_Enc-PC.
                    let from_idx = state
                        .all_parties
                        .iter()
                        .position(|p| *p == from)
                        .ok_or_else(|| TecdsaError::Other(format!("unknown party {from}")))?;
                    let from_cl_pk = self
                        .setup
                        .pk_from_qfi(self.individual_cl_pks[from_idx].elt())
                        .map_err(|e| TecdsaError::Other(format!("pk_from: {e}")))?;
                    let drg_ct_copy = copy_ct(&self.setup, &drg_ct)
                        .map_err(|e| TecdsaError::Other(format!("copy drg_ct: {e}")))?;
                    let drg_ct_wrapped = drg_ct_copy;
                    let drg_ok = drg_gen_verify(
                        &self.setup,
                        &from_cl_pk,
                        &drg_commitments,
                        &drg_ct_wrapped,
                        &drg_proof,
                        &drg_y,
                        &my_share,
                    )
                    .map_err(|e| TecdsaError::Other(format!("DRG verify from {from}: {e}")))?;

                    if !r_enc_ok || !drg_ok {
                        self.round = PresignRobustRound::Round1(state);
                        return Err(TecdsaError::Other(format!(
                            "proof verification failed for party {from}: r_enc={r_enc_ok}, drg={drg_ok}"
                        )));
                    }

                    state.received.insert(
                        from,
                        ReceivedR1 {
                            phi_bar_i,
                            drg_commitments,
                            _drg_ciphertext: drg_ct,
                            _drg_y: drg_y,
                            drg_my_share: my_share,
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
                        .to_bicycl_ct()
                        .map_err(|e| TecdsaError::Other(format!("phi_bar_x from {from}: {e}")))?;
                    let phi_bar_k_i = payload
                        .phi_bar_k_i
                        .to_bicycl_ct()
                        .map_err(|e| TecdsaError::Other(format!("phi_bar_k from {from}: {e}")))?;
                    let r_point =
                        point_from_bytes(&payload.r_point_bytes, &format!("R from {from}"))
                            .map_err(TecdsaError::Other)?;

                    // Verify R_dl-cl proofs AND R_PC-DL proof.
                    let pi_dl_cl_x = payload
                        .pi_dl_cl_x
                        .to_proof()
                        .map_err(|e| TecdsaError::Other(format!("pi_dl_cl_x from {from}: {e}")))?;
                    let pi_dl_cl_k = payload
                        .pi_dl_cl_k
                        .to_proof()
                        .map_err(|e| TecdsaError::Other(format!("pi_dl_cl_k from {from}: {e}")))?;
                    let pi_pc_dl = payload
                        .pi_pc_dl
                        .to_proof()
                        .map_err(|e| TecdsaError::Other(format!("pi_pc_dl from {from}: {e}")))?;

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

                    // Verify R_PC-DL: proves R_i = g^{k_i} via F-subgroup.
                    let drg_comb_y = payload
                        .drg_comb_y
                        .to_qfi()
                        .map_err(|e| TecdsaError::Other(format!("drg_comb_y from {from}: {e}")))?;
                    let pc_dl_ok = pi_pc_dl.verify(&self.setup, &drg_comb_y).map_err(|e| {
                        TecdsaError::Other(format!("R_PC-DL verify from {from}: {e}"))
                    })?;

                    if !dl_cl_x_ok || !dl_cl_k_ok || !pc_dl_ok {
                        self.round = PresignRobustRound::Round2(state);
                        return Err(TecdsaError::Other(format!(
                            "proof verification failed for party {from}: dl_cl_x={dl_cl_x_ok}, dl_cl_k={dl_cl_k_ok}, pc_dl={pc_dl_ok}"
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
