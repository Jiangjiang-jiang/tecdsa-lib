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

//! JTX25 TECDSA-Normal presigning protocol (2 rounds, no DRG).
//!
//! Produces a message-independent [`Jtx25Presignature`] using threshold CL
//! homomorphic encryption with additive nonce sharing among the signing set
//! (k = sum(k_i)). All presign participants must complete the sign phase.
//!
//! ## Protocol Rounds (JTX25 Section 3, Figure 4)
//!
//! ### Presign Round 1
//! Each P_i:
//! 1. Sample phi_i, k_i <- Z_q randomly
//! 2. Compute threshold CL encryption: phi_bar_i <- t-CL.Enc(pk, phi_i)
//! 3. Compute R_i = k_i * G
//! 4. Prove R_cl-enc for phi_bar_i
//! 5. Commit to R_i: commit_i = SHA256(R_i || nonce_i)
//! 6. Broadcast (phi_bar_i, R_cl-enc proof, commit_i)
//!
//! ### Presign Round 2
//! Each P_i:
//! 1. Verify R_cl-enc proofs for all phi_bar_j
//! 2. Decommit R_i: reveal (R_i, nonce_i)
//! 3. Verify all commitments
//! 4. Compute phi_bar = sum(phi_bar_j) via homomorphism
//! 5. Compute phi_bar_x_i = phi_bar * (lambda_i * x_i)
//! 6. Prove R_dl-cl: (X_lambda_i, phi_bar, phi_bar_x_i; lambda_i * x_i)
//! 7. Compute phi_bar_k_i = phi_bar * k_i
//! 8. Prove R_dl-cl: (R_i, phi_bar, phi_bar_k_i; k_i)
//! 9. Broadcast (R_i, nonce_i, phi_bar_x_i, pi_dl-cl_0, phi_bar_k_i, pi_dl-cl_1)
//!
//! ### Differences from TECDSA-Robust
//! - No DRG/PVSS for k_i (n-out-of-n additive sharing)
//! - Round 1 uses hash commitment instead of PVSS shares
//! - Round 2 has no R_Dec_DL proof
//! - R = prod(R_j) without Lagrange weighting
//! - O(1) communication per party (no O(t) PVSS)

#[cfg(feature = "robust")]
pub mod robust;

use std::collections::BTreeMap;

use elliptic_curve::group::GroupEncoding;
use elliptic_curve::CurveArithmetic;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use tecdsa_class_group::bicycl_glue::{BicyclCiphertext, BicyclPublicKey, ClSetup};
use tecdsa_class_group::zk::r_dl_cl::RDlClProof;
use tecdsa_class_group::zk::r_enc::REncProof;
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{state_machine::Outgoing, IaReport, PartyId, Recipient, StateMachine};

use crate::cl_wire::{
    add_ct_components, copy_ct, point_from_bytes, scalar_mul_ct, SerRDlClProof, SerREncProof,
    SerializedClCt,
};
use crate::error::Jtx25Error;
use crate::key_share::Jtx25KeyShare;

// ---------------------------------------------------------------------------
// Presignature output
// ---------------------------------------------------------------------------

/// Presignature produced by the JTX25 Normal presign protocol.
///
/// Unlike the Robust variant, nonce k = sum(k_i) uses n-out-of-n
/// additive sharing. No Lagrange weighting is needed for k-related
/// ciphertexts during online signing.
pub struct Jtx25Presignature {
    pub party_index: u16,
    /// R = prod(R_j) (no Lagrange weighting)
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
    /// The combined phi_bar ciphertext (serialized as compact binary).
    pub phi_bar_c1_bytes: Vec<u8>,
    pub phi_bar_c2_bytes: Vec<u8>,
    /// Per-party phi_bar_x_j ciphertexts (keyed by party_id u16).
    pub phi_bar_x_c1_bytes: BTreeMap<u16, Vec<u8>>,
    pub phi_bar_x_c2_bytes: BTreeMap<u16, Vec<u8>>,
    /// Per-party phi_bar_k_j ciphertexts (keyed by party_id u16).
    pub phi_bar_k_c1_bytes: BTreeMap<u16, Vec<u8>>,
    pub phi_bar_k_c2_bytes: BTreeMap<u16, Vec<u8>>,
    /// CL setup seed.
    pub cl_setup_seed: String,
    pub use_128bit_security: bool,
    /// Threshold CL secret key share (for partial decryption, big-endian bytes).
    pub cl_sk_share: Vec<u8>,
    /// Aggregate CL public key (for partial decryption proof, compact binary).
    pub cl_pk_bytes: Vec<u8>,
    /// Per-party CL PK shares (for verifying partial decryption proofs, compact binary).
    pub cl_pk_share_bytes: BTreeMap<u16, Vec<u8>>,
    /// Total n for threshold CL (n_parties_dkg).
    pub n_parties_dkg: usize,
}

impl Clone for Jtx25Presignature {
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
            cl_setup_seed: self.cl_setup_seed.clone(),
            use_128bit_security: self.use_128bit_security,
            cl_sk_share: self.cl_sk_share.clone(),
            cl_pk_bytes: self.cl_pk_bytes.clone(),
            cl_pk_share_bytes: self.cl_pk_share_bytes.clone(),
            n_parties_dkg: self.n_parties_dkg,
        }
    }
}

impl Zeroize for Jtx25Presignature {
    fn zeroize(&mut self) {
        self.phi_i.zeroize();
        self.k_i.zeroize();
        self.cl_sk_share.zeroize();
    }
}

impl Drop for Jtx25Presignature {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl std::fmt::Debug for Jtx25Presignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Jtx25Presignature")
            .field("party_index", &self.party_index)
            .field("threshold", &self.threshold)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Jtx25PresignMsg {
    Round1(Vec<u8>),
    Round2(Vec<u8>),
}

// ---------------------------------------------------------------------------
// Commitment helpers
// ---------------------------------------------------------------------------

const COMMIT_NONCE_LEN: usize = 32;

fn compute_commitment(
    r_point_bytes: &[u8],
    party_id: u16,
    nonce: &[u8; COMMIT_NONCE_LEN],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"JTX25-Normal-R-Commit");
    hasher.update(r_point_bytes);
    hasher.update(party_id.to_be_bytes());
    hasher.update(nonce);
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// Round 1 payload
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct R1Payload {
    phi_bar_i: SerializedClCt,
    r_enc_proof: SerREncProof,
    /// Hash commitment to R_i = k_i * G.
    r_commitment: [u8; 32],
}

// ---------------------------------------------------------------------------
// Round 2 payload
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct R2Payload {
    /// Decommitment: R_i point (compressed).
    r_point_bytes: Vec<u8>,
    /// Decommitment: nonce used in commitment.
    commit_nonce: [u8; COMMIT_NONCE_LEN],
    /// phi_bar_x_i = phi_bar * (lambda_i * x_i).
    phi_bar_x_i: SerializedClCt,
    /// R_dl-cl proof for (X_lambda_i, phi_bar, phi_bar_x_i; lambda_i * x_i).
    pi_dl_cl_x: SerRDlClProof,
    /// phi_bar_k_i = phi_bar * k_i.
    phi_bar_k_i: SerializedClCt,
    /// R_dl-cl proof for (R_i, phi_bar, phi_bar_k_i; k_i).
    pi_dl_cl_k: SerRDlClProof,
}

// ---------------------------------------------------------------------------
// Received data
// ---------------------------------------------------------------------------

struct ReceivedR1 {
    phi_bar_i: BicyclCiphertext,
    r_commitment: [u8; 32],
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
    k_i: k256::Scalar,
    r_point_i: k256::ProjectivePoint,
    commit_nonce: [u8; COMMIT_NONCE_LEN],
    received: BTreeMap<PartyId, ReceivedR1>,
    outgoing: Vec<Outgoing<Jtx25PresignMsg>>,
}

struct Round2State {
    my_id: PartyId,
    all_parties: Vec<PartyId>,
    phi_i: k256::Scalar,
    k_i: k256::Scalar,
    phi_bar: BicyclCiphertext,
    /// Commitments from Round 1 (for verifying decommitments in Round 2).
    r1_commitments: BTreeMap<PartyId, [u8; 32]>,
    received: BTreeMap<PartyId, ReceivedR2>,
    outgoing: Vec<Outgoing<Jtx25PresignMsg>>,
}

enum PresignRound {
    Round1(Round1State),
    Round2(Round2State),
    Done(Jtx25Presignature),
    Poisoned,
}

// ---------------------------------------------------------------------------
// Key material
// ---------------------------------------------------------------------------

struct KeyMaterial {
    x_i: k256::Scalar,
    x_i_bytes: Vec<u8>,
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
        self.x_i_bytes.zeroize();
        self.cl_sk_share.zeroize();
    }
}

impl Drop for KeyMaterial {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// ---------------------------------------------------------------------------
// Presign state machine
// ---------------------------------------------------------------------------

pub struct Jtx25PresignMachine {
    round: PresignRound,
    setup: ClSetup,
    key_mat: KeyMaterial,
}

impl Jtx25PresignMachine {
    /// Create a new JTX25 Normal presign state machine.
    ///
    /// Immediately runs presign Round 1:
    /// 1. Sample phi_i, k_i
    /// 2. Encrypt phi_i under aggregate threshold CL pk
    /// 3. Compute R_i = k_i * G, commit to it
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

        let threshold = key_share.threshold;

        // Extract key material.
        let pk_elt = setup.pk_element(&key_share.cl_pk)?;
        let cl_pk_bytes = {
            let ctx = setup.ctx();
            pk_elt
                .to_bytes(ctx)
                .map_err(|e| Jtx25Error::ClError(e.into()))?
        };

        let mut cl_pk_share_bytes: BTreeMap<u16, Vec<u8>> = BTreeMap::new();
        for (dkg_idx, qfi) in key_share.cl_pk_shares.iter().enumerate() {
            let pid = dkg_idx as u16;
            let ctx = setup.ctx();
            let data = qfi
                .to_bytes(ctx)
                .map_err(|e| Jtx25Error::ClError(e.into()))?;
            cl_pk_share_bytes.insert(pid, data);
        }

        let x_i_bytes =
            tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&key_share.secret_share);

        let key_mat = KeyMaterial {
            x_i: key_share.secret_share,
            x_i_bytes,
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
            let sk_bytes = setup.sk_to_bytes(&sk)?;
            let q_bytes = setup.q_bytes()?;
            let q = num_bigint::BigUint::from_bytes_be(&q_bytes);
            let bu = num_bigint::BigUint::from_bytes_be(&sk_bytes);
            let reduced = bu % &q;
            tecdsa_curve::conv::biguint_to_scalar::<k256::Secp256k1>(&reduced)
        };
        let phi_i_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&phi_i);

        // --- Step 2: Sample k_i ---
        let k_i = {
            let (sk, _) = setup.keygen()?;
            let sk_bytes = setup.sk_to_bytes(&sk)?;
            let q_bytes = setup.q_bytes()?;
            let q = num_bigint::BigUint::from_bytes_be(&q_bytes);
            let bu = num_bigint::BigUint::from_bytes_be(&sk_bytes);
            let reduced = bu % &q;
            tecdsa_curve::conv::biguint_to_scalar::<k256::Secp256k1>(&reduced)
        };

        // --- Step 3: Encrypt phi_i under aggregate CL pk ---
        let (r_sk, _) = setup.keygen()?;
        let enc_randomness = setup.sk_to_bytes(&r_sk)?;
        let phi_bar_i =
            setup.encrypt_with_r_bytes(&key_mat.cl_pk, &phi_i_bytes, &enc_randomness)?;

        let r_enc_proof = REncProof::prove(
            &mut setup,
            &key_mat.cl_pk,
            &phi_bar_i,
            &phi_i_bytes,
            &enc_randomness,
        )?;

        // --- Step 4: Compute R_i and commit ---
        let r_point_i = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * k_i;
        let r_point_bytes = r_point_i.to_bytes();

        let mut commit_nonce = [0u8; COMMIT_NONCE_LEN];
        {
            let (nonce_sk, _) = setup.keygen()?;
            let nonce_bytes = setup.sk_to_bytes(&nonce_sk)?;
            let len = nonce_bytes.len().min(COMMIT_NONCE_LEN);
            commit_nonce[..len].copy_from_slice(&nonce_bytes[..len]);
        }
        let r_commitment = compute_commitment(&r_point_bytes, my_id.0, &commit_nonce);

        // --- Step 5: Build Round 1 payload ---
        let phi_bar_i_ser = SerializedClCt::from_bicycl_ct(&setup, &phi_bar_i)
            .map_err(|e| Jtx25Error::InvalidInput(format!("serialize phi_bar: {e}")))?;
        let r_enc_proof_ser = SerREncProof::from_proof(&setup, &r_enc_proof)
            .map_err(|e| Jtx25Error::InvalidInput(format!("serialize r_enc_proof: {e}")))?;

        let r1_payload = R1Payload {
            phi_bar_i: phi_bar_i_ser,
            r_enc_proof: r_enc_proof_ser,
            r_commitment,
        };

        let payload_bytes = bincode::serde::encode_to_vec(&r1_payload, bincode::config::standard())
            .map_err(|e| Jtx25Error::InvalidInput(format!("serialize R1: {e}")))?;

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Jtx25PresignMsg::Round1(payload_bytes),
        }];

        // Store own Round 1 data.
        let mut received = BTreeMap::new();
        received.insert(
            my_id,
            ReceivedR1 {
                phi_bar_i,
                r_commitment,
            },
        );

        let state = Round1State {
            my_id,
            all_parties,
            phi_i,
            k_i,
            r_point_i,
            commit_nonce,
            received,
            outgoing,
        };

        Ok(Self {
            round: PresignRound::Round1(state),
            setup,
            key_mat,
        })
    }

    // -----------------------------------------------------------------------
    // Round 1 -> Round 2 transition
    // -----------------------------------------------------------------------

    fn transition_r1_to_r2(
        state: Round1State,
        setup: &mut ClSetup,
        key_mat: &KeyMaterial,
    ) -> tecdsa_core::Result<Round2State> {
        let my_idx = state
            .all_parties
            .iter()
            .position(|p| *p == state.my_id)
            .ok_or_else(|| TecdsaError::Other("my_id not in all_parties".into()))?;

        let party_ids_1based: Vec<u16> = state.all_parties.iter().map(|p| p.0 + 1).collect();

        // Preserve commitments for verification in Round 2.
        let r1_commitments: BTreeMap<PartyId, [u8; 32]> = state
            .received
            .iter()
            .map(|(&pid, r1)| (pid, r1.r_commitment))
            .collect();

        // --- Step 1: Compute phi_bar = sum of all phi_bar_j ---
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

        // --- Step 2: Compute phi_bar_x_i = phi_bar * (lambda_i * x_i) ---
        let lagrange_coeffs =
            tecdsa_vss::lagrange::coefficients::<k256::Secp256k1>(&party_ids_1based);
        let lambda_i = lagrange_coeffs[my_idx];
        let lambda_x_i = lambda_i * key_mat.x_i;
        let lambda_x_i_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&lambda_x_i);

        let phi_bar_x_i = scalar_mul_ct(setup, &phi_bar, &lambda_x_i_bytes)
            .map_err(|e| TecdsaError::Other(format!("scalar_mul phi_bar_x_i: {e}")))?;

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

        // --- Step 3: Compute phi_bar_k_i = phi_bar * k_i ---
        let k_i_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&state.k_i);
        let phi_bar_k_i = scalar_mul_ct(setup, &phi_bar, &k_i_bytes)
            .map_err(|e| TecdsaError::Other(format!("scalar_mul phi_bar_k_i: {e}")))?;

        let pi_dl_cl_k =
            RDlClProof::prove(setup, &state.r_point_i, &phi_bar, &phi_bar_k_i, &k_i_bytes)
                .map_err(|e| TecdsaError::Other(format!("R_dl-cl k prove: {e}")))?;

        // --- Step 4: Build Round 2 payload (decommit + proofs) ---
        let phi_bar_x_i_ser = SerializedClCt::from_bicycl_ct(setup, &phi_bar_x_i)
            .map_err(|e| TecdsaError::Other(format!("ser phi_bar_x_i: {e}")))?;
        let pi_dl_cl_x_ser = SerRDlClProof::from_proof(setup, &pi_dl_cl_x)
            .map_err(|e| TecdsaError::Other(format!("ser pi_dl_cl_x: {e}")))?;
        let phi_bar_k_i_ser = SerializedClCt::from_bicycl_ct(setup, &phi_bar_k_i)
            .map_err(|e| TecdsaError::Other(format!("ser phi_bar_k_i: {e}")))?;
        let pi_dl_cl_k_ser = SerRDlClProof::from_proof(setup, &pi_dl_cl_k)
            .map_err(|e| TecdsaError::Other(format!("ser pi_dl_cl_k: {e}")))?;

        let r2_payload = R2Payload {
            r_point_bytes: state.r_point_i.to_bytes().to_vec(),
            commit_nonce: state.commit_nonce,
            phi_bar_x_i: phi_bar_x_i_ser,
            pi_dl_cl_x: pi_dl_cl_x_ser,
            phi_bar_k_i: phi_bar_k_i_ser,
            pi_dl_cl_k: pi_dl_cl_k_ser,
        };

        let payload_bytes = bincode::serde::encode_to_vec(&r2_payload, bincode::config::standard())
            .map_err(|e| TecdsaError::Other(format!("serialize R2: {e}")))?;

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Jtx25PresignMsg::Round2(payload_bytes),
        }];

        // Store own Round 2 data.
        let mut received = BTreeMap::new();
        received.insert(
            state.my_id,
            ReceivedR2 {
                phi_bar_x_i,
                phi_bar_k_i,
                r_point: state.r_point_i,
            },
        );

        Ok(Round2State {
            my_id: state.my_id,
            all_parties: state.all_parties,
            phi_i: state.phi_i,
            k_i: state.k_i,
            phi_bar,
            r1_commitments,
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
    ) -> tecdsa_core::Result<Jtx25Presignature> {
        let n = state.all_parties.len();

        // R = prod(R_j) -- no Lagrange weighting (n-out-of-n additive sharing).
        let mut r_combined = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::IDENTITY;
        for &party_j in &state.all_parties {
            let r2 = state
                .received
                .get(&party_j)
                .ok_or_else(|| TecdsaError::Other(format!("missing R2 from {party_j}")))?;
            r_combined += r2.r_point;
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

        // Serialize per-party ciphertexts.
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

        Ok(Jtx25Presignature {
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

impl StateMachine for Jtx25PresignMachine {
    type Output = Jtx25Presignature;
    type Inbound = Jtx25PresignMsg;
    type Outbound = Jtx25PresignMsg;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        // Reject messages from self.
        let my_id = match &self.round {
            PresignRound::Round1(s) => s.my_id,
            PresignRound::Round2(s) => s.my_id,
            _ => PartyId(u16::MAX),
        };
        if from == my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }

        let round = std::mem::replace(&mut self.round, PresignRound::Poisoned);

        match round {
            PresignRound::Round1(mut state) => {
                if let Jtx25PresignMsg::Round1(data) = msg {
                    if !state.all_parties.contains(&from) {
                        self.round = PresignRound::Round1(state);
                        return Err(TecdsaError::Other(format!("unknown party: {from}")));
                    }

                    if state.received.contains_key(&from) {
                        self.round = PresignRound::Round1(state);
                        return Err(TecdsaError::Other(format!(
                            "duplicate message from party {from}"
                        )));
                    }

                    let (payload, _): (R1Payload, _) =
                        bincode::serde::decode_from_slice(&data, bincode::config::standard())
                            .map_err(|e| TecdsaError::Other(format!("deser R1: {e}")))?;

                    let phi_bar_i = payload
                        .phi_bar_i
                        .to_bicycl_ct(&self.setup)
                        .map_err(|e| TecdsaError::Other(format!("phi_bar from {from}: {e}")))?;

                    let r_enc_proof = payload
                        .r_enc_proof
                        .to_proof(&self.setup)
                        .map_err(|e| TecdsaError::Other(format!("r_enc from {from}: {e}")))?;

                    // Verify R_enc proof.
                    let r_enc_ok = r_enc_proof
                        .verify(&self.setup, &self.key_mat.cl_pk, &phi_bar_i)
                        .map_err(|e| {
                            TecdsaError::Other(format!("R_enc verify from {from}: {e}"))
                        })?;

                    if !r_enc_ok {
                        self.round = PresignRound::Round1(state);
                        return Err(TecdsaError::Other(format!(
                            "R_enc proof verification failed for party {from}"
                        )));
                    }

                    state.received.insert(
                        from,
                        ReceivedR1 {
                            phi_bar_i,
                            r_commitment: payload.r_commitment,
                        },
                    );

                    if state.received.len() == state.all_parties.len() {
                        let r2_state =
                            Self::transition_r1_to_r2(state, &mut self.setup, &self.key_mat)?;
                        self.round = PresignRound::Round2(r2_state);
                    } else {
                        self.round = PresignRound::Round1(state);
                    }
                } else {
                    self.round = PresignRound::Round1(state);
                    return Err(TecdsaError::Other("unexpected msg type in round 1".into()));
                }
            }

            PresignRound::Round2(mut state) => {
                if let Jtx25PresignMsg::Round2(data) = msg {
                    if !state.all_parties.contains(&from) {
                        self.round = PresignRound::Round2(state);
                        return Err(TecdsaError::Other(format!("unknown party: {from}")));
                    }

                    if state.received.contains_key(&from) {
                        self.round = PresignRound::Round2(state);
                        return Err(TecdsaError::Other(format!(
                            "duplicate message from party {from}"
                        )));
                    }

                    let (payload, _): (R2Payload, _) =
                        bincode::serde::decode_from_slice(&data, bincode::config::standard())
                            .map_err(|e| TecdsaError::Other(format!("deser R2: {e}")))?;

                    // --- Verify commitment decommitment ---
                    let r_point =
                        point_from_bytes(&payload.r_point_bytes, &format!("R from {from}"))
                            .map_err(TecdsaError::Other)?;

                    let expected_commit = state.r1_commitments.get(&from).ok_or_else(|| {
                        TecdsaError::Other(format!("missing R1 commitment for {from}"))
                    })?;
                    let actual_commit =
                        compute_commitment(&payload.r_point_bytes, from.0, &payload.commit_nonce);
                    if actual_commit != *expected_commit {
                        self.round = PresignRound::Round2(state);
                        return Err(TecdsaError::Other(format!(
                            "commitment verification failed for party {from}: R_i decommitment mismatch"
                        )));
                    }

                    // Reconstruct CL objects.
                    let phi_bar_x_i = payload
                        .phi_bar_x_i
                        .to_bicycl_ct(&self.setup)
                        .map_err(|e| TecdsaError::Other(format!("phi_bar_x from {from}: {e}")))?;
                    let phi_bar_k_i = payload
                        .phi_bar_k_i
                        .to_bicycl_ct(&self.setup)
                        .map_err(|e| TecdsaError::Other(format!("phi_bar_k from {from}: {e}")))?;

                    // Verify R_dl-cl proofs.
                    let pi_dl_cl_x = payload
                        .pi_dl_cl_x
                        .to_proof(&self.setup)
                        .map_err(|e| TecdsaError::Other(format!("pi_dl_cl_x from {from}: {e}")))?;
                    let pi_dl_cl_k = payload
                        .pi_dl_cl_k
                        .to_proof(&self.setup)
                        .map_err(|e| TecdsaError::Other(format!("pi_dl_cl_k from {from}: {e}")))?;

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

                    let dl_cl_k_ok = pi_dl_cl_k
                        .verify(&self.setup, &r_point, &state.phi_bar, &phi_bar_k_i)
                        .map_err(|e| {
                            TecdsaError::Other(format!("R_dl-cl k verify from {from}: {e}"))
                        })?;

                    if !dl_cl_x_ok || !dl_cl_k_ok {
                        self.round = PresignRound::Round2(state);
                        return Err(TecdsaError::Other(format!(
                            "proof verification failed for party {from}: dl_cl_x={dl_cl_x_ok}, dl_cl_k={dl_cl_k_ok}"
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
                        self.round = PresignRound::Done(presignature);
                    } else {
                        self.round = PresignRound::Round2(state);
                    }
                } else {
                    self.round = PresignRound::Round2(state);
                    return Err(TecdsaError::Other("unexpected msg type in round 2".into()));
                }
            }

            PresignRound::Done(_) => {
                return Err(TecdsaError::Other("presign already complete".into()));
            }
            PresignRound::Poisoned => {
                return Err(TecdsaError::Other("presign machine is poisoned".into()));
            }
        }

        Ok(())
    }

    fn drain_outgoing(&mut self) -> Vec<Outgoing<Self::Outbound>> {
        match &mut self.round {
            PresignRound::Round1(s) => std::mem::take(&mut s.outgoing),
            PresignRound::Round2(s) => std::mem::take(&mut s.outgoing),
            PresignRound::Done(_) | PresignRound::Poisoned => Vec::new(),
        }
    }

    fn is_done(&self) -> bool {
        matches!(self.round, PresignRound::Done(_))
    }

    fn finish(self) -> tecdsa_core::Result<Self::Output> {
        match self.round {
            PresignRound::Done(presig) => Ok(presig),
            _ => Err(TecdsaError::Other("presign not complete".into())),
        }
    }

    fn current_round(&self) -> u16 {
        match &self.round {
            PresignRound::Round1(_) => 1,
            PresignRound::Round2(_) => 2,
            PresignRound::Done(_) => 3,
            PresignRound::Poisoned => 0,
        }
    }

    fn ia_report(&self) -> Option<&IaReport> {
        None
    }
}
