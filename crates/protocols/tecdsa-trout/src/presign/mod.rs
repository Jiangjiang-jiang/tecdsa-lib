// SPDX-License-Identifier: MIT OR Apache-2.0
//! Trout presigning protocol (Round 1 -- offline, message-independent).
//!
//! Each party P_i:
//! 1. Evaluates eVRF on a session nonce: (k_i, R_i) = eVRF.Eval(evrfkey_i, nonce)
//! 2. Chooses random alpha_i, beta_i, u_i
//! 3. Computes:
//!    - K_tilde_i = Enc(alpha_i, k_i)   (CL encryption of k_i)
//!    - U_i = Com(beta_i, u_i)           (CL commitment to u_i)
//!    - C_tilde_i_scaled = L_i * C_tilde_i  (Lagrange-scaled keygen encryption)
//! 4. Proves:
//!    - R_{CL-EC}: K_tilde_i encrypts same k_i as R_i
//!    - R_{ComKwlg}: knowledge of (u_i, beta_i) in U_i
//! 5. Broadcasts: (R_i, K_tilde_i, U_i, eVRF_proof_i, ct_scaled, pi_cl_ec, pi_com_kwlg)
//!
//! ## Relationship to `MtABroadcast` trait
//!
//! Steps 2-3 (CL encryption of $k_i$ with randomness $\alpha_i$ and CL
//! commitment to $u_i$ with randomness $\beta_i$) structurally match
//! [`tecdsa_protocol::MtABroadcast::encode`] as implemented by
//! [`tecdsa_class_group::ScaledDecryptMtA`].  The trait's `encode` packs
//! `a_i || b_i` into 64 bytes and produces `(c1, c2, u_com)` with state
//! `(alpha_i, beta_i, b_i)` -- the same computation performed here.
//!
//! This module calls the CL primitives directly rather than through the
//! trait because:
//!
//! 1. **eVRF integration**: the nonce $k_i$ is derived from an eVRF
//!    evaluation (not sampled freely), and the eVRF proof is part of the
//!    broadcast.
//!
//! 2. **Lagrange scaling**: the keygen ciphertext $\tilde{C}_i$ is
//!    Lagrange-scaled (step 3c), which is protocol-specific state outside
//!    the `MtABroadcast` abstraction.
//!
//! 3. **ZK proof access**: the `R_{CL-EC}` and `R_{ComKwlg}` proofs need
//!    the raw `alpha_i` and `beta_i` randomness strings, which the trait's
//!    opaque `ScaledDecryptState` would hide.
//!
//! See [`tecdsa_class_group::ScaledDecryptMtA`] for the trait-based
//! equivalent and `crate::scaled_decrypt` for the decode-side helpers
//! used in [`crate::sign`].

pub mod machine;
pub mod types;

use rand_core::CryptoRngCore;
use rug::{integer::Order, Integer};
use tecdsa_class_group::{
    cl::ClSetup,
    zk::{r_cl_dl_ec::RClDlEcProof, r_com_kwlg::RComKwlgProof},
};
use tecdsa_curve::TecdsaCurve;
pub use types::{TroutPresignOutput, TroutRound1Broadcast, TroutRound1State};

use crate::{
    error::{qfi_from_abc, qfi_to_abc, TroutError, TroutResult},
    key_share::TroutKeyShare,
};

/// Execute Round 1 (presign) for a single party.
///
/// # Arguments
/// - `share`: this party's key share
/// - `signing_parties`: 1-based indices of the parties participating
/// - `session_nonce`: unique nonce for this signing session
/// - `setup`: CL-HSM setup
/// - `cl_pk`: the joint CL public key (as bicycl public key)
/// - `rng`: cryptographic RNG
///
/// # Returns
/// `(state, broadcast)` where `state` contains secrets for Round 2
/// and `broadcast` is the message to send to all parties.
pub fn presign_round1(
    share: &TroutKeyShare,
    signing_parties: &[u16],
    session_nonce: &[u8],
    setup: &mut ClSetup,
    cl_pk: &tecdsa_class_group::cl::ClPublicKey,
    rng: &mut impl CryptoRngCore,
) -> TroutResult<(TroutRound1State, TroutRound1Broadcast)> {
    let my_idx = share.party_index;

    // 1. Evaluate eVRF on session_nonce
    // The eVRF proves that k_i was derived deterministically from the eVRF key.
    // k_i = evrf_sk scalar. R_i = k_i * G (for ECDSA nonce, NOT eVRF output point).
    let (evrf_output, evrf_proof) = share.evrf_sk.eval(session_nonce, rng);
    let k_i = *share.evrf_sk.scalar();

    let k_i_bytes = tecdsa_curve::conv::scalar_to_bytes(&k_i);
    // R_i = k_i * G (ECDSA nonce point, using the curve generator)
    let r_i_proj = <k256::Secp256k1 as TecdsaCurve>::generator() * k_i;
    let r_i_affine = elliptic_curve::group::Curve::to_affine(&r_i_proj);
    let r_i_bytes = <k256::Secp256k1 as TecdsaCurve>::point_to_bytes(&r_i_affine);

    // 2. Choose random alpha_i, beta_i, u_i
    let u_i = <k256::Secp256k1 as TecdsaCurve>::random_scalar(&mut *rng);
    let u_i_bytes = tecdsa_curve::conv::scalar_to_bytes(&u_i);

    // alpha_i: random CL exponent (for encryption)
    let (sk_tmp, _) = setup.keygen()?;
    let alpha_i = setup.sk_to_bytes(&sk_tmp)?;

    // beta_i: random CL exponent (for commitment)
    let (sk_tmp2, _) = setup.keygen()?;
    let beta_i = setup.sk_to_bytes(&sk_tmp2)?;

    // 3. Compute K_tilde_i = Enc(alpha_i, k_i)
    let kt_ct = setup.encrypt_with_r_bytes(cl_pk, &k_i_bytes, &alpha_i)?;
    let (kt_c1, kt_c2) = setup.ct_components(&kt_ct)?;

    // 4. Compute U_i = Com(beta_i, u_i) = h^beta_i * pk^u_i
    //    Uses (h, pk) as bases so the scaled decryption cross-terms cancel.
    let pk_elt = cl_pk.elt();
    let h_beta = setup.power_of_h_bytes(&beta_i)?;
    let pk_u = setup.exp_bytes(pk_elt, &u_i_bytes)?;
    let u_com = setup.compose(&h_beta, &pk_u)?;

    // 5. Compute Lagrange-scaled C_tilde_i
    let lagrange_coeffs = tecdsa_vss::lagrange::coefficients::<k256::Secp256k1>(signing_parties);
    let my_party_pos = signing_parties
        .iter()
        .position(|&p| p == my_idx)
        .ok_or_else(|| TroutError::InvalidParam("party not in signing set".into()))?;
    let l_i = lagrange_coeffs[my_party_pos];
    let l_i_bytes = tecdsa_curve::conv::scalar_to_bytes(&l_i);

    // Rebuild C_tilde_i from stored components
    let (c1_a, c1_b, c1_c, c2_a, c2_b, c2_c) = &share.ct_share_components;
    let ct_c1 = qfi_from_abc(c1_a, c1_b, c1_c)?;
    let ct_c2 = qfi_from_abc(c2_a, c2_b, c2_c)?;

    // L_i * C_tilde_i: scale both components by l_i
    let ct_scaled_c1 = setup.exp_bytes(&ct_c1, &l_i_bytes)?;
    let ct_scaled_c2 = setup.exp_bytes(&ct_c2, &l_i_bytes)?;

    // The effective encryption randomness after scaling: L_i * delta_i.
    // We need this for the scaled decryption step.
    // Compute as Integer: l_i_val * delta_i_val
    let l_i_val = Integer::from_digits(&l_i_bytes, Order::Msf);
    let delta_i_val = Integer::from_digits(&share.delta_i, Order::Msf);
    let l_i_delta_i = Integer::from(&l_i_val * &delta_i_val).to_digits::<u8>(Order::Msf);

    // 6. Prove R_{CL-EC}: K_tilde_i encrypts same k_i as R_i
    let pi_cl_ec = RClDlEcProof::prove(setup, cl_pk, &kt_ct, &r_i_bytes, &k_i_bytes, &alpha_i)?;

    // 7. Prove R_{ComKwlg}: knowledge of (u_i, beta_i) in U_i = Com(beta_i, u_i)
    //    U_i = h^beta_i * pk^u_i, so we use prove_with_base with pk as the second base.
    let pi_com_kwlg = RComKwlgProof::prove_with_base(setup, &u_com, pk_elt, &u_i_bytes, &beta_i)?;

    // Serialise QFI components
    let kt_c1_abc = qfi_to_abc(&kt_c1)?;
    let kt_c2_abc = qfi_to_abc(&kt_c2)?;
    let u_com_abc = qfi_to_abc(&u_com)?;
    let ct_scaled_c1_abc = qfi_to_abc(&ct_scaled_c1)?;
    let ct_scaled_c2_abc = qfi_to_abc(&ct_scaled_c2)?;

    let state = TroutRound1State {
        party_index: my_idx,
        k_i,
        u_i,
        alpha_i,
        beta_i,
        l_i,
        l_i_delta_i,
    };

    let bcast = TroutRound1Broadcast {
        party_index: my_idx,
        r_i_bytes: r_i_bytes.clone(),
        evrf_output,
        evrf_proof,
        kt_c1_abc,
        kt_c2_abc,
        u_com_abc,
        ct_scaled_c1_abc,
        ct_scaled_c2_abc,
        pi_cl_ec,
        pi_com_kwlg,
    };

    Ok((state, bcast))
}
