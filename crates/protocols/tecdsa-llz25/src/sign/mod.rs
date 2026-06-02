// SPDX-License-Identifier: GPL-3.0-or-later
//! LLZ25 online signing protocol (Round 2).
//!
//! ## Protocol (LLZ25, Section 4.2 -- Sign)
//!
//! Upon receiving $\{pm_j^{(1)}\}$ from quorum $P$:
//!
//! 1. $K = \prod_{i \in P} K_i$.
//! 2. For each $j \in P \setminus \{i\}$, decode NIM products:
//!    - $\alpha_{i,j} = \text{NIM.Decode\_B}(pe_{\gamma,j}, st_{k,i})$ -- share of $k_i \cdot \gamma_j$
//!    - $\beta_{j,i} = \text{NIM.Decode\_A}(pe_{k,j}, st_{\gamma,i})$ -- share of $\gamma_i \cdot k_j$
//!    - $\mu_{i,j} = \lambda_i \cdot \text{NIM.Decode\_B}(pe_{\gamma,j}, st_{x,i})$ -- share of $\lambda_i x_i \gamma_j$
//!    - $\nu_{j,i} = \lambda_j \cdot \text{NIM.Decode\_A}(pe_{x,j}, st_{\gamma,i})$ -- share of $\lambda_j x_j \gamma_i$
//! 3. Compute:
//!    - $m = H_{sig}(msg)$
//!    - $z = H_1(X, msg, \{pm_j\})$
//!    - $y = H_2(z)$
//!    - $R = K^z \cdot g^y$, $r = x(R) \bmod q$
//! 4. Compute signature shares:
//!    - $w_i = m \gamma_i + r (\lambda_i x_i \gamma_i + \sum_{j \neq i} (\mu_{i,j} + \nu_{j,i}))$
//!    - $u_i = y \gamma_i + z (k_i \gamma_i + \sum_{j \neq i} (\alpha_{i,j} + \beta_{j,i}))$
//! 5. Broadcast $(w_i, u_i)$.
//!
//! ## Combine
//!
//! $w = \sum w_i$, $u = \sum u_i$, $\sigma = w / u \bmod q$.
//! Verify $(r, \sigma)$ against $(X, msg)$.
//!
//! ## Relationship to `MtABroadcast` trait
//!
//! The NIM decode calls (`decode_a`, `decode_b`) in this module correspond to
//! [`tecdsa_protocol::MtABroadcast::decode`] as implemented by
//! [`tecdsa_class_group::NimMtA`].  Direct `Nim` API calls are used here
//! because:
//!
//! - Each party decodes with **multiple NIM states** across different roles
//!   (k via Role B, gamma via Role A, x via Role B from keygen), requiring
//!   fine-grained control over which state is paired with which encoding.
//!
//! - The `Nim::decode_a` / `Nim::decode_b` free functions accept `&NimStateA`
//!   / `&NimStateB` directly, avoiding the enum dispatch overhead of
//!   `NimState::RoleA` / `NimState::RoleB`.
//!
//! See [`tecdsa_class_group::NimMtA`] for the trait-based equivalent.

#![allow(non_snake_case)]

pub mod machine;

use elliptic_curve::group::GroupEncoding;
use elliptic_curve::CurveArithmetic;
use elliptic_curve::PrimeField;
use sha2::{Digest, Sha256};

use tecdsa_class_group::bicycl_glue::BicyclCiphertext as ClHsmqkCiphertext;
use tecdsa_class_group::bicycl_glue::ClSetup;
use tecdsa_class_group::nim::{Nim, NimStateA, NimStateB};
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::ecdsa::{low_s_normalize, verify_ecdsa, DataToSign, Signature};

use crate::error::Llz25Error;
use crate::key_share::Llz25KeyShare;
use crate::presign::{PresignMessage, PresignState};

/// Partial signature from one party: $(w_i, u_i)$.
#[derive(Debug, Clone)]
pub struct PartialSignature {
    pub w_i: k256::Scalar,
    pub u_i: k256::Scalar,
}

/// Hash function with a domain-separation prefix.
fn hash_with_prefix(prefix: &[u8], data: &[u8]) -> k256::Scalar {
    let hash = Sha256::new()
        .chain_update(prefix)
        .chain_update(data)
        .finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash);
    use num_bigint::BigUint;
    use num_traits::Num;
    let val = BigUint::from_bytes_be(&bytes);
    let q = BigUint::from_str_radix(tecdsa_class_group::bicycl_glue::SECP256K1_ORDER, 10).unwrap();
    let reduced = val % &q;
    tecdsa_curve::conv::biguint_to_scalar::<k256::Secp256k1>(&reduced)
}

/// Compute the message hash $m = H_{sig}(msg)$.
pub fn hash_sig(msg: &[u8]) -> k256::Scalar {
    hash_with_prefix(b"THRESHOLD_ECDSA_SIGNATURE", msg)
}

/// Compute $z = H_1(X, msg, \{pm_j\})$.
fn hash_h1(
    public_key: &k256::ProjectivePoint,
    msg: &[u8],
    presign_messages: &[PresignMessage],
) -> k256::Scalar {
    let mut data = Vec::new();
    data.extend_from_slice(&public_key.to_bytes());
    data.extend_from_slice(msg);
    for pm in presign_messages {
        data.extend_from_slice(&pm.big_k.to_bytes());
        data.extend_from_slice(&pm.big_gamma.to_bytes());
    }
    hash_with_prefix(b"THRESHOLD_ECDSA_H1", &data)
}

/// Compute $y = H_2(z)$.
fn hash_h2(z: &k256::Scalar) -> k256::Scalar {
    let z_bytes = z.to_repr();
    hash_with_prefix(b"THRESHOLD_ECDSA_H2", z_bytes.as_ref())
}

/// Compute Lagrange coefficient $\lambda_{i,P}$ for party at position `my_pos`
/// among the given 1-based `indices`, evaluated at x = 0.
fn lagrange_coefficient(indices: &[u16], my_pos: usize) -> k256::Scalar {
    let xi = k256::Scalar::from(u64::from(indices[my_pos]));
    let mut result = k256::Scalar::ONE;
    for (j, &idx) in indices.iter().enumerate() {
        if j == my_pos {
            continue;
        }
        let xj = k256::Scalar::from(u64::from(idx));
        let diff_inv = (xj - xi)
            .invert()
            .expect("distinct indices guarantee non-zero denominator");
        result *= xj * diff_inv;
    }
    result
}

/// Compute one party's partial signature in the LLZ25 sign phase.
///
/// This is the core computation of Round 2. All NIM decoding is done
/// locally -- no new messages are sent except $(w_i, u_i)$.
///
/// # Arguments
/// - `setup`: mutable CL setup (needed by NIM decode methods).
/// - `key_share`: this party's key share from keygen.
/// - `presign_state`: this party's presign state from Round 1.
/// - `presign_messages`: presign messages from ALL parties in the quorum.
/// - `pe_x_list`: `pe_{x,j}` ciphertexts from keygen for each party in quorum.
/// - `quorum_indices`: 1-based party indices in the quorum.
/// - `my_pos`: this party's position in the quorum (0-based).
/// - `msg`: the message to sign.
///
/// # Returns
/// `(partial_signature, r)` where `r = x(R) mod q`.
#[allow(clippy::too_many_arguments)]
pub fn compute_partial_signature(
    setup: &mut ClSetup,
    key_share: &Llz25KeyShare,
    presign_state: &PresignState,
    presign_messages: &[PresignMessage],
    pe_x_list: &[ClHsmqkCiphertext],
    quorum_indices: &[u16],
    my_pos: usize,
    msg: &[u8],
) -> Result<(PartialSignature, k256::Scalar), Llz25Error> {
    let n_quorum = quorum_indices.len();

    // Compute Lagrange coefficient for this party.
    let my_lambda = lagrange_coefficient(quorum_indices, my_pos);

    // Compute K = sum(K_j).
    let big_k: k256::ProjectivePoint = presign_messages.iter().fold(
        <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::IDENTITY,
        |acc, pm| acc + pm.big_k,
    );

    // Compute hash values.
    let m = hash_sig(msg);
    let z = hash_h1(&key_share.public_key, msg, presign_messages);
    let y = hash_h2(&z);

    // Compute R = K^z * g^y.
    let big_r = big_k * z + <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * y;
    let r = <k256::Secp256k1 as TecdsaCurve>::xcoord_mod_q(&big_r.to_affine());

    // Prepare NIM states.
    let pst = presign_state;

    // Accumulate sums for w_i and u_i.
    let mut alpha_beta_sum = k256::Scalar::ZERO;
    let mut mu_nu_sum = k256::Scalar::ZERO;

    // Create NIM context for decoding.
    let nim = Nim::new(setup);

    // Reconstruct NIM states.
    let st_k = NimStateB {
        s_bytes: pst.st_k_bytes.clone(),
    };
    let st_gamma = NimStateA {
        r_bytes: pst.st_gamma_r_bytes.clone(),
        x_bytes: pst.st_gamma_x_bytes.clone(),
    };
    let st_x = NimStateB {
        s_bytes: key_share.st_x_bytes.clone(),
    };

    for j in 0..n_quorum {
        if j == my_pos {
            continue;
        }

        let pm_j = &presign_messages[j];

        // alpha_{i,j} = NIM.Decode_B(pe_{gamma,j}, st_{k,i})
        let alpha_bytes = nim
            .decode_b(&pm_j.pe_gamma, &st_k)
            .map_err(|e| Llz25Error::ClassGroup(format!("decode_b alpha: {e}")))?;
        let alpha_ij = tecdsa_curve::conv::bytes_to_scalar::<k256::Secp256k1>(&alpha_bytes);

        // beta_{j,i} = NIM.Decode_A(pe_{k,j}, st_{gamma,i})
        let beta_bytes = nim
            .decode_a(&pm_j.pe_k, &st_gamma)
            .map_err(|e| Llz25Error::ClassGroup(format!("decode_a beta: {e}")))?;
        let beta_ji = tecdsa_curve::conv::bytes_to_scalar::<k256::Secp256k1>(&beta_bytes);

        alpha_beta_sum += alpha_ij + beta_ji;

        // mu_{i,j} = lambda_i * NIM.Decode_B(pe_{gamma,j}, st_{x,i})
        let mu_bytes = nim
            .decode_b(&pm_j.pe_gamma, &st_x)
            .map_err(|e| Llz25Error::ClassGroup(format!("decode_b mu: {e}")))?;
        let mu_ij = my_lambda * tecdsa_curve::conv::bytes_to_scalar::<k256::Secp256k1>(&mu_bytes);

        // nu_{j,i} = lambda_j * NIM.Decode_A(pe_{x,j}, st_{gamma,i})
        let lambda_j = lagrange_coefficient(quorum_indices, j);
        let nu_bytes = nim
            .decode_a(&pe_x_list[j], &st_gamma)
            .map_err(|e| Llz25Error::ClassGroup(format!("decode_a nu: {e}")))?;
        let nu_ji = lambda_j * tecdsa_curve::conv::bytes_to_scalar::<k256::Secp256k1>(&nu_bytes);

        mu_nu_sum += mu_ij + nu_ji;
    }

    // Self-product terms.
    let k_i_gamma_i = pst.k_i * pst.gamma_i;
    let lambda_i_x_i_gamma_i = my_lambda * key_share.secret_share * pst.gamma_i;

    // w_i = m * gamma_i + r * (lambda_i * x_i * gamma_i + sum(mu + nu))
    let w_i = m * pst.gamma_i + r * (lambda_i_x_i_gamma_i + mu_nu_sum);

    // u_i = y * gamma_i + z * (k_i * gamma_i + sum(alpha + beta))
    let u_i = y * pst.gamma_i + z * (k_i_gamma_i + alpha_beta_sum);

    Ok((PartialSignature { w_i, u_i }, r))
}

/// Combine partial signatures into a final ECDSA signature.
///
/// $w = \sum w_i$, $u = \sum u_i$, $\sigma = w \cdot u^{-1} \bmod q$.
/// The signature is $(r, \sigma)$.
pub fn combine_signatures(
    partials: &[PartialSignature],
    r: &k256::Scalar,
    public_key: &k256::ProjectivePoint,
    msg: &[u8],
) -> Result<Signature<k256::Secp256k1>, Llz25Error> {
    let w: k256::Scalar = partials.iter().map(|p| p.w_i).sum();
    let u: k256::Scalar = partials.iter().map(|p| p.u_i).sum();

    let u_inv = u
        .invert()
        .into_option()
        .ok_or_else(|| Llz25Error::Protocol("u is zero, cannot invert".into()))?;

    let sigma_raw = w * u_inv;

    // Low-S normalization (BIP-146).
    let sigma = low_s_normalize::<k256::Secp256k1>(sigma_raw);

    let sig = Signature { r: *r, s: sigma };

    // Verify the signature.
    let m = hash_sig(msg);
    let data = DataToSign::from_digest(m);
    verify_ecdsa::<k256::Secp256k1>(&sig, public_key, &data).map_err(|e| {
        Llz25Error::SignatureVerification(format!("combined signature verification failed: {e}"))
    })?;

    Ok(sig)
}
