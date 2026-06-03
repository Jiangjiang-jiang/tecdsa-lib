// SPDX-License-Identifier: GPL-3.0-or-later
//! Zero-knowledge proofs over CL-HSM class groups.
//!
//! Each sub-module implements a Sigma-protocol relation following the
//! Fiat-Shamir heuristic (SHA-256).  The naming convention `r_*` mirrors
//! the relation names used in the threshold ECDSA literature.

#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown
)]

pub mod r_aff_com;
pub mod r_bint;
pub mod r_cl_dl;
pub mod r_cl_dl_ec;
pub mod r_cl_kwlg;
pub mod r_com_kwlg;
pub mod r_ddh_cl;
pub mod r_dec_dl;
pub mod r_dl_cl;
pub mod r_el_cl;
pub mod r_enc;
pub mod r_enc_pc;
pub mod r_gdec_cl;
pub mod r_key;
pub mod r_m_aff_dl;
pub mod r_m_aff_dl_ec;
pub mod r_part_dec;
pub mod r_pc_dl;
pub mod r_ped_ec;
pub mod r_sh;

use num_bigint::BigUint;
use sha2::{Digest, Sha256};

use crate::cl::{ClResult, ClSetup, Qfi};

/// Hashes QFI elements + optional extra byte slices via SHA-256 and
/// returns the result reduced modulo `q` as big-endian bytes.
///
/// `label` is a domain-separation tag (e.g. `b"R_key"`) that prevents
/// cross-relation challenge collisions.  Each QFI is serialised via its
/// compact binary encoding (`to_bytes`).
///
/// Context-free challenge derivation. Prefer [`challenge_from_qfi_with_prefix`]
/// for new code that has session/party context available.
pub(crate) fn challenge_from_qfi(
    setup: &ClSetup,
    label: &[u8],
    qfi_elements: &[&Qfi],
    extra: &[&[u8]],
) -> ClResult<Vec<u8>> {
    let mut hasher = Sha256::new();
    hasher.update(label);

    for qfi in qfi_elements {
        let bytes = qfi.to_bytes();
        hasher.update(&bytes);
        hasher.update(b"||");
    }
    for s in extra {
        hasher.update(*s);
        hasher.update(b"||");
    }

    let hash = hasher.finalize();
    let hash_uint = BigUint::from_bytes_be(&hash);
    let q_bytes = setup.q_bytes()?;
    let q = BigUint::from_bytes_be(&q_bytes);
    let e = hash_uint % &q;
    Ok(e.to_bytes_be())
}

/// Like [`challenge_from_qfi`], but prepends an opaque context prefix before
/// the relation label and QFI elements. Use this when binding the challenge
/// to a session/party/round context.
pub(crate) fn challenge_from_qfi_with_prefix(
    setup: &ClSetup,
    prefix: &[u8],
    label: &[u8],
    qfi_elements: &[&Qfi],
    extra: &[&[u8]],
) -> ClResult<Vec<u8>> {
    let mut hasher = Sha256::new();
    hasher.update(prefix);
    hasher.update(label);

    for qfi in qfi_elements {
        let bytes = qfi.to_bytes();
        hasher.update(&bytes);
        hasher.update(b"||");
    }
    for s in extra {
        hasher.update(*s);
        hasher.update(b"||");
    }

    let hash = hasher.finalize();
    let hash_uint = BigUint::from_bytes_be(&hash);
    let q_bytes = setup.q_bytes()?;
    let q = BigUint::from_bytes_be(&q_bytes);
    let e = hash_uint % &q;
    Ok(e.to_bytes_be())
}

/// Samples a random value in `[0, secretkey_bound)` by generating a
/// keypair and extracting the secret key scalar as big-endian bytes.
pub(crate) fn sample_random(setup: &mut ClSetup) -> ClResult<Vec<u8>> {
    let (sk, _pk) = setup.keygen()?;
    setup.sk_to_bytes(&sk)
}

/// Samples a random value in `[0, q)` by sampling a larger value and
/// reducing modulo q, returned as big-endian bytes.
pub(crate) fn sample_random_mod_q(setup: &mut ClSetup) -> ClResult<Vec<u8>> {
    let r = sample_random(setup)?;
    let r_uint = BigUint::from_bytes_be(&r);
    let q_bytes = setup.q_bytes()?;
    let q = BigUint::from_bytes_be(&q_bytes);
    let reduced = r_uint % &q;
    Ok(reduced.to_bytes_be())
}

/// Computes `(a + e * w) mod q` for big-integer big-endian byte slices.
pub(crate) fn response_mod_q(a: &[u8], e: &[u8], w: &[u8], q: &[u8]) -> ClResult<Vec<u8>> {
    let a = BigUint::from_bytes_be(a);
    let e = BigUint::from_bytes_be(e);
    let w = BigUint::from_bytes_be(w);
    let q = BigUint::from_bytes_be(q);
    let resp = (&a + &e * &w) % &q;
    Ok(resp.to_bytes_be())
}

/// Computes `a + e * w` (unbounded, for class-group exponents),
/// returned as big-endian bytes.
pub(crate) fn response_unbounded(a: &[u8], e: &[u8], w: &[u8]) -> ClResult<Vec<u8>> {
    let a = BigUint::from_bytes_be(a);
    let e = BigUint::from_bytes_be(e);
    let w = BigUint::from_bytes_be(w);
    let resp = &a + &e * &w;
    Ok(resp.to_bytes_be())
}

/// Verifies an F-subgroup Schnorr check in scalar arithmetic:
/// `z == dlog_in_F(t) + e * dlog_in_F(Y) mod q`.
///
/// This is needed because F-subgroup elements from `power_of_f` cannot
/// be composed/exponentiated via `Cl(Delta)` operations.
#[allow(non_snake_case)]
pub(crate) fn verify_f_check(
    setup: &ClSetup,
    z_bytes: &[u8],
    t_qfi: &Qfi,
    e_bytes: &[u8],
    y_qfi: &Qfi,
) -> ClResult<bool> {
    let dlog_t = setup.dlog_in_F_bytes(t_qfi)?;
    let dlog_y = setup.dlog_in_F_bytes(y_qfi)?;

    let q_bytes = setup.q_bytes()?;
    let q = BigUint::from_bytes_be(&q_bytes);
    let dt = BigUint::from_bytes_be(&dlog_t);
    let dy = BigUint::from_bytes_be(&dlog_y);
    let ev = BigUint::from_bytes_be(e_bytes);
    let zv = BigUint::from_bytes_be(z_bytes);

    let expected = (&dt + &ev * &dy) % &q;
    let z_mod = &zv % &q;

    Ok(expected == z_mod)
}
