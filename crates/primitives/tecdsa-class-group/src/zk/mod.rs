// SPDX-License-Identifier: MIT OR Apache-2.0
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
pub mod r_blnt;
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

use rug::{integer::Order, Integer};
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
    let hash_uint = Integer::from_digits(&hash, Order::Msf);
    let e = hash_uint % setup.cl().q();
    Ok(e.to_digits::<u8>(Order::Msf))
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
    let hash_uint = Integer::from_digits(&hash, Order::Msf);
    let e = hash_uint % setup.cl().q();
    Ok(e.to_digits::<u8>(Order::Msf))
}

/// Samples a random value in `[0, secretkey_bound)` by generating a
/// keypair and extracting the secret key scalar.
pub(crate) fn sample_random(setup: &mut ClSetup) -> ClResult<Integer> {
    let (sk, _pk) = setup.keygen()?;
    Ok(setup.sk_to_integer(&sk))
}

/// Samples a random value in `[0, q)` by sampling a larger value and
/// reducing modulo q.
pub(crate) fn sample_random_mod_q(setup: &mut ClSetup) -> ClResult<Integer> {
    let r = sample_random(setup)?;
    Ok(r.modulo(setup.cl().q()))
}

/// Computes `(a + e * w) mod q`, with the Fiat-Shamir challenge `e` given as
/// big-endian bytes (as stored in a proof's wire field), returned as
/// big-endian bytes.
pub(crate) fn response_mod_q(a: &Integer, e: &[u8], w: &Integer, q: &Integer) -> Vec<u8> {
    let e = Integer::from_digits(e, Order::Msf);
    let resp = (a + e * w).modulo(q);
    resp.to_digits::<u8>(Order::Msf)
}

/// Computes `a + e * w` (unbounded, for class-group exponents), with the
/// Fiat-Shamir challenge `e` given as big-endian bytes (as stored in a
/// proof's wire field), returned as big-endian bytes.
pub(crate) fn response_unbounded(a: &Integer, e: &[u8], w: &Integer) -> Vec<u8> {
    let e = Integer::from_digits(e, Order::Msf);
    let resp = a + e * w;
    resp.to_digits::<u8>(Order::Msf)
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
    let dt = setup.dlog_in_F(t_qfi)?;
    let dy = setup.dlog_in_F(y_qfi)?;

    let q = setup.cl().q();
    let ev = Integer::from_digits(e_bytes, Order::Msf);
    let zv = Integer::from_digits(z_bytes, Order::Msf);

    let expected = (dt + ev * dy) % q;
    let z_mod = zv % q;

    Ok(expected == z_mod)
}
