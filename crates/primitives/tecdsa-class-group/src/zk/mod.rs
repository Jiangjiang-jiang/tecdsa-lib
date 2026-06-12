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
    let q_bytes = setup.q_bytes()?;
    let q = Integer::from_digits(&q_bytes, Order::Msf);
    let e = hash_uint % &q;
    Ok(e.to_digits::<u8>(Order::Msf))
}

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
    let q_bytes = setup.q_bytes()?;
    let q = Integer::from_digits(&q_bytes, Order::Msf);
    let e = hash_uint % &q;
    Ok(e.to_digits::<u8>(Order::Msf))
}

pub(crate) fn sample_random(setup: &mut ClSetup) -> ClResult<Vec<u8>> {
    let (sk, _pk) = setup.keygen()?;
    setup.sk_to_bytes(&sk)
}

pub(crate) fn sample_random_mod_q(setup: &mut ClSetup) -> ClResult<Vec<u8>> {
    let r = sample_random(setup)?;
    let r_uint = Integer::from_digits(&r, Order::Msf);
    let q_bytes = setup.q_bytes()?;
    let q = Integer::from_digits(&q_bytes, Order::Msf);
    let reduced = r_uint % &q;
    Ok(reduced.to_digits::<u8>(Order::Msf))
}

pub(crate) fn response_mod_q(a: &[u8], e: &[u8], w: &[u8], q: &[u8]) -> ClResult<Vec<u8>> {
    let a = Integer::from_digits(a, Order::Msf);
    let e = Integer::from_digits(e, Order::Msf);
    let w = Integer::from_digits(w, Order::Msf);
    let q = Integer::from_digits(q, Order::Msf);
    let resp = (&a + Integer::from(&e * &w)) % &q;
    Ok(resp.to_digits::<u8>(Order::Msf))
}

pub(crate) fn response_unbounded(a: &[u8], e: &[u8], w: &[u8]) -> ClResult<Vec<u8>> {
    let a = Integer::from_digits(a, Order::Msf);
    let e = Integer::from_digits(e, Order::Msf);
    let w = Integer::from_digits(w, Order::Msf);
    let resp = &a + Integer::from(&e * &w);
    Ok(resp.to_digits::<u8>(Order::Msf))
}

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
    let q = Integer::from_digits(&q_bytes, Order::Msf);
    let dt = Integer::from_digits(&dlog_t, Order::Msf);
    let dy = Integer::from_digits(&dlog_y, Order::Msf);
    let ev = Integer::from_digits(e_bytes, Order::Msf);
    let zv = Integer::from_digits(z_bytes, Order::Msf);

    let expected = (&dt + Integer::from(&ev * &dy)) % &q;
    let z_mod = zv % &q;

    Ok(expected == z_mod)
}
