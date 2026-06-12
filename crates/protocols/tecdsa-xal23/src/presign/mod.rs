#![allow(non_snake_case)]

pub mod machine;
pub mod msg;
pub mod rounds;
mod types;

use elliptic_curve::{
    group::{Curve as CurveGroup, Group},
    sec1::ModulusSize,
    Field, FieldBytes, FieldBytesSize, PrimeField,
};
pub use machine::Xal23PresignMachine;
pub use msg::Xal23PresignMsg;
use rug::{integer::Order, Integer};
use tecdsa_curve::{
    conv::{curve_order, integer_to_scalar, scalar_to_integer},
    TecdsaCurve,
};
use tecdsa_joye_libert::mta::{JlMtA, JlMtaSetup};
use tecdsa_protocol::{MtA, PartyId};
pub use types::Xal23Presignature;

use crate::key_share::Xal23KeyShare;

pub fn presign_all<C: TecdsaCurve>(
    key_shares: &[Xal23KeyShare<C>],
    signer_indices: &[usize],
    rng: &mut impl rand_core::CryptoRngCore,
) -> Vec<Xal23Presignature<C>>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    presign_all_with_sec(key_shares, signer_indices, 40, 40, rng)
}

pub fn presign_all_with_sec<C: TecdsaCurve>(
    key_shares: &[Xal23KeyShare<C>],
    signer_indices: &[usize],
    s: u32,
    t: u32,
    rng: &mut impl rand_core::CryptoRngCore,
) -> Vec<Xal23Presignature<C>>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let setups: Vec<Vec<JlMtaSetup>> = signer_indices
        .iter()
        .map(|&idx| {
            signer_indices
                .iter()
                .map(|&peer_idx| JlMtaSetup {
                    pk: key_shares[peer_idx].jl_pks[peer_idx].clone(),
                    pk0: key_shares[idx].jl_pks[idx].clone(),
                    sk: key_shares[peer_idx].jl_sk.clone(),
                    s,
                    t,
                })
                .collect()
        })
        .collect();

    presign_all_generic::<C, JlMtA>(key_shares, signer_indices, &setups, rng)
}

pub fn presign_all_generic<C: TecdsaCurve, M: MtA>(
    key_shares: &[Xal23KeyShare<C>],
    signer_indices: &[usize],
    mta_setups: &[Vec<M::Setup>],
    rng: &mut impl rand_core::CryptoRngCore,
) -> Vec<Xal23Presignature<C>>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let n = signer_indices.len();
    let q = curve_order::<C>();
    let q_bytes = q.to_digits::<u8>(Order::Msf);

    let mut k_vec: Vec<C::Scalar> = Vec::with_capacity(n);
    let mut gamma_vec: Vec<C::Scalar> = Vec::with_capacity(n);
    let mut g_gamma_vec: Vec<C::ProjectivePoint> = Vec::with_capacity(n);

    for _ in 0..n {
        let k_i = C::random_scalar(rng);
        let gamma_i = C::random_scalar(rng);
        let g_gamma_i = C::generator() * gamma_i;
        k_vec.push(k_i);
        gamma_vec.push(gamma_i);
        g_gamma_vec.push(g_gamma_i);
    }

    let w_vec: Vec<C::Scalar> = signer_indices
        .iter()
        .map(|&idx| key_shares[idx].secret_share)
        .collect();

    let mut alpha_kg = vec![vec![Integer::new(); n]; n];
    let mut beta_kg = vec![vec![Integer::new(); n]; n];

    let mut mu_kw = vec![vec![Integer::new(); n]; n];
    let mut nu_kw = vec![vec![Integer::new(); n]; n];

    for i in 0..n {
        for j in 0..n {
            if i == j {
                continue;
            }

            let setup_j = &mta_setups[i][j];

            {
                let k_i_bytes = scalar_to_integer::<C>(&k_vec[i]).to_digits::<u8>(Order::Msf);
                let gamma_j_bytes =
                    scalar_to_integer::<C>(&gamma_vec[j]).to_digits::<u8>(Order::Msf);

                let (sender_msg, sender_state) =
                    M::sender_encrypt(setup_j, &gamma_j_bytes, &q_bytes, rng)
                        .expect("MtA sender_encrypt failed");

                let (receiver_msg, alpha_bytes) =
                    M::receiver_compute(setup_j, &k_i_bytes, &q_bytes, &sender_msg, rng)
                        .expect("MtA receiver_compute failed");

                let beta_bytes = M::sender_decrypt(setup_j, &sender_state, &q_bytes, &receiver_msg)
                    .expect("MtA sender_decrypt failed");

                alpha_kg[i][j] = Integer::from_digits(&alpha_bytes, Order::Msf);
                beta_kg[i][j] = Integer::from_digits(&beta_bytes, Order::Msf);
            }

            {
                let k_i_bytes = scalar_to_integer::<C>(&k_vec[i]).to_digits::<u8>(Order::Msf);
                let w_j_bytes = scalar_to_integer::<C>(&w_vec[j]).to_digits::<u8>(Order::Msf);

                let (sender_msg, sender_state) =
                    M::sender_encrypt(setup_j, &w_j_bytes, &q_bytes, rng)
                        .expect("MtA sender_encrypt failed");

                let (receiver_msg, mu_bytes) =
                    M::receiver_compute(setup_j, &k_i_bytes, &q_bytes, &sender_msg, rng)
                        .expect("MtA receiver_compute failed");

                let nu_bytes = M::sender_decrypt(setup_j, &sender_state, &q_bytes, &receiver_msg)
                    .expect("MtA sender_decrypt failed");

                mu_kw[i][j] = Integer::from_digits(&mu_bytes, Order::Msf);
                nu_kw[i][j] = Integer::from_digits(&nu_bytes, Order::Msf);
            }
        }
    }

    let mut delta_vec: Vec<C::Scalar> = Vec::with_capacity(n);

    for i in 0..n {
        let mut delta_i = k_vec[i] * gamma_vec[i];
        for j in 0..n {
            if i == j {
                continue;
            }
            delta_i += integer_to_scalar::<C>(&alpha_kg[i][j]);
            delta_i += integer_to_scalar::<C>(&beta_kg[j][i]);
        }
        delta_vec.push(delta_i);
    }

    let delta: C::Scalar = delta_vec.iter().fold(C::Scalar::ZERO, |acc, d| acc + d);

    let delta_inv = delta
        .invert()
        .into_option()
        .expect("delta should be invertible");

    let Gamma: C::ProjectivePoint = g_gamma_vec
        .iter()
        .fold(C::ProjectivePoint::identity(), |acc, g| acc + g);

    let R = Gamma * delta_inv;
    let R_affine = R.to_affine();
    let r = C::xcoord_mod_q(&R_affine);

    let mut sigma_vec: Vec<C::Scalar> = Vec::with_capacity(n);
    for i in 0..n {
        let mut sigma_i = k_vec[i] * w_vec[i];
        for j in 0..n {
            if i == j {
                continue;
            }
            sigma_i += integer_to_scalar::<C>(&mu_kw[i][j]);
            sigma_i += integer_to_scalar::<C>(&nu_kw[j][i]);
        }
        sigma_vec.push(sigma_i);
    }

    let mut presigs = Vec::with_capacity(n);
    for i in 0..n {
        presigs.push(Xal23Presignature {
            R,
            r,
            k_i: k_vec[i],
            sigma_i: sigma_vec[i],
            public_key: key_shares[signer_indices[i]].public_key,
            my_id: PartyId(signer_indices[i] as u16),
            signer_parties: signer_indices
                .iter()
                .map(|&idx| PartyId(idx as u16))
                .collect(),
        });
    }

    presigs
}

#[allow(dead_code)]
fn compute_lagrange_coeff<C: TecdsaCurve>(party_index: usize, signer_indices: &[usize]) -> C::Scalar
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let x_i = C::Scalar::from(party_index as u64 + 1);
    let mut num = C::Scalar::ONE;
    let mut den = C::Scalar::ONE;
    for &j_idx in signer_indices {
        if j_idx == party_index {
            continue;
        }
        let x_j = C::Scalar::from(j_idx as u64 + 1);
        num *= x_j;
        den *= x_j - x_i;
    }
    let den_inv = den
        .invert()
        .into_option()
        .expect("Lagrange denominator should be invertible");
    num * den_inv
}
