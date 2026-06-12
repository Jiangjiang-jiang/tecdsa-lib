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

pub fn presign_round1(
    share: &TroutKeyShare,
    signing_parties: &[u16],
    session_nonce: &[u8],
    setup: &mut ClSetup,
    cl_pk: &tecdsa_class_group::cl::ClPublicKey,
    rng: &mut impl CryptoRngCore,
) -> TroutResult<(TroutRound1State, TroutRound1Broadcast)> {
    let my_idx = share.party_index;

    let (evrf_output, evrf_proof) = share.evrf_sk.eval(session_nonce, rng);
    let k_i = *share.evrf_sk.scalar();

    let k_i_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&k_i);
    let r_i_proj = <k256::Secp256k1 as TecdsaCurve>::generator() * k_i;
    let r_i_affine = elliptic_curve::group::Curve::to_affine(&r_i_proj);
    let r_i_bytes = <k256::Secp256k1 as TecdsaCurve>::point_to_bytes(&r_i_affine);

    let u_i = <k256::Secp256k1 as TecdsaCurve>::random_scalar(&mut *rng);
    let u_i_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&u_i);

    let (sk_tmp, _) = setup.keygen()?;
    let alpha_i = setup.sk_to_bytes(&sk_tmp)?;

    let (sk_tmp2, _) = setup.keygen()?;
    let beta_i = setup.sk_to_bytes(&sk_tmp2)?;

    let kt_ct = setup.encrypt_with_r_bytes(cl_pk, &k_i_bytes, &alpha_i)?;
    let (kt_c1, kt_c2) = setup.ct_components(&kt_ct)?;

    let pk_elt = cl_pk.elt();
    let h_beta = setup.power_of_h_bytes(&beta_i)?;
    let pk_u = setup.exp_bytes(pk_elt, &u_i_bytes)?;
    let u_com = setup.compose(&h_beta, &pk_u)?;

    let lagrange_coeffs = tecdsa_vss::lagrange::coefficients::<k256::Secp256k1>(signing_parties);
    let my_party_pos = signing_parties
        .iter()
        .position(|&p| p == my_idx)
        .ok_or_else(|| TroutError::InvalidParam("party not in signing set".into()))?;
    let l_i = lagrange_coeffs[my_party_pos];
    let l_i_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&l_i);

    let (c1_a, c1_b, c1_c, c2_a, c2_b, c2_c) = &share.ct_share_components;
    let ct_c1 = qfi_from_abc(c1_a, c1_b, c1_c)?;
    let ct_c2 = qfi_from_abc(c2_a, c2_b, c2_c)?;

    let ct_scaled_c1 = setup.exp_bytes(&ct_c1, &l_i_bytes)?;
    let ct_scaled_c2 = setup.exp_bytes(&ct_c2, &l_i_bytes)?;

    let l_i_val = Integer::from_digits(&l_i_bytes, Order::Msf);
    let delta_i_val = Integer::from_digits(&share.delta_i, Order::Msf);
    let l_i_delta_i = Integer::from(&l_i_val * &delta_i_val).to_digits::<u8>(Order::Msf);

    let pi_cl_ec = RClDlEcProof::prove(setup, cl_pk, &kt_ct, &r_i_bytes, &k_i_bytes, &alpha_i)?;

    let pi_com_kwlg = RComKwlgProof::prove_with_base(setup, &u_com, pk_elt, &u_i_bytes, &beta_i)?;

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
