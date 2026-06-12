pub mod machine;

use rug::{integer::Order, Integer};
use tecdsa_class_group::{
    cl::ClSetup,
    scaled_decrypt::{
        aggregate_and_solve, aggregate_ciphertext_components, aggregate_commitments,
        compute_f_share, ScaledDecryptPartyInput, ScaledDecryptPublic,
    },
};
use tecdsa_protocol::ecdsa::{low_s_normalize, verify_ecdsa, DataToSign, Signature};

use crate::{
    error::{qfi_from_abc, TroutError, TroutResult},
    key_share::TroutKeyShare,
    presign::types::TroutPresignOutput,
};

pub fn sign_round2(
    all_presigns: &[TroutPresignOutput],
    message: &DataToSign<k256::Secp256k1>,
    share: &TroutKeyShare,
    setup: &ClSetup,
    cl_pk: &tecdsa_class_group::cl::ClPublicKey,
) -> TroutResult<Signature<k256::Secp256k1>> {
    let _n = all_presigns.len();
    let r_scalar = all_presigns[0].r_scalar;
    let r_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&r_scalar);
    let m_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(message.digest());

    let broadcasts = &all_presigns[0].all_broadcasts;

    for bcast in broadcasts {
        let (c1_a, c1_b, c1_c) = &bcast.kt_c1_abc;
        let (c2_a, c2_b, c2_c) = &bcast.kt_c2_abc;
        let c1 = qfi_from_abc(c1_a, c1_b, c1_c)?;
        let c2 = qfi_from_abc(c2_a, c2_b, c2_c)?;
        let kt_ct = setup.ct_from_components(&c1, &c2)?;

        let cl_ec_ok = bcast
            .pi_cl_ec
            .verify(setup, cl_pk, &kt_ct, &bcast.r_i_bytes)?;
        if !cl_ec_ok {
            return Err(TroutError::ProofFailed(format!(
                "R_CL-EC proof failed for party {}",
                bcast.party_index
            )));
        }
    }

    let pk_elt = cl_pk.elt();
    for bcast in broadcasts {
        let (a, b, c) = &bcast.u_com_abc;
        let u_com = qfi_from_abc(a, b, c)?;

        let com_kwlg_ok = bcast.pi_com_kwlg.verify_with_base(setup, &u_com, pk_elt)?;
        if !com_kwlg_ok {
            return Err(TroutError::ProofFailed(format!(
                "R_ComKwlg proof failed for party {}",
                bcast.party_index
            )));
        }
    }

    let mut kt_components = Vec::new();
    for bcast in broadcasts {
        let (c1_a, c1_b, c1_c) = &bcast.kt_c1_abc;
        let (c2_a, c2_b, c2_c) = &bcast.kt_c2_abc;
        let c1 = qfi_from_abc(c1_a, c1_b, c1_c)?;
        let c2 = qfi_from_abc(c2_a, c2_b, c2_c)?;
        kt_components.push((c1, c2));
    }

    let mut u_coms = Vec::new();
    for bcast in broadcasts {
        let (a, b, c) = &bcast.u_com_abc;
        let u = qfi_from_abc(a, b, c)?;
        u_coms.push(u);
    }

    let mut ct_scaled_components = Vec::new();
    for bcast in broadcasts {
        let (c1_a, c1_b, c1_c) = &bcast.ct_scaled_c1_abc;
        let (c2_a, c2_b, c2_c) = &bcast.ct_scaled_c2_abc;
        let c1 = qfi_from_abc(c1_a, c1_b, c1_c)?;
        let c2 = qfi_from_abc(c2_a, c2_b, c2_c)?;
        ct_scaled_components.push((c1, c2));
    }

    let mut z_components = Vec::new();
    for (c1, c2) in &ct_scaled_components {
        let z_c1 = setup.exp_bytes(c1, &r_bytes)?;
        let z_c2 = setup.exp_bytes(c2, &r_bytes)?;
        z_components.push((z_c1, z_c2));
    }

    let f_m = setup.power_of_f_bytes(&m_bytes)?;
    let (old_c1, old_c2) = z_components.remove(0);
    let new_z0_c2 = setup.compose(&old_c2, &f_m)?;
    z_components.insert(0, (old_c1, new_z0_c2));

    let (kt_a1, kt_a2) = aggregate_ciphertext_components(setup, &kt_components)?;
    let u_b_agg = aggregate_commitments(setup, &u_coms)?;

    let sd1_public = ScaledDecryptPublic {
        a1: kt_a1,
        a2: kt_a2,
        b_agg: u_b_agg,
    };

    let sd1_inputs: Vec<ScaledDecryptPartyInput> = all_presigns
        .iter()
        .map(|p| ScaledDecryptPartyInput {
            alpha_i: p.alpha_i.clone(),
            beta_i: p.beta_i.clone(),
            b_i: tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&p.u_i),
        })
        .collect();

    let mut f1_shares = Vec::new();
    for input in &sd1_inputs {
        let f_i = compute_f_share(setup, input, &sd1_public)?;
        f1_shares.push(f_i);
    }
    let uk = tecdsa_curve::conv::bytes_to_scalar::<k256::Secp256k1>(&aggregate_and_solve(
        setup, &f1_shares,
    )?);

    let (z_a1, z_a2) = aggregate_ciphertext_components(setup, &z_components)?;
    let u_b_agg2 = aggregate_commitments(setup, &u_coms)?;

    let sd2_public = ScaledDecryptPublic {
        a1: z_a1,
        a2: z_a2,
        b_agg: u_b_agg2,
    };

    let sd2_inputs: Vec<ScaledDecryptPartyInput> = all_presigns
        .iter()
        .map(|p| {
            let r_val = Integer::from_digits(
                &tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&r_scalar),
                Order::Msf,
            );
            let lid_val = Integer::from_digits(&p.l_i_delta_i, Order::Msf);
            let alpha_z = Integer::from(&r_val * &lid_val).to_digits::<u8>(Order::Msf);

            ScaledDecryptPartyInput {
                alpha_i: alpha_z,
                beta_i: p.beta_i.clone(),
                b_i: tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&p.u_i),
            }
        })
        .collect();

    let mut f2_shares = Vec::new();
    for input in &sd2_inputs {
        let f_i = compute_f_share(setup, input, &sd2_public)?;
        f2_shares.push(f_i);
    }
    let u_mx = tecdsa_curve::conv::bytes_to_scalar::<k256::Secp256k1>(&aggregate_and_solve(
        setup, &f2_shares,
    )?);

    let uk_inv = uk
        .invert()
        .into_option()
        .ok_or_else(|| TroutError::EcdsaFailed("u*k is zero, cannot invert".into()))?;

    let s = uk_inv * u_mx;
    let s = low_s_normalize::<k256::Secp256k1>(s);

    let sig = Signature { r: r_scalar, s };

    verify_ecdsa::<k256::Secp256k1>(&sig, &share.public_key, message)
        .map_err(|e| TroutError::EcdsaFailed(format!("final verification: {e}")))?;

    Ok(sig)
}

pub fn identify_cheater(
    f_shares: &[tecdsa_class_group::scaled_decrypt::ScaledDecryptShare],
    setup: &ClSetup,
    cl_pk: &tecdsa_class_group::cl::ClPublicKey,
    ct_in: &tecdsa_class_group::cl::ClCiphertext,
    u_coms: &[tecdsa_class_group::cl::Qfi],
) -> Option<usize> {
    for (i, share) in f_shares.iter().enumerate() {
        if let Some(ref proof) = share.pi_aff_com {
            let identity = match setup.identity() {
                Ok(id) => id,
                Err(_) => return Some(i),
            };
            let ct_out = match setup.ct_from_components(&identity, &share.f_i) {
                Ok(ct) => ct,
                Err(_) => return Some(i),
            };
            match proof.verify(setup, cl_pk, ct_in, &ct_out, &u_coms[i]) {
                Ok(true) => continue,
                _ => return Some(i),
            }
        }
    }
    None
}
