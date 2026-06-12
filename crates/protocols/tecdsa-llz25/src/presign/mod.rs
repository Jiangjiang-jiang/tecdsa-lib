#![allow(non_snake_case)]

pub mod machine;

use elliptic_curve::{group::GroupEncoding, CurveArithmetic};
use tecdsa_class_group::{
    cl::{ClCiphertext as ClHsmqkCiphertext, ClPublicKey as ClHsmqkPublicKey, ClSetup, Qfi},
    nim::{Nim, NimEncodeAOutput, NimEncodeBOutput, NimStateA, NimStateB},
    zk::{r_cl_dl_ec::RClDlEcProof, r_ped_ec::RPedEcProof},
};
use tecdsa_curve::TecdsaCurve;
use zeroize::Zeroize;

use crate::{error::Llz25Error, key_share::Llz25KeyShare};

pub struct PresignMessage {
    pub big_k: k256::ProjectivePoint,
    pub big_gamma: k256::ProjectivePoint,
    pub pe_k: ClHsmqkCiphertext,
    pub pe_gamma: Qfi,
    pub proof_cl: RClDlEcProof,
    pub proof_ped: RPedEcProof,
}

pub struct PresignState {
    pub k_i: k256::Scalar,
    pub gamma_i: k256::Scalar,
    pub st_k_bytes: Vec<u8>,
    pub st_gamma_r_bytes: Vec<u8>,
    pub st_gamma_x_bytes: Vec<u8>,
}

impl Zeroize for PresignState {
    fn zeroize(&mut self) {
        self.k_i.zeroize();
        self.gamma_i.zeroize();
        self.st_k_bytes.zeroize();
        self.st_gamma_r_bytes.zeroize();
        self.st_gamma_x_bytes.zeroize();
    }
}

impl Drop for PresignState {
    fn drop(&mut self) {
        self.zeroize();
    }
}

pub fn presign_round1(
    setup: &mut ClSetup,
    pk_crs: &ClHsmqkPublicKey,
) -> Result<(PresignMessage, PresignState), Llz25Error> {
    let mut rng = rand::thread_rng();

    let k_i = k256::Secp256k1::random_scalar(&mut rng);
    let gamma_i = k256::Secp256k1::random_scalar(&mut rng);

    let big_k = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * k_i;
    let big_gamma = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * gamma_i;

    let k_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&k_i);
    let gamma_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&gamma_i);

    let mut nim = Nim::new(setup);
    let NimEncodeBOutput {
        pe_b: pe_k,
        state: st_k,
    } = nim
        .encode_b(&k_bytes, pk_crs)
        .map_err(|e| Llz25Error::ClassGroup(format!("NIM.Encode_B(k_i) failed: {e}")))?;

    let NimEncodeAOutput {
        pe_a: pe_gamma,
        state: st_gamma,
    } = nim
        .encode_a(&gamma_bytes, pk_crs)
        .map_err(|e| Llz25Error::ClassGroup(format!("NIM.Encode_A(gamma_i) failed: {e}")))?;

    let big_k_bytes = big_k.to_bytes().to_vec();
    let proof_cl = RClDlEcProof::prove(setup, pk_crs, &pe_k, &big_k_bytes, &k_bytes, &st_k.s_bytes)
        .map_err(|e| Llz25Error::ClassGroup(format!("R_CL_DL_EC prove failed: {e}")))?;

    let big_gamma_bytes = big_gamma.to_bytes().to_vec();
    let proof_ped = RPedEcProof::prove(
        setup,
        pk_crs,
        &pe_gamma,
        &big_gamma_bytes,
        &gamma_bytes,
        &st_gamma.r_bytes,
    )
    .map_err(|e| Llz25Error::ClassGroup(format!("R_Ped_EC prove failed: {e}")))?;

    let message = PresignMessage {
        big_k,
        big_gamma,
        pe_k,
        pe_gamma,
        proof_cl,
        proof_ped,
    };

    let state = PresignState {
        k_i,
        gamma_i,
        st_k_bytes: st_k.s_bytes,
        st_gamma_r_bytes: st_gamma.r_bytes,
        st_gamma_x_bytes: st_gamma.x_bytes,
    };

    Ok((message, state))
}

pub fn verify_presign_message(
    setup: &ClSetup,
    pk_crs: &ClHsmqkPublicKey,
    msg: &PresignMessage,
) -> Result<bool, Llz25Error> {
    let big_k_bytes = msg.big_k.to_bytes().to_vec();
    let big_gamma_bytes = msg.big_gamma.to_bytes().to_vec();

    let cl_ok = msg
        .proof_cl
        .verify(setup, pk_crs, &msg.pe_k, &big_k_bytes)
        .map_err(|e| Llz25Error::ClassGroup(format!("R_CL_DL_EC verify failed: {e}")))?;

    let ped_ok = msg
        .proof_ped
        .verify(setup, pk_crs, &msg.pe_gamma, &big_gamma_bytes)
        .map_err(|e| Llz25Error::ClassGroup(format!("R_Ped_EC verify failed: {e}")))?;

    Ok(cl_ok && ped_ok)
}

pub struct PresignCoefficients {
    pub gamma_i: k256::Scalar,
    pub u_coeff: k256::Scalar,
    pub w_coeff: k256::Scalar,
}

impl Zeroize for PresignCoefficients {
    fn zeroize(&mut self) {
        self.gamma_i.zeroize();
        self.u_coeff.zeroize();
        self.w_coeff.zeroize();
    }
}

impl Drop for PresignCoefficients {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl std::fmt::Debug for PresignCoefficients {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PresignCoefficients").finish_non_exhaustive()
    }
}

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

#[allow(clippy::too_many_arguments)]
pub fn compute_presign_coefficients(
    setup: &mut ClSetup,
    key_share: &Llz25KeyShare,
    presign_state: &PresignState,
    presign_messages: &[PresignMessage],
    pe_x_list: &[ClHsmqkCiphertext],
    quorum_indices: &[u16],
    my_pos: usize,
) -> Result<PresignCoefficients, Llz25Error> {
    let n_quorum = quorum_indices.len();

    let my_lambda = lagrange_coefficient(quorum_indices, my_pos);

    let pst = presign_state;

    let mut alpha_beta_sum = k256::Scalar::ZERO;
    let mut mu_nu_sum = k256::Scalar::ZERO;

    let nim = Nim::new(setup);

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

        let alpha_bytes = nim
            .decode_b(&pm_j.pe_gamma, &st_k)
            .map_err(|e| Llz25Error::ClassGroup(format!("decode_b alpha: {e}")))?;
        let alpha_ij = tecdsa_curve::conv::bytes_to_scalar::<k256::Secp256k1>(&alpha_bytes);

        let beta_bytes = nim
            .decode_a(&pm_j.pe_k, &st_gamma)
            .map_err(|e| Llz25Error::ClassGroup(format!("decode_a beta: {e}")))?;
        let beta_ji = tecdsa_curve::conv::bytes_to_scalar::<k256::Secp256k1>(&beta_bytes);

        alpha_beta_sum += alpha_ij + beta_ji;

        let mu_bytes = nim
            .decode_b(&pm_j.pe_gamma, &st_x)
            .map_err(|e| Llz25Error::ClassGroup(format!("decode_b mu: {e}")))?;
        let mu_ij = my_lambda * tecdsa_curve::conv::bytes_to_scalar::<k256::Secp256k1>(&mu_bytes);

        let lambda_j = lagrange_coefficient(quorum_indices, j);
        let nu_bytes = nim
            .decode_a(&pe_x_list[j], &st_gamma)
            .map_err(|e| Llz25Error::ClassGroup(format!("decode_a nu: {e}")))?;
        let nu_ji = lambda_j * tecdsa_curve::conv::bytes_to_scalar::<k256::Secp256k1>(&nu_bytes);

        mu_nu_sum += mu_ij + nu_ji;
    }

    let k_i_gamma_i = pst.k_i * pst.gamma_i;
    let lambda_i_x_i_gamma_i = my_lambda * key_share.secret_share * pst.gamma_i;

    Ok(PresignCoefficients {
        gamma_i: pst.gamma_i,
        u_coeff: k_i_gamma_i + alpha_beta_sum,
        w_coeff: lambda_i_x_i_gamma_i + mu_nu_sum,
    })
}

impl std::fmt::Debug for PresignMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PresignMessage").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for PresignState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PresignState").finish_non_exhaustive()
    }
}
