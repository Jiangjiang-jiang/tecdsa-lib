#![allow(non_snake_case)]

use elliptic_curve::{group::GroupEncoding, CurveArithmetic};
use rand_core::CryptoRngCore;
use subtle::ConstantTimeEq;
use tecdsa_class_group::{
    cl::{ClCiphertext, ClSetup},
    drg::{drg_comb, drg_gen, drg_gen_verify, DrgCombOutput, DrgGenOutput, PedersenVssShare},
    zk::r_enc_pc::REncPcProof,
};
use tecdsa_curve::{conv::scalar_to_bytes, TecdsaCurve};

use crate::{
    key_share::Wmy23KeyShare,
    keygen::rounds::RDlPcProof,
    mtawc::{self, MtAwcBobOutput},
    presign::Wmy23Presignature,
};

fn global_idx(signer_ids: &[u16], pos: usize) -> usize {
    debug_assert!(signer_ids[pos] >= 1, "signer ids are 1-based");
    (signer_ids[pos] - 1) as usize
}

fn combined_pc_at(
    all_commitments: &[Vec<k256::ProjectivePoint>],
    index_1based: u16,
) -> k256::ProjectivePoint {
    let x = k256::Scalar::from(u64::from(index_1based));
    let mut pc = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::IDENTITY;
    for coms in all_commitments {
        let mut x_pow = k256::Scalar::ONE;
        for com in coms {
            pc += *com * x_pow;
            x_pow *= x;
        }
    }
    pc
}

pub fn share_zero(n: usize, rng: &mut impl CryptoRngCore) -> Vec<k256::Scalar> {
    assert!(n >= 1, "share_zero requires n >= 1");
    let mut shares = Vec::with_capacity(n);
    let mut sum = k256::Scalar::ZERO;
    for _ in 0..(n - 1) {
        let s = k256::Secp256k1::random_scalar(rng);
        sum += s;
        shares.push(s);
    }
    shares.push(-sum);
    shares
}

pub struct Phase3Output {
    pub delta_shares: Vec<k256::Scalar>,
    pub big_d_i: k256::ProjectivePoint,
}

pub struct DrgPresignR1State {
    pub index: usize,
    pub n: usize,
    pub k_gen: DrgGenOutput,
    pub gamma_gen: DrgGenOutput,
}

#[derive(Clone)]
pub struct DrgPresignR1Bcast {
    pub k_commitments: Vec<k256::ProjectivePoint>,
    pub gamma_commitments: Vec<k256::ProjectivePoint>,
    pub k_ciphertext: ClCiphertext,
    pub k_proof: REncPcProof,
    pub gamma_ciphertext: ClCiphertext,
    pub gamma_proof: REncPcProof,
}

#[derive(Clone)]
pub struct DrgPresignR1P2P {
    pub k_share: PedersenVssShare,
    pub gamma_share: PedersenVssShare,
}

#[allow(clippy::type_complexity)]
pub fn drg_presign_round1(
    index: usize,
    n: usize,
    threshold: u16,
    signer_ids: &[u16],
    key_share: &Wmy23KeyShare,
    setup: &mut ClSetup,
    rng: &mut impl CryptoRngCore,
) -> Result<
    (
        DrgPresignR1State,
        DrgPresignR1Bcast,
        Vec<Option<DrgPresignR1P2P>>,
    ),
    Box<dyn std::error::Error>,
> {
    let my_pk = &key_share.cl_pks[global_idx(signer_ids, index)];

    let k_gen = drg_gen(setup, my_pk, threshold, n as u16, rng)?;

    let gamma_gen = drg_gen(setup, my_pk, threshold, n as u16, rng)?;

    let mut p2p: Vec<Option<DrgPresignR1P2P>> = Vec::with_capacity(n);
    for j in 0..n {
        if j == index {
            p2p.push(None);
        } else {
            p2p.push(Some(DrgPresignR1P2P {
                k_share: k_gen.vss_shares[j].clone(),
                gamma_share: gamma_gen.vss_shares[j].clone(),
            }));
        }
    }

    let bcast = DrgPresignR1Bcast {
        k_commitments: k_gen.commitments.clone(),
        gamma_commitments: gamma_gen.commitments.clone(),
        k_ciphertext: k_gen.ciphertext.clone(),
        k_proof: k_gen.proof.clone(),
        gamma_ciphertext: gamma_gen.ciphertext.clone(),
        gamma_proof: gamma_gen.proof.clone(),
    };

    let state = DrgPresignR1State {
        index,
        n,
        k_gen,
        gamma_gen,
    };

    Ok((state, bcast, p2p))
}

pub struct DrgPresignR2State {
    pub k_comb: DrgCombOutput,
    pub gamma_comb: DrgCombOutput,
    pub hat_k_i: k256::Scalar,
    pub hat_gamma_i: k256::Scalar,
    pub hat_x_i: k256::Scalar,
}

#[derive(Clone)]
pub struct DrgPresignR2Bcast {
    pub k_comb_ct: ClCiphertext,
    pub k_comb_proof: REncPcProof,
    pub k_comb_pc_bytes: Vec<u8>,
    pub gamma_comb_ct: ClCiphertext,
    pub gamma_comb_proof: REncPcProof,
    pub gamma_comb_pc_bytes: Vec<u8>,
    pub g_gamma_point: k256::ProjectivePoint,
    pub gamma_reveal_proof: RDlPcProof,
}

pub fn drg_presign_round2(
    r1_state: &DrgPresignR1State,
    r1_bcasts: &[DrgPresignR1Bcast],
    received_p2p: &[Option<DrgPresignR1P2P>],
    signer_ids: &[u16],
    key_share: &Wmy23KeyShare,
    setup: &mut ClSetup,
) -> Result<(DrgPresignR2State, DrgPresignR2Bcast), Box<dyn std::error::Error>> {
    let n = r1_state.n;
    let my_idx = r1_state.index;
    let my_index_1based = (my_idx + 1) as u16;

    for i in 0..n {
        if i == my_idx {
            continue;
        }
        let p2p = received_p2p[i]
            .as_ref()
            .ok_or_else(|| format!("missing P2P data from party {i}"))?;

        let pk_i = &key_share.cl_pks[global_idx(signer_ids, i)];
        let bcast_i = &r1_bcasts[i];

        let k_pc_bytes = bcast_i
            .k_commitments
            .first()
            .ok_or_else(|| format!("party {i}: empty k commitments"))?
            .to_bytes()
            .to_vec();
        let k_ok = drg_gen_verify(
            setup,
            pk_i,
            &bcast_i.k_commitments,
            &bcast_i.k_ciphertext,
            &bcast_i.k_proof,
            &k_pc_bytes,
            &p2p.k_share,
        )?;
        if !k_ok {
            return Err(format!("DRG.GenVf: k share from party {i} failed").into());
        }

        let gamma_pc_bytes = bcast_i
            .gamma_commitments
            .first()
            .ok_or_else(|| format!("party {i}: empty gamma commitments"))?
            .to_bytes()
            .to_vec();
        let gamma_ok = drg_gen_verify(
            setup,
            pk_i,
            &bcast_i.gamma_commitments,
            &bcast_i.gamma_ciphertext,
            &bcast_i.gamma_proof,
            &gamma_pc_bytes,
            &p2p.gamma_share,
        )?;
        if !gamma_ok {
            return Err(format!("DRG.GenVf: gamma share from party {i} failed").into());
        }
    }

    let my_pk = &key_share.cl_pks[global_idx(signer_ids, my_idx)];

    let mut k_received: Vec<(u16, PedersenVssShare)> = Vec::with_capacity(n);
    let mut k_commitments_all: Vec<(u16, Vec<k256::ProjectivePoint>)> = Vec::with_capacity(n);
    let mut gamma_received: Vec<(u16, PedersenVssShare)> = Vec::with_capacity(n);
    let mut gamma_commitments_all: Vec<(u16, Vec<k256::ProjectivePoint>)> = Vec::with_capacity(n);

    for i in 0..n {
        let sender_1based = (i + 1) as u16;
        if i == my_idx {
            k_received.push((sender_1based, r1_state.k_gen.vss_shares[my_idx].clone()));
            gamma_received.push((sender_1based, r1_state.gamma_gen.vss_shares[my_idx].clone()));
        } else {
            let p2p = received_p2p[i]
                .as_ref()
                .ok_or_else(|| format!("missing P2P from party {i}"))?;
            k_received.push((sender_1based, p2p.k_share.clone()));
            gamma_received.push((sender_1based, p2p.gamma_share.clone()));
        }
        k_commitments_all.push((sender_1based, r1_bcasts[i].k_commitments.clone()));
        gamma_commitments_all.push((sender_1based, r1_bcasts[i].gamma_commitments.clone()));
    }

    let k_comb = drg_comb(
        setup,
        my_pk,
        my_index_1based,
        &k_received,
        &k_commitments_all,
    )?;
    let gamma_comb = drg_comb(
        setup,
        my_pk,
        my_index_1based,
        &gamma_received,
        &gamma_commitments_all,
    )?;

    let local_indices: Vec<u16> = (1..=(n as u16)).collect();
    let local_lambdas = tecdsa_vss::lagrange::coefficients::<k256::Secp256k1>(&local_indices);
    let hat_k_i = local_lambdas[my_idx] * k_comb.combined_share;
    let hat_gamma_i = local_lambdas[my_idx] * gamma_comb.combined_share;

    let global_lambdas = tecdsa_vss::lagrange::coefficients::<k256::Secp256k1>(signer_ids);
    let hat_x_i = global_lambdas[my_idx] * key_share.secret_share;

    let g = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR;
    let g_gamma_point = g * gamma_comb.combined_share;
    let mut reveal_rng = rand::thread_rng();
    let gamma_reveal_proof = RDlPcProof::prove(
        &gamma_comb.combined_share,
        &gamma_comb.combined_randomness,
        &g_gamma_point,
        &gamma_comb.pedersen_commitment,
        &mut reveal_rng,
    );

    let r2_bcast = DrgPresignR2Bcast {
        k_comb_ct: k_comb.ciphertext.clone(),
        k_comb_proof: k_comb.proof.clone(),
        k_comb_pc_bytes: k_comb.pc_bytes.clone(),
        gamma_comb_ct: gamma_comb.ciphertext.clone(),
        gamma_comb_proof: gamma_comb.proof.clone(),
        gamma_comb_pc_bytes: gamma_comb.pc_bytes.clone(),
        g_gamma_point,
        gamma_reveal_proof,
    };

    let r2_state = DrgPresignR2State {
        k_comb,
        gamma_comb,
        hat_k_i,
        hat_gamma_i,
        hat_x_i,
    };

    Ok((r2_state, r2_bcast))
}

pub struct DrgPresignR3Data {
    pub gamma_bob_outputs: Vec<Option<MtAwcBobOutput>>,
    pub x_bob_outputs: Vec<Option<MtAwcBobOutput>>,
}

pub fn drg_presign_round3_bob(
    r2_state: &DrgPresignR2State,
    r1_state: &DrgPresignR1State,
    signer_ids: &[u16],
    key_share: &Wmy23KeyShare,
    r2_bcasts: &[DrgPresignR2Bcast],
    setup: &mut ClSetup,
    rng: &mut impl CryptoRngCore,
) -> Result<DrgPresignR3Data, Box<dyn std::error::Error>> {
    let n = r1_state.n;
    let my_idx = r1_state.index;
    let hat_gamma_i = &r2_state.hat_gamma_i;
    let hat_x_i = &r2_state.hat_x_i;

    let local_indices: Vec<u16> = (1..=(n as u16)).collect();
    let local_lambdas = tecdsa_vss::lagrange::coefficients::<k256::Secp256k1>(&local_indices);

    let mut gamma_bob_outputs: Vec<Option<MtAwcBobOutput>> = Vec::with_capacity(n);
    let mut x_bob_outputs: Vec<Option<MtAwcBobOutput>> = Vec::with_capacity(n);

    for j in 0..n {
        if j == my_idx {
            gamma_bob_outputs.push(None);
            x_bob_outputs.push(None);
            continue;
        }

        let pk_j = &key_share.cl_pks[global_idx(signer_ids, j)];

        let lambda_j_bytes = scalar_to_bytes::<k256::Secp256k1>(&local_lambdas[j]);
        let c_hat_k_j =
            setup.scal_ciphertext_bytes(pk_j, &r2_bcasts[j].k_comb_ct, &lambda_j_bytes)?;

        let gamma_bob = mtawc::mtawc_bob(setup, pk_j, &c_hat_k_j, hat_gamma_i, rng)?;

        let x_bob = mtawc::mtawc_bob(setup, pk_j, &c_hat_k_j, hat_x_i, rng)?;

        gamma_bob_outputs.push(Some(gamma_bob));
        x_bob_outputs.push(Some(x_bob));
    }

    Ok(DrgPresignR3Data {
        gamma_bob_outputs,
        x_bob_outputs,
    })
}

pub struct DrgPresignR4State {
    pub n: usize,
    pub index: usize,
    pub delta_i: k256::Scalar,
    pub sigma_i: k256::Scalar,
    pub gamma_sum: k256::ProjectivePoint,
    pub big_d_i: k256::ProjectivePoint,
    pub hat_k_i: k256::Scalar,
    pub hat_k_randomness: k256::Scalar,
    pub hat_x_i: k256::Scalar,
    pub mu_shares: Vec<Option<k256::Scalar>>,
    pub nu_points: Vec<Option<k256::ProjectivePoint>>,
    pub pc_hat_k: Vec<k256::ProjectivePoint>,
    pub xhat_points: Vec<k256::ProjectivePoint>,
    pub d_proof: RDlPcProof,
    pub gamma_beta: Vec<Vec<Option<k256::ProjectivePoint>>>,
}

#[allow(clippy::too_many_arguments)]
pub fn drg_presign_round4_compute(
    r1_state: &DrgPresignR1State,
    r1_bcasts: &[DrgPresignR1Bcast],
    r2_state: &DrgPresignR2State,
    r2_bcasts: &[DrgPresignR2Bcast],
    r3_datas: &[DrgPresignR3Data],
    signer_ids: &[u16],
    key_share: &Wmy23KeyShare,
    setup: &mut ClSetup,
    rng: &mut impl CryptoRngCore,
) -> Result<(DrgPresignR4State, Phase3Output), Box<dyn std::error::Error>> {
    let n = r1_state.n;
    let my_idx = r1_state.index;
    let hat_k_i = r2_state.hat_k_i;
    let hat_gamma_i = r2_state.hat_gamma_i;

    let local_indices: Vec<u16> = (1..=(n as u16)).collect();
    let local_lambdas = tecdsa_vss::lagrange::coefficients::<k256::Secp256k1>(&local_indices);
    let global_lambdas = tecdsa_vss::lagrange::coefficients::<k256::Secp256k1>(signer_ids);

    let k_coms_all: Vec<Vec<k256::ProjectivePoint>> =
        r1_bcasts.iter().map(|b| b.k_commitments.clone()).collect();
    let gamma_coms_all: Vec<Vec<k256::ProjectivePoint>> =
        r1_bcasts.iter().map(|b| b.gamma_commitments.clone()).collect();
    let mut k_comb_pcs: Vec<k256::ProjectivePoint> = Vec::with_capacity(n);
    for j in 0..n {
        let idx_1based = (j + 1) as u16;
        let pk_j = &key_share.cl_pks[global_idx(signer_ids, j)];
        let b = &r2_bcasts[j];

        let pc_kj = combined_pc_at(&k_coms_all, idx_1based);
        if pc_kj.to_bytes().as_slice() != b.k_comb_pc_bytes.as_slice() {
            return Err(format!("CombVf: PC_k mismatch for party {j}").into());
        }
        if !b
            .k_comb_proof
            .verify(setup, pk_j, &b.k_comb_ct, &b.k_comb_pc_bytes)?
        {
            return Err(format!("CombVf: R_Enc-PC (k) failed for party {j}").into());
        }
        k_comb_pcs.push(pc_kj);

        let pc_gj = combined_pc_at(&gamma_coms_all, idx_1based);
        if pc_gj.to_bytes().as_slice() != b.gamma_comb_pc_bytes.as_slice() {
            return Err(format!("CombVf: PC_gamma mismatch for party {j}").into());
        }
        if !b
            .gamma_comb_proof
            .verify(setup, pk_j, &b.gamma_comb_ct, &b.gamma_comb_pc_bytes)?
        {
            return Err(format!("CombVf: R_Enc-PC (gamma) failed for party {j}").into());
        }

        if !b
            .gamma_reveal_proof
            .verify(&b.g_gamma_point, &pc_gj)
            .map_err(|e| format!("ExpVf error for party {j}: {e}"))?
        {
            return Err(format!("ExpVf: R_DL-PC failed for party {j}").into());
        }
    }

    let mut alphas: Vec<k256::Scalar> = vec![k256::Scalar::ZERO; n];
    let mut betas: Vec<k256::Scalar> = vec![k256::Scalar::ZERO; n];
    let mut mu_sum = k256::Scalar::ZERO;
    let mut nu_sum = k256::Scalar::ZERO;
    let mut mu_shares: Vec<Option<k256::Scalar>> = vec![None; n];
    let mut nu_points: Vec<Option<k256::ProjectivePoint>> = vec![None; n];

    for j in 0..n {
        if j == my_idx {
            continue;
        }

        let g_hat_gamma_j = r2_bcasts[j].g_gamma_point * local_lambdas[j];
        let x_j = key_share.public_shares[global_idx(signer_ids, j)];
        let g_hat_x_j = x_j * global_lambdas[j];

        let gamma_bob_out = r3_datas[j].gamma_bob_outputs[my_idx]
            .as_ref()
            .ok_or("missing gamma bob output")?;
        let alpha_out = mtawc::mtawc_alice_decrypt_and_check(
            setup,
            &key_share.cl_sk,
            &gamma_bob_out.c_alpha,
            &gamma_bob_out.g_beta,
            &hat_k_i,
            &g_hat_gamma_j,
        )
        .map_err(|e| format!("gamma MtAwc check failed (sender {j}): {e}"))?;
        alphas[j] = alpha_out.alpha;

        let x_bob_out = r3_datas[j].x_bob_outputs[my_idx]
            .as_ref()
            .ok_or("missing x bob output")?;
        let mu_out = mtawc::mtawc_alice_decrypt_and_check(
            setup,
            &key_share.cl_sk,
            &x_bob_out.c_alpha,
            &x_bob_out.g_beta,
            &hat_k_i,
            &g_hat_x_j,
        )
        .map_err(|e| format!("key MtAwc check failed (sender {j}): {e}"))?;
        mu_sum += mu_out.alpha;
        mu_shares[j] = Some(mu_out.alpha);
        nu_points[j] = Some(x_bob_out.g_beta);

        let my_gamma_bob = r3_datas[my_idx].gamma_bob_outputs[j]
            .as_ref()
            .ok_or("missing my gamma bob output")?;
        betas[j] = my_gamma_bob.beta;

        let my_x_bob = r3_datas[my_idx].x_bob_outputs[j]
            .as_ref()
            .ok_or("missing my x bob output")?;
        nu_sum += my_x_bob.beta;
    }

    let theta = share_zero(n, rng);

    let mut delta_shares = Vec::with_capacity(n);
    for j in 0..n {
        if j == my_idx {
            delta_shares.push(hat_k_i * hat_gamma_i + theta[j]);
        } else {
            delta_shares.push(alphas[j] + betas[j] + theta[j]);
        }
    }

    let mut gamma_sum = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::IDENTITY;
    for j in 0..n {
        gamma_sum += r2_bcasts[j].g_gamma_point * local_lambdas[j];
    }

    let big_d_i = gamma_sum * hat_k_i;

    let alpha_sum: k256::Scalar = alphas.iter().copied().sum();
    let beta_sum: k256::Scalar = betas.iter().copied().sum();
    let delta_i = hat_k_i * hat_gamma_i + alpha_sum + beta_sum;

    {
        let g = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR;
        let mut lhs = g * delta_i;
        for j in 0..n {
            if j == my_idx {
                continue;
            }
            let b_ij = r3_datas[j].gamma_bob_outputs[my_idx]
                .as_ref()
                .ok_or("B_{ij}: missing gamma bob output")?
                .g_beta;
            let b_ji = r3_datas[my_idx].gamma_bob_outputs[j]
                .as_ref()
                .ok_or("B_{ji}: missing gamma bob output")?
                .g_beta;
            lhs += b_ij - b_ji;
        }
        if bool::from(!lhs.to_bytes().ct_eq(&big_d_i.to_bytes())) {
            return Err(format!(
                "Phase 3 B_{{ij}}/B_{{ji}} verification failed for party {my_idx}"
            )
            .into());
        }
    }

    let sigma_i = hat_k_i * r2_state.hat_x_i + mu_sum + nu_sum;

    let hat_k_randomness = local_lambdas[my_idx] * r2_state.k_comb.combined_randomness;

    let pc_hat_k: Vec<k256::ProjectivePoint> = (0..n)
        .map(|j| k_comb_pcs[j] * local_lambdas[j])
        .collect();
    let xhat_points: Vec<k256::ProjectivePoint> = (0..n)
        .map(|j| key_share.public_shares[global_idx(signer_ids, j)] * global_lambdas[j])
        .collect();

    let d_proof = RDlPcProof::prove_with_base(
        &gamma_sum,
        &hat_k_i,
        &hat_k_randomness,
        &big_d_i,
        &pc_hat_k[my_idx],
        rng,
    );

    let mut gamma_beta: Vec<Vec<Option<k256::ProjectivePoint>>> =
        vec![vec![None; n]; n];
    for bob in 0..n {
        for alice in 0..n {
            if bob == alice {
                continue;
            }
            if let Some(out) = r3_datas[bob].gamma_bob_outputs[alice].as_ref() {
                gamma_beta[bob][alice] = Some(out.g_beta);
            }
        }
    }

    let r4_state = DrgPresignR4State {
        n,
        index: my_idx,
        delta_i,
        sigma_i,
        gamma_sum,
        big_d_i,
        hat_k_i,
        hat_k_randomness,
        hat_x_i: r2_state.hat_x_i,
        mu_shares,
        nu_points,
        pc_hat_k,
        xhat_points,
        d_proof,
        gamma_beta,
    };

    let phase3 = Phase3Output {
        delta_shares,
        big_d_i,
    };

    Ok((r4_state, phase3))
}

#[must_use]
pub fn verify_phase3_party(
    r4_state: &DrgPresignR4State,
    j: usize,
    delta_j: &k256::Scalar,
    big_d_j: &k256::ProjectivePoint,
    d_proof_j: &RDlPcProof,
) -> bool {
    let n = r4_state.n;
    if j >= n {
        return false;
    }

    match d_proof_j.verify_with_base(&r4_state.gamma_sum, big_d_j, &r4_state.pc_hat_k[j]) {
        Ok(true) => {}
        _ => return false,
    }

    let g = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR;
    let mut lhs = g * delta_j;
    for l in 0..n {
        if l == j {
            continue;
        }
        let Some(b_jl) = r4_state.gamma_beta[l][j] else {
            return false;
        };
        let Some(b_lj) = r4_state.gamma_beta[j][l] else {
            return false;
        };
        lhs += b_jl - b_lj;
    }
    bool::from(lhs.to_bytes().ct_eq(&big_d_j.to_bytes()))
}

pub fn drg_presign_finalize(
    r4_state: &DrgPresignR4State,
    all_delta_i: &[k256::Scalar],
    all_big_d: &[k256::ProjectivePoint],
) -> Result<Wmy23Presignature, Box<dyn std::error::Error>> {
    let n = r4_state.n;
    if all_delta_i.len() != n || all_big_d.len() != n {
        return Err("finalize: wrong number of revealed shares".into());
    }

    let delta: k256::Scalar = all_delta_i.iter().copied().sum();

    let g = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR;
    let d_prod = all_big_d.iter().fold(
        <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::IDENTITY,
        |acc, d| acc + d,
    );
    if bool::from(!(g * delta).to_bytes().ct_eq(&d_prod.to_bytes())) {
        return Err("share revelation check failed: g^delta != prod D_j".into());
    }

    let delta_inv = delta
        .invert()
        .into_option()
        .ok_or("delta is zero, cannot invert")?;

    let big_r = r4_state.gamma_sum * delta_inv;

    let r_x = <k256::Secp256k1 as TecdsaCurve>::xcoord_mod_q(&big_r.to_affine());

    let big_r_shares: Vec<k256::ProjectivePoint> =
        all_big_d.iter().map(|d| *d * delta_inv).collect();

    Ok(Wmy23Presignature {
        k_i: r4_state.hat_k_i,
        big_r,
        r_x,
        sigma_i: r4_state.sigma_i,
        n_signers: n,
        index: r4_state.index,
        hat_k_randomness: r4_state.hat_k_randomness,
        hat_x_i: r4_state.hat_x_i,
        mu_shares: r4_state.mu_shares.clone(),
        nu_points: r4_state.nu_points.clone(),
        pc_hat_k: r4_state.pc_hat_k.clone(),
        big_r_shares,
        xhat_points: r4_state.xhat_points.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_share_zero_sums_to_zero() {
        let mut rng = rand::thread_rng();
        for n in [1, 2, 3, 5, 10] {
            let shares = share_zero(n, &mut rng);
            assert_eq!(shares.len(), n);
            let sum: k256::Scalar = shares.iter().copied().sum();
            assert_eq!(
                sum,
                k256::Scalar::ZERO,
                "share_zero({n}) should produce shares summing to zero"
            );
        }
    }

    #[test]
    fn test_share_zero_randomness() {
        let mut rng = rand::thread_rng();
        let shares1 = share_zero(5, &mut rng);
        let shares2 = share_zero(5, &mut rng);
        assert_ne!(
            shares1, shares2,
            "two independent zero-sharings should differ"
        );
    }

    #[test]
    fn test_share_zero_single_element() {
        let mut rng = rand::thread_rng();
        let shares = share_zero(1, &mut rng);
        assert_eq!(shares.len(), 1);
        assert_eq!(
            shares[0],
            k256::Scalar::ZERO,
            "single-element zero-sharing must be zero"
        );
    }
}
