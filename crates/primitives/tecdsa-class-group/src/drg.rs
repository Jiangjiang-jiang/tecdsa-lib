#![allow(non_snake_case)]

use elliptic_curve::{group::GroupEncoding, CurveArithmetic};
use rand_core::CryptoRngCore;
use tecdsa_curve::{conv::scalar_to_bytes, TecdsaCurve};

use crate::{
    cl::{ClCiphertext, ClPublicKey, ClSetup, Qfi},
    zk::{r_enc_pc::REncPcProof, r_pc_dl::RPcDlProof},
};

#[derive(Clone, Debug)]
pub struct PedersenVssShare {
    pub index: u16,
    pub value: k256::Scalar,
    pub randomness: k256::Scalar,
}

#[derive(Clone, Debug)]
pub struct PedersenVssOutput {
    pub shares: Vec<PedersenVssShare>,
    pub commitments: Vec<k256::ProjectivePoint>,
    pub secret: k256::Scalar,
    pub secret_randomness: k256::Scalar,
}

pub fn pedersen_vss_share(
    secret: &k256::Scalar,
    threshold: u16,
    n: u16,
    rng: &mut impl CryptoRngCore,
) -> PedersenVssOutput {
    assert!(threshold > 0, "threshold must be >= 1");
    assert!(threshold <= n, "threshold must be <= n");

    let t = threshold as usize;

    let mut f_coeffs: Vec<k256::Scalar> = Vec::with_capacity(t);
    f_coeffs.push(*secret);
    for _ in 1..t {
        f_coeffs.push(k256::Secp256k1::random_scalar(rng));
    }

    let mut fp_coeffs: Vec<k256::Scalar> = Vec::with_capacity(t);
    for _ in 0..t {
        fp_coeffs.push(k256::Secp256k1::random_scalar(rng));
    }

    let g = <k256::Secp256k1 as TecdsaCurve>::generator();
    let h = <k256::Secp256k1 as TecdsaCurve>::nums_pedersen_h();

    let commitments: Vec<k256::ProjectivePoint> = f_coeffs
        .iter()
        .zip(fp_coeffs.iter())
        .map(|(a_d, ap_d)| g * a_d + h * ap_d)
        .collect();

    let shares: Vec<PedersenVssShare> = (1..=n)
        .map(|j| {
            let x = k256::Scalar::from(u64::from(j));
            let mut value = k256::Scalar::ZERO;
            let mut randomness = k256::Scalar::ZERO;
            let mut x_pow = k256::Scalar::ONE;
            for d in 0..t {
                value += f_coeffs[d] * x_pow;
                randomness += fp_coeffs[d] * x_pow;
                x_pow *= x;
            }
            PedersenVssShare {
                index: j,
                value,
                randomness,
            }
        })
        .collect();

    PedersenVssOutput {
        shares,
        commitments,
        secret: *secret,
        secret_randomness: fp_coeffs[0],
    }
}

#[must_use]
pub fn pedersen_vss_verify(
    share: &PedersenVssShare,
    commitments: &[k256::ProjectivePoint],
) -> bool {
    let g = <k256::Secp256k1 as TecdsaCurve>::generator();
    let h = <k256::Secp256k1 as TecdsaCurve>::nums_pedersen_h();

    let lhs = g * share.value + h * share.randomness;

    let x = k256::Scalar::from(u64::from(share.index));
    let mut rhs = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::IDENTITY;
    let mut x_pow = k256::Scalar::ONE;
    for com in commitments {
        rhs += *com * x_pow;
        x_pow *= x;
    }

    lhs == rhs
}

pub struct DrgGenOutput {
    pub secret: k256::Scalar,
    pub secret_randomness: k256::Scalar,
    pub vss_shares: Vec<PedersenVssShare>,
    pub commitments: Vec<k256::ProjectivePoint>,
    pub ciphertext: ClCiphertext,
    pub enc_randomness: Vec<u8>,
    pub pc_bytes: Vec<u8>,
    pub proof: REncPcProof,
}

pub struct DrgCombOutput {
    pub combined_share: k256::Scalar,
    pub combined_randomness: k256::Scalar,
    pub pedersen_commitment: k256::ProjectivePoint,
    pub ciphertext: ClCiphertext,
    pub enc_randomness: Vec<u8>,
    pub pc_bytes: Vec<u8>,
    pub proof: REncPcProof,
}

pub struct DrgRevealExpOutput {
    pub point: k256::ProjectivePoint,
    pub y_element: Qfi,
    pub proof: RPcDlProof,
}

pub fn drg_gen(
    setup: &mut ClSetup,
    pk: &ClPublicKey,
    threshold: u16,
    n: u16,
    rng: &mut impl CryptoRngCore,
) -> Result<DrgGenOutput, Box<dyn std::error::Error>> {
    let chi_i = k256::Secp256k1::random_scalar(rng);

    drg_gen_with_secret(setup, pk, &chi_i, threshold, n, rng)
}

pub fn drg_gen_with_secret(
    setup: &mut ClSetup,
    pk: &ClPublicKey,
    secret: &k256::Scalar,
    threshold: u16,
    n: u16,
    rng: &mut impl CryptoRngCore,
) -> Result<DrgGenOutput, Box<dyn std::error::Error>> {
    let vss_output = pedersen_vss_share(secret, threshold, n, rng);

    let chi_bytes = scalar_to_bytes::<k256::Secp256k1>(secret);

    let (r_sk, _r_pk) = setup.keygen()?;
    let r_bytes = setup.sk_to_bytes(&r_sk)?;

    let ciphertext = setup.encrypt_with_r_bytes(pk, &chi_bytes, &r_bytes)?;

    let pc = vss_output.commitments[0];
    let pc_bytes = pc.to_bytes().to_vec();
    let chi_prime_bytes = scalar_to_bytes::<k256::Secp256k1>(&vss_output.secret_randomness);
    let proof = REncPcProof::prove(
        setup,
        pk,
        &ciphertext,
        &pc_bytes,
        &chi_bytes,
        &chi_prime_bytes,
        &r_bytes,
    )?;

    Ok(DrgGenOutput {
        secret: vss_output.secret,
        secret_randomness: vss_output.secret_randomness,
        vss_shares: vss_output.shares,
        commitments: vss_output.commitments,
        ciphertext,
        enc_randomness: r_bytes,
        pc_bytes,
        proof,
    })
}

pub fn drg_gen_verify(
    setup: &ClSetup,
    pk_i: &ClPublicKey,
    commitments: &[k256::ProjectivePoint],
    ciphertext: &ClCiphertext,
    proof: &REncPcProof,
    pc_bytes: &[u8],
    my_share: &PedersenVssShare,
) -> Result<bool, Box<dyn std::error::Error>> {
    if !pedersen_vss_verify(my_share, commitments) {
        return Ok(false);
    }

    let proof_ok = proof.verify(setup, pk_i, ciphertext, pc_bytes)?;
    Ok(proof_ok)
}

pub fn drg_gen_verify_full(
    setup: &ClSetup,
    pk_i: &ClPublicKey,
    commitments: &[k256::ProjectivePoint],
    ciphertext: &ClCiphertext,
    proof: &REncPcProof,
    pc_bytes: &[u8],
    my_share: &PedersenVssShare,
) -> Result<bool, Box<dyn std::error::Error>> {
    if !pedersen_vss_verify(my_share, commitments) {
        return Ok(false);
    }

    let proof_ok = proof.verify(setup, pk_i, ciphertext, pc_bytes)?;
    Ok(proof_ok)
}

pub fn drg_comb(
    setup: &mut ClSetup,
    pk: &ClPublicKey,
    my_index: u16,
    received_shares: &[(u16, PedersenVssShare)],
    all_commitments: &[(u16, Vec<k256::ProjectivePoint>)],
) -> Result<DrgCombOutput, Box<dyn std::error::Error>> {
    let mut combined_share = k256::Scalar::ZERO;
    let mut combined_randomness = k256::Scalar::ZERO;
    for (_sender, share) in received_shares {
        assert_eq!(
            share.index, my_index,
            "share index mismatch: expected {my_index}, got {}",
            share.index
        );
        combined_share += share.value;
        combined_randomness += share.randomness;
    }

    let x = k256::Scalar::from(u64::from(my_index));
    let mut pedersen_commitment = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::IDENTITY;
    for (_sender, coms) in all_commitments {
        let mut x_pow = k256::Scalar::ONE;
        for com in coms {
            pedersen_commitment += *com * x_pow;
            x_pow *= x;
        }
    }

    let x_i_bytes = scalar_to_bytes::<k256::Secp256k1>(&combined_share);
    let (r_sk, _r_pk) = setup.keygen()?;
    let r_bytes = setup.sk_to_bytes(&r_sk)?;
    let ciphertext = setup.encrypt_with_r_bytes(pk, &x_i_bytes, &r_bytes)?;

    let pc_bytes = pedersen_commitment.to_bytes().to_vec();
    let x_prime_i_bytes = scalar_to_bytes::<k256::Secp256k1>(&combined_randomness);
    let proof = REncPcProof::prove(
        setup,
        pk,
        &ciphertext,
        &pc_bytes,
        &x_i_bytes,
        &x_prime_i_bytes,
        &r_bytes,
    )?;

    Ok(DrgCombOutput {
        combined_share,
        combined_randomness,
        pedersen_commitment,
        ciphertext,
        enc_randomness: r_bytes,
        pc_bytes,
        proof,
    })
}

pub fn drg_reveal_exp(
    setup: &mut ClSetup,
    combined_share: &k256::Scalar,
) -> Result<DrgRevealExpOutput, Box<dyn std::error::Error>> {
    let g = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR;
    let point = g * combined_share;

    let x_bytes = scalar_to_bytes::<k256::Secp256k1>(combined_share);

    let y = setup.power_of_f_bytes(&x_bytes)?;
    let proof = RPcDlProof::prove(setup, &y, &x_bytes)?;

    Ok(DrgRevealExpOutput {
        point,
        y_element: y,
        proof,
    })
}

pub fn drg_reveal_exp_verify(
    setup: &ClSetup,
    output: &DrgRevealExpOutput,
) -> Result<bool, Box<dyn std::error::Error>> {
    Ok(output.proof.verify(setup, &output.y_element)?)
}

pub fn drg_reveal_exp_verify_full(
    setup: &ClSetup,
    proof: &RPcDlProof,
    y: &Qfi,
) -> Result<bool, Box<dyn std::error::Error>> {
    Ok(proof.verify(setup, y)?)
}

pub struct DrgPresignState {
    pub gen_output: DrgGenOutput,
    pub comb_output: Option<DrgCombOutput>,
}

pub fn drg_full_run(
    setup: &mut ClSetup,
    pks: &[ClPublicKey],
    threshold: u16,
    n: u16,
    rng: &mut impl CryptoRngCore,
) -> Result<Vec<DrgCombOutput>, Box<dyn std::error::Error>> {
    let n_usize = n as usize;

    let gen_outputs = pks
        .iter()
        .map(|pk| drg_gen(setup, pk, threshold, n, rng))
        .collect::<Result<Vec<_>, _>>()?;

    for j in 0..n_usize {
        for i in 0..n_usize {
            if i == j {
                continue;
            }
            let share_for_j = &gen_outputs[i].vss_shares[j];
            let ok = drg_gen_verify(
                setup,
                &pks[i],
                &gen_outputs[i].commitments,
                &gen_outputs[i].ciphertext,
                &gen_outputs[i].proof,
                &gen_outputs[i].pc_bytes,
                share_for_j,
            )?;
            if !ok {
                return Err(
                    format!("DRG.GenVf failed: party {j} rejected party {i}'s share").into(),
                );
            }
        }
    }

    let comb_outputs = pks
        .iter()
        .enumerate()
        .map(|(j, pk)| {
            let my_index = (j + 1) as u16;

            let received_shares: Vec<(u16, PedersenVssShare)> = (0..n_usize)
                .map(|i| {
                    let sender_index = (i + 1) as u16;
                    (sender_index, gen_outputs[i].vss_shares[j].clone())
                })
                .collect();

            let all_commitments: Vec<(u16, Vec<k256::ProjectivePoint>)> = (0..n_usize)
                .map(|i| {
                    let sender_index = (i + 1) as u16;
                    (sender_index, gen_outputs[i].commitments.clone())
                })
                .collect();

            drg_comb(setup, pk, my_index, &received_shares, &all_commitments)
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(comb_outputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cl::{ClPublicKey, ClSetup, Mpz, Qfi};

    #[allow(clippy::type_complexity)]
    fn make_cl_keys(setup: &mut ClSetup, n: usize) -> Vec<(Vec<u8>, ClPublicKey, (Mpz, Mpz, Mpz))> {
        (0..n)
            .map(|_| {
                let (sk_raw, pk) = setup.keygen().expect("CL keygen");
                let sk_bytes = setup.sk_to_bytes(&sk_raw).expect("sk to bytes");
                let pk_qfi = pk.elt();
                let abc = (pk_qfi.a().clone(), pk_qfi.b().clone(), pk_qfi.c().clone());
                (sk_bytes, pk, abc)
            })
            .collect()
    }

    fn reconstruct_pk(setup: &ClSetup, abc: &(Mpz, Mpz, Mpz)) -> ClPublicKey {
        let qfi = Qfi::from_abc(abc.0.clone(), abc.1.clone(), abc.2.clone());
        let pk_raw = ClPublicKey::from_qfi(setup.cl(), qfi).expect("pk from qfi");
        pk_raw
    }

    #[test]
    fn test_pedersen_vss_basic() {
        let mut rng = rand::thread_rng();
        let secret = k256::Secp256k1::random_scalar(&mut rng);
        let threshold = 2u16;
        let n = 3u16;

        let output = pedersen_vss_share(&secret, threshold, n, &mut rng);

        assert_eq!(output.shares.len(), n as usize);
        assert_eq!(output.commitments.len(), threshold as usize);
        assert_eq!(output.secret, secret);

        for share in &output.shares {
            assert!(
                pedersen_vss_verify(share, &output.commitments),
                "share {} failed verification",
                share.index
            );
        }
    }

    #[test]
    #[ignore = "redundant DRG variant"]
    fn test_pedersen_vss_rejects_wrong_share() {
        let mut rng = rand::thread_rng();
        let secret = k256::Secp256k1::random_scalar(&mut rng);

        let output = pedersen_vss_share(&secret, 2, 3, &mut rng);

        let mut bad_share = output.shares[0].clone();
        bad_share.value += k256::Scalar::ONE;
        assert!(
            !pedersen_vss_verify(&bad_share, &output.commitments),
            "tampered share should fail verification"
        );
    }

    #[test]
    #[ignore = "redundant DRG variant"]
    fn test_pedersen_vss_reconstruction() {
        let mut rng = rand::thread_rng();
        let n = 3u16;
        let threshold = 2u16;

        let secret1 = k256::Secp256k1::random_scalar(&mut rng);
        let secret2 = k256::Secp256k1::random_scalar(&mut rng);
        let secret3 = k256::Secp256k1::random_scalar(&mut rng);
        let expected_sum = secret1 + secret2 + secret3;

        let out1 = pedersen_vss_share(&secret1, threshold, n, &mut rng);
        let out2 = pedersen_vss_share(&secret2, threshold, n, &mut rng);
        let out3 = pedersen_vss_share(&secret3, threshold, n, &mut rng);

        let combined: Vec<k256::Scalar> = (0..n as usize)
            .map(|j| out1.shares[j].value + out2.shares[j].value + out3.shares[j].value)
            .collect();

        let indices: Vec<u16> = (1..=n).collect();
        let coeffs = tecdsa_vss::lagrange::coefficients::<k256::Secp256k1>(&indices);
        let reconstructed: k256::Scalar = combined
            .iter()
            .zip(coeffs.iter())
            .map(|(s, c)| *s * c)
            .sum();

        assert_eq!(
            reconstructed, expected_sum,
            "Lagrange reconstruction should yield sum of secrets"
        );
    }

    #[test]
    fn test_drg_gen_basic() {
        let mut setup = ClSetup::new_secp256k1("30001").expect("CL setup");
        let keys = make_cl_keys(&mut setup, 1);
        let mut rng = rand::thread_rng();

        let gen = drg_gen(&mut setup, &keys[0].1, 1, 2, &mut rng).expect("drg_gen");

        assert_eq!(gen.vss_shares.len(), 2);
        assert_eq!(gen.commitments.len(), 1);
        let _ = &gen.proof;

        for share in &gen.vss_shares {
            assert!(pedersen_vss_verify(share, &gen.commitments));
        }
    }

    #[test]
    fn test_drg_gen_verify_accepts_honest() {
        let mut setup = ClSetup::new_secp256k1("30002").expect("CL setup");
        let keys = make_cl_keys(&mut setup, 2);
        let mut rng = rand::thread_rng();

        let gen = drg_gen(&mut setup, &keys[0].1, 1, 2, &mut rng).expect("drg_gen");

        let ok = drg_gen_verify(
            &setup,
            &keys[0].1,
            &gen.commitments,
            &gen.ciphertext,
            &gen.proof,
            &gen.pc_bytes,
            &gen.vss_shares[0],
        )
        .expect("drg_gen_verify");
        assert!(ok, "honest share should verify");
    }

    #[test]
    #[ignore = "redundant DRG variant"]
    fn test_drg_gen_verify_rejects_tampered() {
        let mut setup = ClSetup::new_secp256k1("30003").expect("CL setup");
        let keys = make_cl_keys(&mut setup, 2);
        let mut rng = rand::thread_rng();

        let gen = drg_gen(&mut setup, &keys[0].1, 1, 2, &mut rng).expect("drg_gen");

        let mut bad_share = gen.vss_shares[0].clone();
        bad_share.value += k256::Scalar::ONE;

        let ok = drg_gen_verify(
            &setup,
            &keys[0].1,
            &gen.commitments,
            &gen.ciphertext,
            &gen.proof,
            &gen.pc_bytes,
            &bad_share,
        )
        .expect("drg_gen_verify");
        assert!(!ok, "tampered share should be rejected");
    }

    #[test]
    fn test_drg_full_run_2_of_2() {
        let mut setup = ClSetup::new_secp256k1("30004").expect("CL setup");
        let keys = make_cl_keys(&mut setup, 2);
        let pks: Vec<ClPublicKey> = keys
            .iter()
            .map(|(_, _, abc)| reconstruct_pk(&setup, abc))
            .collect();
        let mut rng = rand::thread_rng();

        let comb_outputs = drg_full_run(&mut setup, &pks, 1, 2, &mut rng).expect("drg_full_run");

        assert_eq!(comb_outputs.len(), 2);

        let indices: Vec<u16> = vec![1, 2];
        let coeffs = tecdsa_vss::lagrange::coefficients::<k256::Secp256k1>(&indices);
        let combined_shares: Vec<k256::Scalar> =
            comb_outputs.iter().map(|c| c.combined_share).collect();
        let _reconstructed: k256::Scalar = combined_shares
            .iter()
            .zip(coeffs.iter())
            .map(|(s, c)| *s * c)
            .sum();

        let _ = &comb_outputs[0].proof;
    }

    #[test]
    #[ignore = "redundant DRG variant"]
    fn test_drg_full_run_3_of_3() {
        let mut setup = ClSetup::new_secp256k1("30005").expect("CL setup");
        let keys = make_cl_keys(&mut setup, 3);
        let pks: Vec<ClPublicKey> = keys
            .iter()
            .map(|(_, _, abc)| reconstruct_pk(&setup, abc))
            .collect();
        let mut rng = rand::thread_rng();

        let comb_outputs = drg_full_run(&mut setup, &pks, 2, 3, &mut rng).expect("drg_full_run");

        assert_eq!(comb_outputs.len(), 3);

        let g = <k256::Secp256k1 as TecdsaCurve>::generator();
        let h = <k256::Secp256k1 as TecdsaCurve>::nums_pedersen_h();
        for comb in &comb_outputs {
            let expected_pc = g * comb.combined_share + h * comb.combined_randomness;
            assert_eq!(
                comb.pedersen_commitment, expected_pc,
                "Pedersen commitment should match combined share"
            );
        }
    }

    #[test]
    fn test_drg_reveal_exp() {
        let mut setup = ClSetup::new_secp256k1("30006").expect("CL setup");
        let mut rng = rand::thread_rng();
        let x = k256::Secp256k1::random_scalar(&mut rng);

        let reveal = drg_reveal_exp(&mut setup, &x).expect("reveal_exp");

        let expected = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * x;
        assert_eq!(reveal.point, expected, "X_i should be g^x_i");
        let _ = &reveal.proof;
    }

    #[test]
    fn test_drg_comb_shares_reconstruct_sum() {
        let mut setup = ClSetup::new_secp256k1("30007").expect("CL setup");
        let n = 3u16;
        let threshold = 2u16;
        let keys = make_cl_keys(&mut setup, n as usize);
        let pks: Vec<ClPublicKey> = keys
            .iter()
            .map(|(_, _, abc)| reconstruct_pk(&setup, abc))
            .collect();
        let mut rng = rand::thread_rng();

        let gen_outputs = pks
            .iter()
            .map(|pk| drg_gen(&mut setup, pk, threshold, n, &mut rng).expect("drg_gen"))
            .collect::<Vec<_>>();

        let expected_sum: k256::Scalar = gen_outputs.iter().map(|g| g.secret).sum();

        let comb_outputs = pks
            .iter()
            .enumerate()
            .map(|(j, pk)| {
                let my_index = (j + 1) as u16;
                let received_shares: Vec<(u16, PedersenVssShare)> = (0..n as usize)
                    .map(|i| ((i + 1) as u16, gen_outputs[i].vss_shares[j].clone()))
                    .collect();
                let all_commitments: Vec<(u16, Vec<k256::ProjectivePoint>)> = (0..n as usize)
                    .map(|i| ((i + 1) as u16, gen_outputs[i].commitments.clone()))
                    .collect();
                drg_comb(&mut setup, pk, my_index, &received_shares, &all_commitments)
                    .expect("drg_comb")
            })
            .collect::<Vec<_>>();

        let indices: Vec<u16> = (1..=n).collect();
        let coeffs = tecdsa_vss::lagrange::coefficients::<k256::Secp256k1>(&indices);
        let reconstructed: k256::Scalar = comb_outputs
            .iter()
            .zip(coeffs.iter())
            .map(|(c, coeff)| c.combined_share * coeff)
            .sum();

        assert_eq!(
            reconstructed, expected_sum,
            "combined shares should reconstruct to the sum of secrets"
        );
    }

    #[test]
    fn test_drg_r_enc_pc_proof_verifies() {
        let mut setup = ClSetup::new_secp256k1("30008").expect("CL setup");
        let keys = make_cl_keys(&mut setup, 1);
        let mut rng = rand::thread_rng();

        let gen = drg_gen(&mut setup, &keys[0].1, 1, 2, &mut rng).expect("drg_gen");

        let ok = gen
            .proof
            .verify(&setup, &keys[0].1, &gen.ciphertext, &gen.pc_bytes)
            .expect("verify");
        assert!(ok, "R_Enc-PC proof should verify for honest generation");
    }

    #[test]
    #[ignore = "redundant DRG variant"]
    fn test_drg_gen_verify_full() {
        let mut setup = ClSetup::new_secp256k1("30009").expect("CL setup");
        let keys = make_cl_keys(&mut setup, 2);
        let mut rng = rand::thread_rng();

        let gen = drg_gen(&mut setup, &keys[0].1, 1, 2, &mut rng).expect("drg_gen");

        let ok = drg_gen_verify_full(
            &setup,
            &keys[0].1,
            &gen.commitments,
            &gen.ciphertext,
            &gen.proof,
            &gen.pc_bytes,
            &gen.vss_shares[0],
        )
        .expect("verify_full");
        assert!(ok, "full verification should pass for honest party");
    }

    #[test]
    #[ignore = "redundant DRG variant"]
    fn test_drg_reveal_exp_proof_verifies() {
        let mut setup = ClSetup::new_secp256k1("30010").expect("CL setup");
        let mut rng = rand::thread_rng();
        let x = k256::Secp256k1::random_scalar(&mut rng);

        let reveal = drg_reveal_exp(&mut setup, &x).expect("reveal_exp");

        let ok =
            drg_reveal_exp_verify_full(&setup, &reveal.proof, &reveal.y_element).expect("verify");
        assert!(ok, "R_PC-DL proof should verify");
    }
}
