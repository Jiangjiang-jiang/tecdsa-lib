#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    clippy::cast_possible_wrap,
    clippy::needless_range_loop
)]

use elliptic_curve::{group::GroupEncoding, CurveArithmetic};
use rand_core::CryptoRngCore;
use tecdsa_curve::{conv::scalar_to_bytes, TecdsaCurve};

use crate::{
    cl::{Ciphertext as ClHsmqkCiphertext, ClResult, ClSetup, PublicKey as ClHsmqkPublicKey},
    zk::{r_dec_dl::RDecDlProof, r_enc_pc::REncPcProof},
};

#[derive(Clone, Debug)]
pub struct DkgDlPedersenShare {
    pub index: u16,
    pub value: k256::Scalar,
    pub randomness: k256::Scalar,
}

struct PedersenVssResult {
    shares: Vec<DkgDlPedersenShare>,
    commitments: Vec<k256::ProjectivePoint>,
    secret: k256::Scalar,
    secret_randomness: k256::Scalar,
}

fn pedersen_vss_share_dl(
    secret: &k256::Scalar,
    threshold: u16,
    n: u16,
    rng: &mut impl CryptoRngCore,
) -> PedersenVssResult {
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

    let shares: Vec<DkgDlPedersenShare> = (1..=n)
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
            DkgDlPedersenShare {
                index: j,
                value,
                randomness,
            }
        })
        .collect();

    PedersenVssResult {
        shares,
        commitments,
        secret: *secret,
        secret_randomness: fp_coeffs[0],
    }
}

#[must_use]
pub fn pedersen_vss_verify_dl(
    share: &DkgDlPedersenShare,
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

pub struct DkgDlGenPerRecipient {
    pub pc: k256::ProjectivePoint,
    pub ct: ClHsmqkCiphertext,
    pub proof: REncPcProof,
}

pub struct DkgDlGenOutput {
    pub per_recipient: Vec<DkgDlGenPerRecipient>,
    pub commitments: Vec<k256::ProjectivePoint>,
    pub my_secret: k256::Scalar,
    pub my_secret_prime: k256::Scalar,
    pub my_shares: Vec<k256::Scalar>,
    pub my_shares_prime: Vec<k256::Scalar>,
}

pub fn dkg_dl_gen(
    setup: &mut ClSetup,
    all_pks: &[ClHsmqkPublicKey],
    n: usize,
    threshold: usize,
    my_index: usize,
    rng: &mut impl CryptoRngCore,
) -> ClResult<DkgDlGenOutput> {
    assert_eq!(all_pks.len(), n);
    assert!(my_index < n);
    assert!(threshold > 0 && threshold <= n);

    let chi_i = k256::Secp256k1::random_scalar(rng);
    let vss = pedersen_vss_share_dl(&chi_i, threshold as u16, n as u16, rng);

    let mut per_recipient = Vec::with_capacity(n);
    let mut share_values = Vec::with_capacity(n);
    let mut share_randomness = Vec::with_capacity(n);

    for j in 0..n {
        let share = &vss.shares[j];
        let chi_ij = share.value;
        let chi_prime_ij = share.randomness;
        let chi_ij_bytes = scalar_to_bytes::<k256::Secp256k1>(&chi_ij);

        let g = <k256::Secp256k1 as TecdsaCurve>::generator();
        let h = <k256::Secp256k1 as TecdsaCurve>::nums_pedersen_h();
        let pc = g * chi_ij + h * chi_prime_ij;

        let pk_j = &all_pks[j];
        let (r_sk, _) = setup.keygen()?;
        let r_bytes = setup.sk_to_bytes(&r_sk)?;
        let ct = setup.encrypt_with_r_bytes(pk_j, &chi_ij_bytes, &r_bytes)?;

        let pc_bytes = pc.to_bytes();
        let chi_prime_ij_bytes = scalar_to_bytes::<k256::Secp256k1>(&chi_prime_ij);
        let proof = REncPcProof::prove(
            setup,
            pk_j,
            &ct,
            pc_bytes.as_ref(),
            &chi_ij_bytes,
            &chi_prime_ij_bytes,
            &r_bytes,
        )?;

        per_recipient.push(DkgDlGenPerRecipient { pc, ct, proof });
        share_values.push(chi_ij);
        share_randomness.push(chi_prime_ij);
    }

    Ok(DkgDlGenOutput {
        per_recipient,
        commitments: vss.commitments,
        my_secret: vss.secret,
        my_secret_prime: vss.secret_randomness,
        my_shares: share_values,
        my_shares_prime: share_randomness,
    })
}

pub fn dkg_dl_gen_verify(
    setup: &ClSetup,
    per_recipient: &DkgDlGenPerRecipient,
    commitments: &[k256::ProjectivePoint],
    recipient_pk: &ClHsmqkPublicKey,
    my_share: &DkgDlPedersenShare,
) -> ClResult<bool> {
    if !pedersen_vss_verify_dl(my_share, commitments) {
        return Ok(false);
    }

    let pc_bytes = per_recipient.pc.to_bytes();
    let proof_ok =
        per_recipient
            .proof
            .verify(setup, recipient_pk, &per_recipient.ct, pc_bytes.as_ref())?;
    Ok(proof_ok)
}

pub struct DkgDlRevealOutput {
    pub combined_share: k256::Scalar,
    pub public_share: k256::ProjectivePoint,
    pub proof: RDecDlProof,
    pub combined_ct: ClHsmqkCiphertext,
}

pub fn dkg_dl_reveal(
    setup: &mut ClSetup,
    my_sk_bytes: &[u8],
    my_pk: &ClHsmqkPublicKey,
    received_cts: &[ClHsmqkCiphertext],
    n: usize,
) -> ClResult<DkgDlRevealOutput> {
    assert_eq!(received_cts.len(), n);

    let sk = setup.sk_from_bytes(my_sk_bytes)?;

    let mut combined_share = k256::Scalar::ZERO;

    let mut combined_c1 = setup.identity()?;
    let mut combined_c2 = setup.identity()?;

    for ct_j in received_cts {
        let m_bytes = setup.decrypt_bytes(&sk, ct_j)?;

        let chi_ji = bytes_to_scalar(&m_bytes);
        combined_share += chi_ji;

        let (c1, c2) = setup.ct_components(ct_j)?;
        combined_c1 = setup.compose(&combined_c1, &c1)?;
        combined_c2 = setup.compose(&combined_c2, &c2)?;
    }

    let public_share = k256::ProjectivePoint::GENERATOR * combined_share;

    let combined_ct = setup.ct_from_components(&combined_c1, &combined_c2)?;

    let pd = setup.exp_bytes(&combined_c1, my_sk_bytes)?;

    let proof = RDecDlProof::prove(setup, my_pk, &combined_ct, &pd, my_sk_bytes)?;

    Ok(DkgDlRevealOutput {
        combined_share,
        public_share,
        proof,
        combined_ct,
    })
}

pub fn dkg_dl_reveal_verify(
    setup: &ClSetup,
    reveal: &DkgDlRevealOutput,
    party_pk: &ClHsmqkPublicKey,
) -> ClResult<bool> {
    let x_i_bytes = scalar_to_bytes::<k256::Secp256k1>(&reveal.combined_share);
    let f_xi = setup.power_of_f_bytes(&x_i_bytes)?;
    let (_, c2) = setup.ct_components(&reveal.combined_ct)?;
    let mut f_xi_inv = f_xi;
    f_xi_inv.neg();
    let pd = setup.compose(&c2, &f_xi_inv)?;

    reveal
        .proof
        .verify(setup, party_pk, &reveal.combined_ct, &pd)
}

pub fn dkg_dl_aggregate(
    public_shares: &[k256::ProjectivePoint],
    party_indices_1based: &[u16],
) -> k256::ProjectivePoint {
    assert_eq!(public_shares.len(), party_indices_1based.len());
    assert!(!public_shares.is_empty());

    let coeffs = lagrange_coefficients_at_zero(party_indices_1based);

    let mut aggregate = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::IDENTITY;
    for (share, coeff) in public_shares.iter().zip(coeffs.iter()) {
        aggregate += *share * coeff;
    }

    aggregate
}

fn lagrange_coefficients_at_zero(indices: &[u16]) -> Vec<k256::Scalar> {
    indices
        .iter()
        .map(|&i| {
            let xi = k256::Scalar::from(u64::from(i));
            indices
                .iter()
                .filter(|&&j| j != i)
                .fold(k256::Scalar::ONE, |acc, &j| {
                    let xj = k256::Scalar::from(u64::from(j));
                    acc * xj
                        * (xj - xi)
                            .invert()
                            .expect("distinct indices guarantee non-zero denominator")
                })
        })
        .collect()
}

fn bytes_to_scalar(bytes: &[u8]) -> k256::Scalar {
    tecdsa_curve::conv::bytes_to_scalar::<k256::Secp256k1>(bytes)
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::*;
    use crate::cl::ClSetup;

    #[test]
    fn dkg_dl_3_parties_full_round() {
        let n = 3;
        let t = 2;

        let mut setup = ClSetup::new_secp256k1("60001").expect("setup");

        let mut sk_bytes_vec = Vec::new();
        let mut pks = Vec::new();
        for _ in 0..n {
            let (sk, pk) = setup.keygen().expect("keygen");
            let sk_bytes = setup.sk_to_bytes(&sk).expect("sk_bytes");
            sk_bytes_vec.push(sk_bytes);
            pks.push(pk);
        }

        let mut gen_outputs = Vec::new();
        for i in 0..n {
            let output = dkg_dl_gen(&mut setup, &pks, n, t, i, &mut OsRng).expect("gen");
            gen_outputs.push(output);
        }

        for dealer in 0..n {
            for recipient in 0..n {
                let share = DkgDlPedersenShare {
                    index: (recipient + 1) as u16,
                    value: gen_outputs[dealer].my_shares[recipient],
                    randomness: gen_outputs[dealer].my_shares_prime[recipient],
                };

                let ok = dkg_dl_gen_verify(
                    &setup,
                    &gen_outputs[dealer].per_recipient[recipient],
                    &gen_outputs[dealer].commitments,
                    &pks[recipient],
                    &share,
                )
                .expect("gen_verify");
                assert!(
                    ok,
                    "GenVf failed for dealer={dealer}, recipient={recipient}"
                );
            }
        }

        let mut reveal_outputs = Vec::new();
        for i in 0..n {
            let received_cts: Vec<ClHsmqkCiphertext> = (0..n)
                .map(|dealer| gen_outputs[dealer].per_recipient[i].ct.clone())
                .collect();

            let reveal = dkg_dl_reveal(&mut setup, &sk_bytes_vec[i], &pks[i], &received_cts, n)
                .expect("reveal");
            reveal_outputs.push(reveal);
        }

        for i in 0..n {
            let ok =
                dkg_dl_reveal_verify(&setup, &reveal_outputs[i], &pks[i]).expect("reveal_verify");
            assert!(ok, "RevealVf failed for party={i}");
        }

        let public_shares: Vec<k256::ProjectivePoint> =
            reveal_outputs.iter().map(|r| r.public_share).collect();
        let indices: Vec<u16> = (1..=n as u16).collect();

        let agg = dkg_dl_aggregate(&public_shares, &indices);

        let total_secret: k256::Scalar = gen_outputs.iter().map(|g| g.my_secret).sum();
        let expected = k256::ProjectivePoint::GENERATOR * total_secret;
        assert_eq!(agg, expected, "aggregate mismatch");
    }

    #[test]
    fn dkg_dl_share_consistency() {
        let n = 3;
        let t = 2;

        let mut setup = ClSetup::new_secp256k1("60002").expect("setup");

        let mut sk_bytes_vec = Vec::new();
        let mut pks = Vec::new();
        for _ in 0..n {
            let (sk, pk) = setup.keygen().expect("keygen");
            sk_bytes_vec.push(setup.sk_to_bytes(&sk).expect("sk_bytes"));
            pks.push(pk);
        }

        let mut gen_outputs = Vec::new();
        for i in 0..n {
            gen_outputs.push(dkg_dl_gen(&mut setup, &pks, n, t, i, &mut OsRng).expect("gen"));
        }

        for i in 0..n {
            let expected_share: k256::Scalar = gen_outputs.iter().map(|g| g.my_shares[i]).sum();

            let received_cts: Vec<ClHsmqkCiphertext> = (0..n)
                .map(|dealer| gen_outputs[dealer].per_recipient[i].ct.clone())
                .collect();

            let reveal = dkg_dl_reveal(&mut setup, &sk_bytes_vec[i], &pks[i], &received_cts, n)
                .expect("reveal");

            assert_eq!(
                reveal.combined_share, expected_share,
                "share mismatch for party {i}"
            );
        }
    }

    #[test]
    fn dkg_dl_2_of_2() {
        let n = 2;
        let t = 2;

        let mut setup = ClSetup::new_secp256k1("60003").expect("setup");

        let mut sk_bytes_vec = Vec::new();
        let mut pks = Vec::new();
        for _ in 0..n {
            let (sk, pk) = setup.keygen().expect("keygen");
            sk_bytes_vec.push(setup.sk_to_bytes(&sk).expect("sk_bytes"));
            pks.push(pk);
        }

        let mut gen_outputs = Vec::new();
        for i in 0..n {
            gen_outputs.push(dkg_dl_gen(&mut setup, &pks, n, t, i, &mut OsRng).expect("gen"));
        }

        for d in 0..n {
            for r in 0..n {
                let share = DkgDlPedersenShare {
                    index: (r + 1) as u16,
                    value: gen_outputs[d].my_shares[r],
                    randomness: gen_outputs[d].my_shares_prime[r],
                };
                assert!(
                    dkg_dl_gen_verify(
                        &setup,
                        &gen_outputs[d].per_recipient[r],
                        &gen_outputs[d].commitments,
                        &pks[r],
                        &share,
                    )
                    .expect("verify"),
                    "GenVf failed d={d} r={r}"
                );
            }
        }

        let mut reveals = Vec::new();
        for i in 0..n {
            let cts: Vec<ClHsmqkCiphertext> = (0..n)
                .map(|d| gen_outputs[d].per_recipient[i].ct.clone())
                .collect();
            reveals.push(
                dkg_dl_reveal(&mut setup, &sk_bytes_vec[i], &pks[i], &cts, n).expect("reveal"),
            );
        }

        for i in 0..n {
            assert!(
                dkg_dl_reveal_verify(&setup, &reveals[i], &pks[i]).expect("verify"),
                "RevealVf failed i={i}"
            );
        }

        let public_shares: Vec<k256::ProjectivePoint> =
            reveals.iter().map(|r| r.public_share).collect();
        let indices: Vec<u16> = (1..=n as u16).collect();
        let agg = dkg_dl_aggregate(&public_shares, &indices);

        let total_secret: k256::Scalar = gen_outputs.iter().map(|g| g.my_secret).sum();
        let expected = k256::ProjectivePoint::GENERATOR * total_secret;
        assert_eq!(agg, expected);
    }
}
