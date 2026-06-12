#![forbid(unsafe_code)]

use elliptic_curve::CurveArithmetic;
use k256::{ProjectivePoint, Scalar};

#[derive(Debug, Clone, Copy)]
pub struct Ciphertext {
    pub c0: ProjectivePoint,
    pub c1: ProjectivePoint,
}

pub fn encrypt(pk: &ProjectivePoint, m: &ProjectivePoint, r: &Scalar) -> Ciphertext {
    let g = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR;
    Ciphertext {
        c0: g * r,
        c1: *m + *pk * r,
    }
}

pub fn partial_decrypt(ct: &Ciphertext, dk_i: &Scalar) -> ProjectivePoint {
    ct.c0 * dk_i
}

pub fn combine_partials(
    ct: &Ciphertext,
    partials: &[(Scalar, ProjectivePoint)],
) -> ProjectivePoint {
    let mut combined = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::IDENTITY;
    for (lambda_j, pd_j) in partials {
        combined += *pd_j * lambda_j;
    }
    ct.c1 - combined
}

pub fn add(a: &Ciphertext, b: &Ciphertext) -> Ciphertext {
    Ciphertext {
        c0: a.c0 + b.c0,
        c1: a.c1 + b.c1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_scalar(val: u64) -> Scalar {
        Scalar::from(val)
    }

    #[test]
    fn encrypt_decrypt_single_party() {
        let g = ProjectivePoint::GENERATOR;
        let dk = test_scalar(42);
        let pk = g * dk;
        let m = g * test_scalar(17);
        let r = test_scalar(23);

        let ct = encrypt(&pk, &m, &r);
        let pd = partial_decrypt(&ct, &dk);
        let decrypted = combine_partials(&ct, &[(Scalar::ONE, pd)]);
        assert_eq!(m, decrypted);
    }

    #[test]
    fn threshold_decrypt() {
        let g = ProjectivePoint::GENERATOR;
        let dk_1 = test_scalar(11);
        let dk_2 = test_scalar(22);
        let dk_3 = test_scalar(33);
        let pk = g * dk_1 + g * dk_2 + g * dk_3;

        let m = g * test_scalar(77);
        let ct = encrypt(&pk, &m, &test_scalar(55));

        let pd_1 = partial_decrypt(&ct, &dk_1);
        let pd_2 = partial_decrypt(&ct, &dk_2);
        let pd_3 = partial_decrypt(&ct, &dk_3);

        let decrypted = combine_partials(
            &ct,
            &[
                (Scalar::ONE, pd_1),
                (Scalar::ONE, pd_2),
                (Scalar::ONE, pd_3),
            ],
        );
        assert_eq!(m, decrypted);
    }

    #[test]
    fn homomorphic_add() {
        let g = ProjectivePoint::GENERATOR;
        let dk = test_scalar(42);
        let pk = g * dk;

        let m_1 = g * test_scalar(17);
        let m_2 = g * test_scalar(23);
        let ct_1 = encrypt(&pk, &m_1, &test_scalar(31));
        let ct_2 = encrypt(&pk, &m_2, &test_scalar(37));

        let ct_sum = add(&ct_1, &ct_2);
        let pd = partial_decrypt(&ct_sum, &dk);
        let decrypted = combine_partials(&ct_sum, &[(Scalar::ONE, pd)]);
        assert_eq!(m_1 + m_2, decrypted);
    }
}
