use elliptic_curve::CurveArithmetic;
use k256::Secp256k1;
use tecdsa_vss::{feldman, lagrange, shamir};

fn scalar_from_u64(v: u64) -> <Secp256k1 as CurveArithmetic>::Scalar {
    <Secp256k1 as CurveArithmetic>::Scalar::from(v)
}

#[test]
fn shamir_2_of_3_reconstruct() {
    let mut rng = rand::thread_rng();
    let secret = scalar_from_u64(12_345);
    let shares = shamir::split::<Secp256k1>(&secret, 2, 3, &mut rng);
    let reconstructed = shamir::reconstruct::<Secp256k1>(&shares[..2]);
    assert_eq!(secret, reconstructed);
}

#[test]
fn shamir_3_of_5_reconstruct() {
    let mut rng = rand::thread_rng();
    let secret = scalar_from_u64(99_999);
    let shares = shamir::split::<Secp256k1>(&secret, 3, 5, &mut rng);
    let reconstructed = shamir::reconstruct::<Secp256k1>(&shares[..3]);
    assert_eq!(secret, reconstructed);
}

#[test]
fn shamir_insufficient_shares_wrong_result() {
    let mut rng = rand::thread_rng();
    let secret = scalar_from_u64(42);
    let shares = shamir::split::<Secp256k1>(&secret, 3, 5, &mut rng);
    let bad = shamir::reconstruct::<Secp256k1>(&shares[..2]);
    assert_ne!(secret, bad);
}

#[test]
fn lagrange_coefficients_sum_to_one() {
    let indices: Vec<u16> = vec![1, 2, 3];
    let coeffs = lagrange::coefficients::<Secp256k1>(&indices);
    let sum: <Secp256k1 as CurveArithmetic>::Scalar = coeffs.iter().copied().sum();
    assert_eq!(sum, <Secp256k1 as CurveArithmetic>::Scalar::ONE);
}

#[test]
fn feldman_vss_verification() {
    let mut rng = rand::thread_rng();
    let secret = scalar_from_u64(7_777);
    let (shares, commitments) = feldman::split::<Secp256k1>(&secret, 2, 3, &mut rng);
    for share in &shares {
        assert!(feldman::verify::<Secp256k1>(
            &share.value,
            share.index,
            &commitments,
        ));
    }
}
