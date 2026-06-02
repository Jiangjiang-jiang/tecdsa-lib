// SPDX-License-Identifier: MIT OR Apache-2.0
use elliptic_curve::CurveArithmetic;
use k256::Secp256k1;
use tecdsa_commit::{HashCommitment, PedersenCommitment};

#[test]
fn hash_commitment_binding() {
    let mut rng = rand::thread_rng();
    let (com, opening) = HashCommitment::commit(b"message-a", &mut rng);
    assert!(com.verify(b"message-a", &opening));
    assert!(!com.verify(b"message-b", &opening));
}

#[test]
fn pedersen_hiding() {
    let mut rng = rand::thread_rng();
    // Use a deterministic scalar (From<u64>) to avoid the rand_core 0.6/0.10 split.
    let value = <Secp256k1 as CurveArithmetic>::Scalar::from(42u64);
    let com1 = PedersenCommitment::<Secp256k1>::commit_scalar(&value, &mut rng);
    let com2 = PedersenCommitment::<Secp256k1>::commit_scalar(&value, &mut rng);
    // Two commitments to the same value must differ (hiding property).
    assert_ne!(com1.point, com2.point);
}

#[test]
fn pedersen_verification() {
    let mut rng = rand::thread_rng();
    let value = <Secp256k1 as CurveArithmetic>::Scalar::from(99u64);
    let com = PedersenCommitment::<Secp256k1>::commit_scalar(&value, &mut rng);
    assert!(com.verify_scalar(&value));
}
