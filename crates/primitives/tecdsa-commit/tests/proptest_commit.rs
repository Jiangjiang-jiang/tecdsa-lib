use proptest::prelude::*;
use tecdsa_commit::HashCommitment;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    #[test]
    fn hash_commit_verify_roundtrip(message: Vec<u8>) {
        let mut rng = rand::thread_rng();
        let (commitment, nonce) = HashCommitment::commit(&message, &mut rng);
        prop_assert!(commitment.verify(&message, &nonce));
    }

    #[test]
    fn hash_commit_rejects_wrong_message(message: Vec<u8>, other: Vec<u8>) {
        prop_assume!(message != other);
        let mut rng = rand::thread_rng();
        let (commitment, nonce) = HashCommitment::commit(&message, &mut rng);
        prop_assert!(!commitment.verify(&other, &nonce));
    }

    #[test]
    fn hash_commit_rejects_wrong_nonce(message: Vec<u8>) {
        let mut rng = rand::thread_rng();
        let (commitment, nonce) = HashCommitment::commit(&message, &mut rng);
        let mut bad_nonce = nonce;
        bad_nonce[0] ^= 0xFF;
        prop_assert!(!commitment.verify(&message, &bad_nonce));
    }
}
