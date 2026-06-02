// SPDX-License-Identifier: MIT OR Apache-2.0
use proptest::prelude::*;
use tecdsa_vss::shamir;

// Use k256 as the concrete curve for property tests.
type C = k256::Secp256k1;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn shamir_split_reconstruct(threshold in 1u16..=10, extra in 0u16..=5) {
        let n = threshold + extra;
        let mut rng = rand::thread_rng();

        // Random secret via rejection sampling.
        let secret = loop {
            let mut bytes = k256::FieldBytes::default();
            rand::RngCore::fill_bytes(&mut rng, &mut bytes);
            if let Some(s) = Option::from(<k256::Scalar as elliptic_curve::PrimeField>::from_repr(bytes)) {
                break s;
            }
        };

        let shares = shamir::split::<C>(&secret, threshold, n, &mut rng);
        assert_eq!(shares.len(), n as usize);

        // Reconstruct from exactly threshold shares.
        let subset: Vec<_> = shares.into_iter().take(threshold as usize).collect();
        let recovered = shamir::reconstruct::<C>(&subset);
        prop_assert_eq!(recovered, secret);
    }
}
