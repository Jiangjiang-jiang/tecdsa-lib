// SPDX-License-Identifier: MIT OR Apache-2.0
use tecdsa_pedersen_mod::{PedersenModParams, PiPrm};

#[test]
fn pedersen_mod_params_generate_valid_ring() {
    let mut rng = rand::thread_rng();
    let (params, _secret) = PedersenModParams::generate(256, &mut rng);

    assert!(
        params.is_well_formed(),
        "generated params must be well-formed"
    );
    assert!(
        params.modulus_bits() >= 500,
        "N = p*q with 256-bit primes should be >= 500 bits, got {}",
        params.modulus_bits()
    );
}

#[test]
fn pi_prm_honest_verifies() {
    let mut rng = rand::thread_rng();
    let (params, secret) = PedersenModParams::generate(256, &mut rng);

    let proof = PiPrm::prove(&params, &secret, &mut rng);
    assert!(proof.verify(&params), "honest Pi_prm proof must verify");
}
