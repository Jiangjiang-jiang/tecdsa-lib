// SPDX-License-Identifier: MIT OR Apache-2.0
//! Micro-attribution of CGGMP20 cost at SecurityLevel128.

use std::time::Instant;

use rug::Integer;
use tecdsa_bigint::BigIntExt;
use tecdsa_paillier::{
    zk::{pi_fac, pi_mod},
    DecryptionKey,
};
use tecdsa_pedersen_mod::{PedersenModParams, PiPrm};

const BITS: u32 = 1536;

#[derive(udigest::Digestable)]
struct Tag {
    context: &'static str,
}

macro_rules! time {
    ($label:expr, $body:expr) => {{
        let t0 = Instant::now();
        let out = $body;
        println!(
            "{:<34} {:>9.1} ms",
            $label,
            t0.elapsed().as_secs_f64() * 1e3
        );
        out
    }};
}

fn main() {
    let mut rng = tecdsa_core::Csprng::new();

    println!(
        "mode: {}",
        if cfg!(feature = "parallel") {
            format!("parallel, {} threads", tecdsa_bigint::par::num_threads())
        } else {
            "sequential".to_string()
        }
    );

    let reps: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(16);

    // Safe-prime generation is a random search: report the full distribution.
    let mut samples: Vec<f64> = Vec::new();
    for _ in 0..reps {
        let t0 = Instant::now();
        let _ = Integer::generate_safe_prime(&mut rng, BITS);
        samples.push(t0.elapsed().as_secs_f64() * 1e3);
    }
    samples.sort_by(f64::total_cmp);
    let mean = samples.iter().sum::<f64>() / samples.len() as f64;
    println!(
        "safe_prime(1536) n={reps}  mean {mean:.0} ms  min {:.0}  p50 {:.0}  max {:.0}",
        samples[0],
        samples[samples.len() / 2],
        samples[samples.len() - 1]
    );

    let p = Integer::generate_safe_prime(&mut rng, BITS);
    let q = Integer::generate_safe_prime(&mut rng, BITS);
    let dk = DecryptionKey::from_primes(p, q).expect("valid");

    let (params, secret) = PedersenModParams::generate(u64::from(BITS), &mut rng);

    let pi_prm = time!("PiPrm::prove", PiPrm::prove(&params, &secret, &mut rng));
    let ok = time!("PiPrm::verify", pi_prm.verify(&params));
    assert!(ok);

    let tag = Tag { context: "x" };
    let pi_mod_proof = time!(
        "pi_mod::prove (80 reps)",
        pi_mod::non_interactive::prove::<80, sha2::Sha256>(
            &tag,
            pi_mod::Data { n: dk.n() },
            pi_mod::PrivateData {
                p: dk.p(),
                q: dk.q()
            },
            &mut rng,
        )
        .expect("prove")
    );
    time!(
        "pi_mod::verify (80 reps)",
        pi_mod::non_interactive::verify::<80, sha2::Sha256>(
            &tag,
            pi_mod::Data { n: dk.n() },
            &pi_mod_proof,
            &mut rng,
        )
        .expect("verify")
    );

    let aux = tecdsa_paillier::zk::bridge::pedersen_to_aux(&params);
    let sp = pi_fac::SecurityParams {
        l: 256,
        epsilon: 512,
    };
    let n_own = dk.n().clone();
    let n_root = n_own.clone().sqrt();
    let pi_fac_proof = time!(
        "pi_fac::prove",
        pi_fac::non_interactive::prove::<sha2::Sha256>(
            &tag,
            &aux,
            pi_fac::Data {
                n: &n_own,
                n_root: &n_root
            },
            pi_fac::PrivateData {
                p: dk.p(),
                q: dk.q()
            },
            &sp,
            &mut rng,
        )
        .expect("prove")
    );
    time!(
        "pi_fac::verify",
        pi_fac::non_interactive::verify::<sha2::Sha256>(
            &tag,
            &aux,
            pi_fac::Data {
                n: &n_own,
                n_root: &n_root
            },
            &sp,
            &pi_fac_proof,
        )
        .expect("verify")
    );
}
