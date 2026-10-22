// SPDX-License-Identifier: MIT OR Apache-2.0
//! Safe-prime generation throughput.
//!
//!   cargo run --release -p tecdsa-bigint --example prime_bench -- [bits] [reps]
//!   cargo run --release -p tecdsa-bigint --features parallel --example prime_bench

use std::time::Instant;

use rug::Integer;
use tecdsa_bigint::BigIntExt;

fn main() {
    let mut args = std::env::args().skip(1);
    let bits: u32 = args.next().and_then(|s| s.parse().ok()).unwrap_or(1536);
    let reps: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(16);

    let mode = if cfg!(feature = "parallel") {
        format!("parallel ({} threads)", rayon_threads())
    } else {
        "sequential".to_string()
    };

    let mut rng = rand::thread_rng();
    let mut samples = Vec::with_capacity(reps);
    for _ in 0..reps {
        let t0 = Instant::now();
        let p = Integer::generate_safe_prime(&mut rng, bits);
        samples.push(t0.elapsed().as_secs_f64() * 1e3);
        assert_eq!(p.significant_bits(), bits);
    }
    samples.sort_by(f64::total_cmp);
    let mean = samples.iter().sum::<f64>() / samples.len() as f64;
    println!(
        "safe_prime({bits})  {mode}  n={reps}  mean {mean:.0} ms  min {:.0}  p50 {:.0}  max {:.0}",
        samples[0],
        samples[samples.len() / 2],
        samples[samples.len() - 1],
    );
}

#[cfg(feature = "parallel")]
fn rayon_threads() -> usize {
    rayon::current_num_threads()
}

#[cfg(not(feature = "parallel"))]
fn rayon_threads() -> usize {
    1
}
