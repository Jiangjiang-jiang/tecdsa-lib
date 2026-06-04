// SPDX-License-Identifier: MIT OR Apache-2.0
//! One-shot Joye-Libert MtA timing.
//!
//! Prints setup separately so paper comparisons can use only the MtA rows.

use std::time::{Duration, Instant};

use k256::elliptic_curve::PrimeField;
use k256::Secp256k1;
use rand_core::OsRng;
use tecdsa_curve::TecdsaCurve;
use tecdsa_joye_libert::mta::{JlMtA, JlMtaSetup};
use tecdsa_protocol::MtA;

type C = Secp256k1;

fn time_once<T>(name: &str, f: impl FnOnce() -> T) -> T {
    let start = Instant::now();
    let out = f();
    let elapsed = start.elapsed();
    println!("{name}\t{}\t{}", elapsed.as_nanos(), HumanDuration(elapsed));
    out
}

struct HumanDuration(Duration);

impl std::fmt::Display for HumanDuration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ns = self.0.as_nanos();
        if ns < 1_000 {
            write!(f, "{ns} ns")
        } else if ns < 1_000_000 {
            write!(f, "{:.3} us", ns as f64 / 1_000.0)
        } else if ns < 1_000_000_000 {
            write!(f, "{:.3} ms", ns as f64 / 1_000_000.0)
        } else {
            write!(f, "{:.3} s", ns as f64 / 1_000_000_000.0)
        }
    }
}

fn main() {
    println!("name\telapsed_ns\telapsed");

    let a = C::random_scalar(&mut OsRng);
    let b = C::random_scalar(&mut OsRng);
    let a_bytes = a.to_repr();
    let b_bytes = b.to_repr();
    let q_bytes = tecdsa_curve::conv::curve_order::<C>().to_bytes_be();

    let (pk, sk, pk0) = time_once("mta/setup/jl_keygen", || {
        let (pk, sk, _x) =
            tecdsa_joye_libert::kgen::generate_keypair_with_qnr(1680, 712, &mut OsRng);
        let (pk0, _, _) =
            tecdsa_joye_libert::kgen::generate_keypair_with_qnr(1680, 712, &mut OsRng);
        (pk, sk, pk0)
    });

    let setup = JlMtaSetup {
        pk,
        pk0,
        sk,
        s: 40,
        t: 40,
    };

    let (sender_msg, sender_state) = time_once("mta/jl/sender_encrypt", || {
        JlMtA::sender_encrypt(&setup, b_bytes.as_ref(), &q_bytes, &mut OsRng).expect("sender")
    });
    let (receiver_msg, _alpha) = time_once("mta/jl/receiver_compute", || {
        JlMtA::receiver_compute(&setup, a_bytes.as_ref(), &q_bytes, &sender_msg, &mut OsRng)
            .expect("receiver")
    });
    time_once("mta/jl/sender_decrypt", || {
        JlMtA::sender_decrypt(&setup, &sender_state, &q_bytes, &receiver_msg).expect("decrypt")
    });
}
