// SPDX-License-Identifier: MIT OR Apache-2.0
//! Thin parallel-iteration facade.
//!
//! Every helper has two bodies selected by the `parallel` cargo feature: a
//! rayon one and a plain sequential one. The signatures (including the
//! `Send`/`Sync` bounds) are identical in both builds, so call sites never need
//! `#[cfg]` and a sequential build still type-checks against the same bounds.
//!
//! This is what makes the workspace's data parallelism a one-line change at
//! each call site: the independent repetitions of a sigma protocol, the
//! per-peer proof loops in a protocol round, and so on.

/// Map `f` over `items`, preserving order.
pub fn map<T, U, F>(items: &[T], f: F) -> Vec<U>
where
    T: Sync,
    U: Send,
    F: Fn(&T) -> U + Sync + Send,
{
    #[cfg(feature = "parallel")]
    {
        use rayon::prelude::*;
        items.par_iter().map(f).collect()
    }
    #[cfg(not(feature = "parallel"))]
    {
        items.iter().map(f).collect()
    }
}

/// Map `f` over `0..n`, preserving order.
pub fn map_indexed<U, F>(n: usize, f: F) -> Vec<U>
where
    U: Send,
    F: Fn(usize) -> U + Sync + Send,
{
    #[cfg(feature = "parallel")]
    {
        use rayon::prelude::*;
        (0..n).into_par_iter().map(f).collect()
    }
    #[cfg(not(feature = "parallel"))]
    {
        (0..n).map(f).collect()
    }
}

/// Map a fallible `f` over `items`, short-circuiting on the first error.
pub fn try_map<T, U, E, F>(items: &[T], f: F) -> Result<Vec<U>, E>
where
    T: Sync,
    U: Send,
    E: Send,
    F: Fn(&T) -> Result<U, E> + Sync + Send,
{
    #[cfg(feature = "parallel")]
    {
        use rayon::prelude::*;
        items.par_iter().map(f).collect()
    }
    #[cfg(not(feature = "parallel"))]
    {
        items.iter().map(f).collect()
    }
}

/// Run a fallible `f` over `items` for its effect, short-circuiting on error.
///
/// In a parallel build the returned error is the one from an unspecified
/// failing element, not necessarily the first in order.
pub fn try_for_each<T, E, F>(items: &[T], f: F) -> Result<(), E>
where
    T: Sync,
    E: Send,
    F: Fn(&T) -> Result<(), E> + Sync + Send,
{
    #[cfg(feature = "parallel")]
    {
        use rayon::prelude::*;
        items.par_iter().try_for_each(f)
    }
    #[cfg(not(feature = "parallel"))]
    {
        items.iter().try_for_each(f)
    }
}

/// `true` when `f` holds for every element.
pub fn all<T, F>(items: &[T], f: F) -> bool
where
    T: Sync,
    F: Fn(&T) -> bool + Sync + Send,
{
    #[cfg(feature = "parallel")]
    {
        use rayon::prelude::*;
        items.par_iter().all(f)
    }
    #[cfg(not(feature = "parallel"))]
    {
        items.iter().all(f)
    }
}

/// Run two independent closures, potentially on two threads.
pub fn join<A, B, RA, RB>(a: A, b: B) -> (RA, RB)
where
    A: FnOnce() -> RA + Send,
    B: FnOnce() -> RB + Send,
    RA: Send,
    RB: Send,
{
    #[cfg(feature = "parallel")]
    {
        rayon::join(a, b)
    }
    #[cfg(not(feature = "parallel"))]
    {
        (a(), b())
    }
}

/// Generate two independent safe primes of `bits` bits, concurrently.
///
/// `rng` is split into two seeded streams up front, so the pair is still a
/// deterministic function of the caller's RNG and does not depend on the
/// thread schedule.
pub fn gen_two_primes(
    rng: &mut impl rand_core::RngCore,
    bits: u32,
) -> (rug::Integer, rug::Integer) {
    use rand::SeedableRng;

    use crate::BigIntExt;

    let mut seed_p = [0u8; 32];
    let mut seed_q = [0u8; 32];
    rng.fill_bytes(&mut seed_p);
    rng.fill_bytes(&mut seed_q);
    join(
        || rug::Integer::generate_blum_prime(&mut rand::rngs::StdRng::from_seed(seed_p), bits),
        || rug::Integer::generate_blum_prime(&mut rand::rngs::StdRng::from_seed(seed_q), bits),
    )
}

/// Number of worker threads the facade will use (1 in a sequential build).
#[must_use]
pub fn num_threads() -> usize {
    #[cfg(feature = "parallel")]
    {
        rayon::current_num_threads()
    }
    #[cfg(not(feature = "parallel"))]
    {
        1
    }
}
