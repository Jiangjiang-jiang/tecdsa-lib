// SPDX-License-Identifier: MIT OR Apache-2.0
//! Runtime-configurable `(n, t)` benchmark sweeps.
//!
//! The multi-party benchmark suite (`benches/multiparty.rs`) and the one-shot
//! timing binary (`src/bin/protocol_once.rs`) read their party/threshold
//! configurations from environment variables, so the swept configurations can
//! be changed at run time **without recompiling**.
//!
//! | Env var | Format | Default | Meaning |
//! |---------|--------|---------|---------|
//! | `TECDSA_BENCH_DKG_CONFIGS` | `n:t,n:t,…` | `3:3,7:7,11:11,15:15,20:20` | DKG `(n, t)` pairs |
//! | `TECDSA_BENCH_SIGN_N` | integer | `20` | party count for presign/sign |
//! | `TECDSA_BENCH_SIGN_THRESHOLDS` | `t,t,…` | `2,3,7,11,15,20` | signing thresholds (quorum sizes) |
//!
//! Example:
//! ```bash
//! TECDSA_BENCH_DKG_CONFIGS=3:3,7:7 TECDSA_BENCH_SIGN_THRESHOLDS=2,20 \
//!     cargo bench -p tecdsa-bench --bench multiparty
//! ```
//!
//! A variable that is **unset** uses its default. A variable that is **set but
//! empty** (or only whitespace/commas) yields an empty list, which skips that
//! phase entirely — e.g. `TECDSA_BENCH_DKG_CONFIGS= ` runs only presign/sign,
//! and `TECDSA_BENCH_SIGN_THRESHOLDS= ` runs only DKG. (`TECDSA_BENCH_SIGN_N`
//! is a single integer and has no skip form.)
//!
//! Each accessor parses and validates its variable on every call, panicking with
//! a descriptive message on malformed input. Benchmark functions should call
//! them once and reuse the returned `Vec`.

use std::env;

const DKG_CONFIGS_VAR: &str = "TECDSA_BENCH_DKG_CONFIGS";
const SIGN_N_VAR: &str = "TECDSA_BENCH_SIGN_N";
const SIGN_THRESHOLDS_VAR: &str = "TECDSA_BENCH_SIGN_THRESHOLDS";
const RUNS_VAR: &str = "TECDSA_BENCH_RUNS";

const DEFAULT_DKG_CONFIGS: &[(u16, u16)] = &[(2, 2), (3, 3), (7, 7), (11, 11), (15, 15), (20, 20)];
const DEFAULT_SIGN_N: u16 = 20;
const DEFAULT_SIGN_THRESHOLDS: &[u16] = &[2, 3, 7, 11, 20];

/// Parse a single `u16` field (trimmed), panicking with context on failure.
fn parse_u16(var: &str, field: &str) -> u16 {
    field
        .trim()
        .parse::<u16>()
        .unwrap_or_else(|e| panic!("{var}: invalid integer {field:?}: {e}"))
}

/// Parse and validate a `TECDSA_BENCH_DKG_CONFIGS` value (`n:t,n:t,…`).
///
/// An empty (or whitespace/comma-only) value yields an empty vec, which the
/// benchmark loops treat as "skip the DKG sweep".
fn parse_dkg_configs(raw: &str) -> Vec<(u16, u16)> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|pair| {
            let (n, t) = pair
                .split_once(':')
                .unwrap_or_else(|| panic!("{DKG_CONFIGS_VAR}: expected `n:t` pair, got {pair:?}"));
            let n = parse_u16(DKG_CONFIGS_VAR, n);
            let t = parse_u16(DKG_CONFIGS_VAR, t);
            assert!(
                t >= 1 && t <= n,
                "{DKG_CONFIGS_VAR}: invalid pair {n}:{t} (need 1 <= t <= n)"
            );
            (n, t)
        })
        .collect()
}

/// Parse and validate a `TECDSA_BENCH_SIGN_THRESHOLDS` value (`t,t,…`) against `n`.
///
/// An empty (or whitespace/comma-only) value yields an empty vec, which the
/// benchmark loops treat as "skip the presign/sign sweep".
fn parse_sign_thresholds(raw: &str, n: u16) -> Vec<u16> {
    let thresholds: Vec<u16> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|t| parse_u16(SIGN_THRESHOLDS_VAR, t))
        .collect();
    validate_thresholds(&thresholds, n);
    thresholds
}

/// Validate that every threshold satisfies `1 <= t <= n`. An empty list is
/// allowed (it means "skip the presign/sign sweep").
fn validate_thresholds(thresholds: &[u16], n: u16) {
    for &t in thresholds {
        assert!(
            t >= 1 && t <= n,
            "{SIGN_THRESHOLDS_VAR}: threshold {t} out of range for n={n} \
             (need 1 <= t <= n; set {SIGN_THRESHOLDS_VAR} when overriding {SIGN_N_VAR})"
        );
    }
}

/// DKG `(n, t)` sweep from `TECDSA_BENCH_DKG_CONFIGS`
/// (default `3:3,7:7,11:11,15:15,20:20`).
///
/// Each comma-separated entry is `n:t`. Validates `1 <= t <= n`. If the variable
/// is **unset** the default is used; if it is **set but empty** (or only
/// whitespace/commas) the result is empty and the DKG sweep is skipped.
///
/// # Panics
/// If the variable contains a malformed entry (non-integer, missing `:`, or
/// `t` out of range).
#[must_use]
pub fn dkg_configs() -> Vec<(u16, u16)> {
    match env::var(DKG_CONFIGS_VAR) {
        Ok(s) => parse_dkg_configs(&s),
        Err(_) => DEFAULT_DKG_CONFIGS.to_vec(),
    }
}

/// Party count for the presign/sign sweep from `TECDSA_BENCH_SIGN_N`
/// (default `20`).
///
/// # Panics
/// If the variable is set but not a positive integer.
#[must_use]
pub fn sign_n() -> u16 {
    match env::var(SIGN_N_VAR) {
        Ok(s) => {
            let n = parse_u16(SIGN_N_VAR, &s);
            assert!(n >= 1, "{SIGN_N_VAR}: must be >= 1");
            n
        }
        Err(_) => DEFAULT_SIGN_N,
    }
}

/// Signing thresholds (quorum sizes) for the presign/sign sweep from
/// `TECDSA_BENCH_SIGN_THRESHOLDS` (default `2,3,7,11,15,20`).
///
/// Validates `1 <= t <= sign_n()` for every threshold, including the defaults;
/// when lowering `TECDSA_BENCH_SIGN_N` below a default threshold you must also
/// set `TECDSA_BENCH_SIGN_THRESHOLDS`. If the variable is **unset** the default
/// is used; if it is **set but empty** (or only whitespace/commas) the result is
/// empty and the presign/sign sweep is skipped.
///
/// # Panics
/// If the variable contains a malformed (non-integer) entry, or any threshold is
/// out of range.
#[must_use]
pub fn sign_thresholds() -> Vec<u16> {
    let n = sign_n();
    match env::var(SIGN_THRESHOLDS_VAR) {
        Ok(raw) => parse_sign_thresholds(&raw, n),
        Err(_) => {
            let thresholds = DEFAULT_SIGN_THRESHOLDS.to_vec();
            validate_thresholds(&thresholds, n);
            thresholds
        }
    }
}

/// The default signing quorum for threshold `t`: parties `1..=t`.
#[must_use]
pub fn first_signers(t: u16) -> Vec<u16> {
    (1..=t).collect()
}

/// Explicit override for the number of real protocol executions per
/// (phase, config), from `TECDSA_BENCH_RUNS`.
///
/// Returns `Some(n)` when the variable is set (forcing exactly `n` executions,
/// clamped to at least 1), and `None` when unset — in which case the harness
/// chooses the execution count adaptively (see
/// [`per_party::precompute_runs`](crate::per_party::precompute_runs)).
///
/// This is the main lever for fast smoke runs: `TECDSA_BENCH_RUNS=1` executes
/// each protocol/phase exactly once.
///
/// # Panics
/// If the variable is set but not a non-negative integer.
#[must_use]
pub fn bench_runs_override() -> Option<usize> {
    match env::var(RUNS_VAR) {
        Ok(s) => {
            let n = s
                .trim()
                .parse::<usize>()
                .unwrap_or_else(|e| panic!("{RUNS_VAR}: invalid integer {s:?}: {e}"));
            Some(n.max(1))
        }
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dkg_pairs_with_whitespace() {
        assert_eq!(
            parse_dkg_configs("3:3, 7:7 ,20:20"),
            vec![(3, 3), (7, 7), (20, 20)]
        );
        assert_eq!(parse_dkg_configs("5:2"), vec![(5, 2)]);
    }

    #[test]
    #[should_panic(expected = "1 <= t <= n")]
    fn rejects_threshold_greater_than_n() {
        let _ = parse_dkg_configs("3:5");
    }

    #[test]
    #[should_panic(expected = "expected `n:t` pair")]
    fn rejects_missing_colon() {
        let _ = parse_dkg_configs("33");
    }

    #[test]
    #[should_panic(expected = "invalid integer")]
    fn rejects_non_integer_pair() {
        let _ = parse_dkg_configs("a:b");
    }

    #[test]
    fn empty_dkg_configs_means_skip() {
        assert!(parse_dkg_configs("").is_empty());
        assert!(parse_dkg_configs("  , ").is_empty());
    }

    #[test]
    fn empty_sign_thresholds_means_skip() {
        assert!(parse_sign_thresholds("", 20).is_empty());
        assert!(parse_sign_thresholds(" , ", 20).is_empty());
    }

    #[test]
    fn parses_thresholds_with_whitespace() {
        assert_eq!(parse_sign_thresholds("2,3, 20", 20), vec![2, 3, 20]);
    }

    #[test]
    #[should_panic(expected = "out of range")]
    fn rejects_threshold_above_n() {
        let _ = parse_sign_thresholds("21", 20);
    }

    #[test]
    fn defaults_are_internally_consistent() {
        for &(n, t) in DEFAULT_DKG_CONFIGS {
            assert!(t >= 1 && t <= n, "default dkg pair {n}:{t} invalid");
        }
        // Default thresholds must fit the default party count.
        validate_thresholds(DEFAULT_SIGN_THRESHOLDS, DEFAULT_SIGN_N);
    }

    #[test]
    fn first_signers_is_one_to_t() {
        assert_eq!(first_signers(1), vec![1]);
        assert_eq!(first_signers(4), vec![1, 2, 3, 4]);
    }
}
