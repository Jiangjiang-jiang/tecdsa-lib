use std::env;

const DKG_CONFIGS_VAR: &str = "TECDSA_BENCH_DKG_CONFIGS";
const SIGN_N_VAR: &str = "TECDSA_BENCH_SIGN_N";
const SIGN_THRESHOLDS_VAR: &str = "TECDSA_BENCH_SIGN_THRESHOLDS";
const RUNS_VAR: &str = "TECDSA_BENCH_RUNS";

const DEFAULT_DKG_CONFIGS: &[(u16, u16)] = &[(2, 2), (3, 3), (7, 7), (11, 11), (15, 15), (20, 20)];
const DEFAULT_SIGN_N: u16 = 20;
const DEFAULT_SIGN_THRESHOLDS: &[u16] = &[2, 3, 7, 11, 20];

fn parse_u16(var: &str, field: &str) -> u16 {
    field
        .trim()
        .parse::<u16>()
        .unwrap_or_else(|e| panic!("{var}: invalid integer {field:?}: {e}"))
}

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

fn validate_thresholds(thresholds: &[u16], n: u16) {
    for &t in thresholds {
        assert!(
            t >= 1 && t <= n,
            "{SIGN_THRESHOLDS_VAR}: threshold {t} out of range for n={n} \
             (need 1 <= t <= n; set {SIGN_THRESHOLDS_VAR} when overriding {SIGN_N_VAR})"
        );
    }
}

#[must_use]
pub fn dkg_configs() -> Vec<(u16, u16)> {
    match env::var(DKG_CONFIGS_VAR) {
        Ok(s) => parse_dkg_configs(&s),
        Err(_) => DEFAULT_DKG_CONFIGS.to_vec(),
    }
}

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

#[must_use]
pub fn first_signers(t: u16) -> Vec<u16> {
    (1..=t).collect()
}

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
        validate_thresholds(DEFAULT_SIGN_THRESHOLDS, DEFAULT_SIGN_N);
    }

    #[test]
    fn first_signers_is_one_to_t() {
        assert_eq!(first_signers(1), vec![1]);
        assert_eq!(first_signers(4), vec![1, 2, 3, 4]);
    }
}
