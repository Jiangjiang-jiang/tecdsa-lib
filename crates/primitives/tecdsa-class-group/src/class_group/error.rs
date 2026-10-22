//! Error type for the crate.

use core::fmt;

use rug::Integer;

/// Crate-wide result alias.
pub type Result<T> = core::result::Result<T, ClassGroupError>;

/// Parse an integer with GMP base-0 semantics: `0x`/`0X` hex, `0b`/`0B`
/// binary, leading-`0` octal, otherwise decimal. A leading `+`/`-` is
/// accepted. (Equivalent to what `mpz_set_str(..., 0)` would do.)
pub fn parse_int_auto(s: &str) -> Result<Integer> {
    let t = s.trim();
    if t.is_empty() {
        return Err(ClassGroupError::ParseError("empty string".into()));
    }
    let (neg, rest) = match t.as_bytes()[0] {
        b'-' => (true, &t[1..]),
        b'+' => (false, &t[1..]),
        _ => (false, t),
    };
    let (radix, digits): (i32, &str) =
        if let Some(r) = rest.strip_prefix("0x").or_else(|| rest.strip_prefix("0X")) {
            (16, r)
        } else if let Some(r) = rest.strip_prefix("0b").or_else(|| rest.strip_prefix("0B")) {
            (2, r)
        } else if rest.len() > 1 && rest.starts_with('0') {
            (8, &rest[1..])
        } else {
            (10, rest)
        };
    let parsed = Integer::parse_radix(digits, radix)
        .map_err(|e| ClassGroupError::ParseError(e.to_string()))?;
    let mut v = Integer::from(parsed);
    if neg {
        v = -v;
    }
    Ok(v)
}

/// Errors produced while constructing parameters, parsing, or validating inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClassGroupError {
    /// A supplied value violated a precondition (out of range, wrong sign, ...).
    InvalidArgument(String),
    /// The parameters do not satisfy the CL-HSM_qk setup constraints.
    InvalidParameter(String),
    /// A string could not be parsed into an integer.
    ParseError(String),
    /// A value was outside the bound required by the scheme.
    OutOfBounds(String),
}

impl fmt::Display for ClassGroupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClassGroupError::InvalidArgument(s) => write!(f, "invalid argument: {s}"),
            ClassGroupError::InvalidParameter(s) => write!(f, "invalid parameter: {s}"),
            ClassGroupError::ParseError(s) => write!(f, "parse error: {s}"),
            ClassGroupError::OutOfBounds(s) => write!(f, "out of bounds: {s}"),
        }
    }
}

impl std::error::Error for ClassGroupError {}

#[cfg(test)]
mod tests {
    use tecdsa_bigint::BigIntExt;

    use super::*;

    #[test]
    fn parse_hex_decimal_octal_binary() {
        assert_eq!(parse_int_auto("0xff").unwrap(), Integer::from(255u64));
        assert_eq!(parse_int_auto("255").unwrap(), Integer::from(255u64));
        assert_eq!(parse_int_auto("0377").unwrap(), Integer::from(255u64));
        assert_eq!(parse_int_auto("0b11111111").unwrap(), Integer::from(255u64));
        assert_eq!(parse_int_auto("-0x10").unwrap(), Integer::from(-16i64));
        assert_eq!(parse_int_auto("0").unwrap(), Integer::from(0u64));
    }

    #[test]
    fn parse_large_hex() {
        let q =
            parse_int_auto("0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d").unwrap();
        assert_eq!(q.significant_bits(), 224);
        assert!(q.is_odd());
    }

    #[test]
    fn bytes_roundtrip() {
        let a = parse_int_auto("0xdeadbeef0123456789").unwrap();
        let b = Integer::from_bytes_msf(&a.to_bytes_msf());
        assert_eq!(a, b);
    }

    #[test]
    fn empty_string_errors() {
        assert!(parse_int_auto("").is_err());
        assert!(parse_int_auto("   ").is_err());
    }
}
