// SPDX-License-Identifier: MIT OR Apache-2.0
/// Trait defining the security parameters for CGGMP20 threshold ECDSA.
///
/// These constants determine the size of RSA moduli, the range-proof
/// slack parameters, and the statistical security parameter used in
/// zero-knowledge proofs.
pub trait Cggmp20SecurityParams: Send + Sync + 'static {
    /// Bit-length of each RSA prime factor (`p`, `q`).
    const RSA_PRIME_BITS: u32;
    /// Bit-length of the RSA modulus `N = p * q`.
    const RSA_MODULUS_BITS: u32;
    /// Slack parameter `epsilon` for range proofs (bits).
    const EPSILON: usize;
    /// Bit-length bound `ell` on the secret scalar.
    const ELL: usize;
    /// Bit-length bound `ell'` on the masking value.
    const ELL_PRIME: usize;
    /// Statistical security parameter `kappa` (bits).
    const KAPPA: usize;
}

/// 128-bit computational security level.
///
/// Parameters follow CGGMP20 Table 2 (revised version, 2024):
/// - 3071-bit Paillier modulus (two 1536-bit safe primes)
/// - `ε = 512`, `ℓ = 256`, `ℓ' = 1280`, `κ = 256`
#[derive(Debug, Clone, Copy)]
pub struct SecurityLevel128;

impl Cggmp20SecurityParams for SecurityLevel128 {
    const RSA_PRIME_BITS: u32 = 1536;
    const RSA_MODULUS_BITS: u32 = 3071;
    const EPSILON: usize = 512;
    const ELL: usize = 256;
    const ELL_PRIME: usize = 1280;
    const KAPPA: usize = 256;
}
