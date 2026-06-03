// SPDX-License-Identifier: MIT OR Apache-2.0
//! WMY23 presigning types.

use zeroize::Zeroize;

/// Presignature output from WMY23 presigning (4 rounds).
///
/// Contains the combined nonce point $R$, x-coordinate $r$, and per-party
/// secrets needed for the 1-round online signing phase.
///
/// The key relationship is:
/// - $R = g^{1/k}$ (nonce point, where $k = \sum k_i$)
/// - $r = x(R) \bmod q$
/// - $\sigma_i = k_i \cdot x_i + \sum_j (\mu_{ij} + \nu_{ji})$
///   is this party's share of $k \cdot x$
/// - In online signing: $s_i = m \cdot k_i + r \cdot \sigma_i$,
///   then $s = \sum s_i = k(m + rx)$.
///
/// Since $R = g^{1/k}$, the signature $(r, s)$ with $s = k(m+rx)$ is valid:
/// the ECDSA verifier computes $R' = g^{m/s} \cdot pk^{r/s} = g^{1/k} = R$.
pub struct Wmy23Presignature {
    /// This party's nonce share $k_i$.
    pub k_i: k256::Scalar,
    /// Combined nonce point $R = g^{1/k}$.
    pub big_r: k256::ProjectivePoint,
    /// $r = x(R) \bmod q$.
    pub r_x: k256::Scalar,
    /// This party's share of $k \cdot x$:
    /// $\sigma_i = k_i \cdot x_i + \sum_j (\mu_{ij} + \nu_{ji})$.
    pub sigma_i: k256::Scalar,
    /// Number of signing parties.
    pub n_signers: usize,
}

impl Zeroize for Wmy23Presignature {
    fn zeroize(&mut self) {
        self.k_i.zeroize();
        self.sigma_i.zeroize();
    }
}

impl Drop for Wmy23Presignature {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl std::fmt::Debug for Wmy23Presignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wmy23Presignature")
            .field("n_signers", &self.n_signers)
            .finish_non_exhaustive()
    }
}
