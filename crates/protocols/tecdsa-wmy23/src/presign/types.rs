// SPDX-License-Identifier: MIT OR Apache-2.0
//! WMY23 presigning types.

use zeroize::Zeroize;

/// Presignature output from WMY23 presigning (4 rounds).
///
/// Contains the combined nonce point $R$, x-coordinate $r$, this party's
/// secrets for the online signing phase, and the verification material
/// $V_i$ that makes online signing *identifiable* (WMY23 Figures 7-9).
///
/// The key relationships are:
/// - $R = g^{1/k}$ (nonce point, where $k = \sum_i \hat{k}_i$)
/// - $r = x(R) \bmod q$
/// - $\sigma_i = \hat{k}_i \hat{x}_i + \sum_{j} (\mu_{ij} + \nu_{ji})$
///   is this party's additive share of $k \cdot x$
/// - $\mu_{ij} + \nu_{ij} = \hat{k}_i \hat{x}_j$ (the key MtAwc product, with
///   this party as the nonce-share holder/receiver)
///
/// In identifiable online signing each party broadcasts $M_{ij} = R^{\mu_{ij}}$
/// with a NIZKDL-2PC proof (relation `R_DL-2PC`, WMY23 Fig. 13) and its
/// partial signature $s_i = m \hat{k}_i + r \sigma_i$. Every party verifies
/// the proofs and the share-consistency equation
/// $R^{s_i} \prod_{j \ne i} (M_{ji}/M_{ij})^{r} = R_i^{m} \hat{X}_i^{r}$
/// (the additive-share form of WMY23 Equation (3)), pinpointing any cheater.
pub struct Wmy23Presignature {
    /// This party's nonce share $\hat{k}_i$ (Lagrange-weighted).
    pub k_i: k256::Scalar,
    /// Combined nonce point $R = g^{1/k}$.
    pub big_r: k256::ProjectivePoint,
    /// $r = x(R) \bmod q$.
    pub r_x: k256::Scalar,
    /// This party's additive share of $k \cdot x$.
    pub sigma_i: k256::Scalar,
    /// Number of signing parties.
    pub n_signers: usize,

    // ---- WMY23 Vi material for identifiable online signing (Figs 7-9) ----
    /// This party's 0-based local position within the signing quorum.
    pub index: usize,
    /// Commitment randomness $\hat{k}_i'$ for $\hat{k}_i$ (NIZKDL-2PC witness).
    pub hat_k_randomness: k256::Scalar,
    /// This party's Lagrange-weighted key share $\hat{x}_i$ (for $s_{ii}$).
    pub hat_x_i: k256::Scalar,
    /// $\mu_{ij}$: this party's key-MtAwc shares as nonce-share holder.
    /// `None` at this party's own index.
    pub mu_shares: Vec<Option<k256::Scalar>>,
    /// $N_{ij} = g^{\nu_{ij}}$: counterparties' key-MtAwc shares-in-exponent.
    /// `None` at this party's own index.
    pub nu_points: Vec<Option<k256::ProjectivePoint>>,
    /// $PC_{\hat{k}_j} = g^{\hat{k}_j} h^{\hat{k}_j'}$ for every party $j$.
    pub pc_hat_k: Vec<k256::ProjectivePoint>,
    /// $R_j = R^{\hat{k}_j}$ for every party $j$ (nonce share in exponent).
    pub big_r_shares: Vec<k256::ProjectivePoint>,
    /// $\hat{X}_j = g^{\hat{x}_j}$ for every party $j$ (key share in exponent).
    pub xhat_points: Vec<k256::ProjectivePoint>,
}

impl Zeroize for Wmy23Presignature {
    fn zeroize(&mut self) {
        self.k_i.zeroize();
        self.sigma_i.zeroize();
        self.hat_k_randomness.zeroize();
        self.hat_x_i.zeroize();
        for mu in self.mu_shares.iter_mut().flatten() {
            mu.zeroize();
        }
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
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}
