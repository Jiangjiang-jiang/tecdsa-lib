use zeroize::Zeroize;

pub struct Wmy23Presignature {
    pub k_i: k256::Scalar,
    pub big_r: k256::ProjectivePoint,
    pub r_x: k256::Scalar,
    pub sigma_i: k256::Scalar,
    pub n_signers: usize,

    pub index: usize,
    pub hat_k_randomness: k256::Scalar,
    pub hat_x_i: k256::Scalar,
    pub mu_shares: Vec<Option<k256::Scalar>>,
    pub nu_points: Vec<Option<k256::ProjectivePoint>>,
    pub pc_hat_k: Vec<k256::ProjectivePoint>,
    pub big_r_shares: Vec<k256::ProjectivePoint>,
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
