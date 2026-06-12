use rug::Integer;
use serde::{Deserialize, Serialize};

use crate::{
    kgen::{JlPublicKey, JlSecretKey},
    zk::{zkqr2k::ZkQr2kProof, zkqr2kdl::ZkQr2kDlProof},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkJlModProof {
    pub proof_qr2k: ZkQr2kProof,
    pub proof_qr2kdl: ZkQr2kDlProof,
}

impl ZkJlModProof {
    pub fn prove(
        pk: &JlPublicKey,
        sk: &JlSecretKey,
        x: &Integer,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Self {
        let proof_qr2k = ZkQr2kProof::prove(&pk.n, pk.k, x, &pk.h, rng);
        let proof_qr2kdl = ZkQr2kDlProof::prove(&pk.n, pk.k, &sk.alpha, &pk.h, &pk.y, rng);

        Self {
            proof_qr2k,
            proof_qr2kdl,
        }
    }

    #[must_use]
    pub fn verify(&self) -> bool {
        self.proof_qr2k.verify() && self.proof_qr2kdl.verify()
    }

    #[must_use]
    pub fn verify_for_pk(&self, pk: &JlPublicKey) -> bool {
        if self.proof_qr2k.n != pk.n || self.proof_qr2k.k != pk.k || self.proof_qr2k.h != pk.h {
            return false;
        }
        if self.proof_qr2kdl.n != pk.n
            || self.proof_qr2kdl.k != pk.k
            || self.proof_qr2kdl.h != pk.h
            || self.proof_qr2kdl.y != pk.y
        {
            return false;
        }
        self.verify()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kgen::generate_keypair_with_qnr;

    #[test]
    fn zkjlmod_prove_and_verify() {
        let mut rng = rand::thread_rng();
        let (pk, sk, x) = generate_keypair_with_qnr(256, 32, &mut rng);

        let proof = ZkJlModProof::prove(&pk, &sk, &x, &mut rng);
        assert!(proof.verify());
    }
}
