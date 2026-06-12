use elliptic_curve::{sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField};
use tecdsa_curve::TecdsaCurve;
use tecdsa_joye_libert::kgen::{JlPublicKey, JlSecretKey};
use zeroize::Zeroize;

#[derive(Debug, Clone)]
pub struct VssSetup {
    pub threshold: u16,
    pub total: u16,
}

#[derive(Clone)]
pub struct Xal23KeyShare<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub party_index: u16,
    pub secret_share: C::Scalar,
    pub public_key: C::ProjectivePoint,
    pub public_shares: Vec<C::ProjectivePoint>,
    pub vss_setup: VssSetup,
    pub jl_sk: JlSecretKey,
    pub jl_pks: Vec<JlPublicKey>,
}

impl<C: TecdsaCurve> Zeroize for Xal23KeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn zeroize(&mut self) {
        self.secret_share.zeroize();
    }
}

impl<C: TecdsaCurve> std::fmt::Debug for Xal23KeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Xal23KeyShare")
            .field("party_index", &self.party_index)
            .field("secret_share", &"[REDACTED]")
            .field("vss_setup", &self.vss_setup)
            .finish()
    }
}

pub fn trusted_dealer_keygen<C: TecdsaCurve>(
    n: u16,
    t: u16,
    jl_p_bits: u64,
    jl_k: u32,
    rng: &mut impl rand_core::CryptoRngCore,
) -> Vec<Xal23KeyShare<C>>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    use elliptic_curve::Field;

    assert!(n >= 2, "need at least 2 parties");
    assert!(t >= 2, "threshold must be >= 2");

    let x = C::random_scalar(rng);
    let Y = C::generator() * x;

    let mut shares = Vec::with_capacity(n as usize);
    let mut sum = C::Scalar::ZERO;
    for _ in 0..(n - 1) {
        let x_i = C::random_scalar(rng);
        sum += x_i;
        shares.push(x_i);
    }
    shares.push(x - sum);

    let public_shares: Vec<C::ProjectivePoint> =
        shares.iter().map(|xi| C::generator() * *xi).collect();

    let mut jl_pks = Vec::with_capacity(n as usize);
    let mut jl_sks = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let (pk, sk) = tecdsa_joye_libert::kgen::generate_keypair_with_params(jl_p_bits, jl_k, rng);
        jl_pks.push(pk);
        jl_sks.push(sk);
    }

    let mut key_shares = Vec::with_capacity(n as usize);
    for i in 0..n {
        let idx = i as usize;
        key_shares.push(Xal23KeyShare {
            party_index: i,
            secret_share: shares[idx],
            public_key: Y,
            public_shares: public_shares.clone(),
            vss_setup: VssSetup {
                threshold: t,
                total: n,
            },
            jl_sk: jl_sks[idx].clone(),
            jl_pks: jl_pks.clone(),
        });
    }

    key_shares
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_dealer_produces_valid_shares() {
        let mut rng = rand::thread_rng();
        let shares = trusted_dealer_keygen::<k256::Secp256k1>(3, 2, 256, 128, &mut rng);

        assert_eq!(shares.len(), 3);

        assert_eq!(shares[0].public_key, shares[1].public_key);
        assert_eq!(shares[1].public_key, shares[2].public_key);

        let sum: k256::Scalar = shares
            .iter()
            .fold(k256::Scalar::ZERO, |acc, s| acc + s.secret_share);
        let reconstructed_pk = k256::ProjectivePoint::GENERATOR * sum;
        assert_eq!(reconstructed_pk, shares[0].public_key);
    }
}
