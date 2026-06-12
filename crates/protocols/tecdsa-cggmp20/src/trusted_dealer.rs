use elliptic_curve::{sec1::ModulusSize, CurveArithmetic, FieldBytesSize};
use rand_core::CryptoRngCore;
use tecdsa_curve::TecdsaCurve;
use tecdsa_vss::feldman;

use crate::key_share::{Cggmp20CoreKeyShare, VssSetup};

pub fn deal<C: TecdsaCurve>(
    secret_key: &<C as CurveArithmetic>::Scalar,
    threshold: u16,
    n: u16,
    rng: &mut impl CryptoRngCore,
) -> Vec<Cggmp20CoreKeyShare<C>>
where
    FieldBytesSize<C>: ModulusSize,
{
    let (shares, _commitments) = feldman::split::<C>(secret_key, threshold, n, rng);

    let public_key = C::generator() * secret_key;

    let public_shares: Vec<C::ProjectivePoint> = shares
        .iter()
        .map(|share| C::generator() * share.value)
        .collect();

    shares
        .into_iter()
        .map(|share| Cggmp20CoreKeyShare {
            party_index: share.index - 1,
            secret_share: share.value,
            public_key,
            public_shares: public_shares.clone(),
            vss_setup: VssSetup {
                threshold,
                total: n,
            },
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use k256::Secp256k1;

    use super::*;

    #[test]
    fn trusted_dealer_produces_valid_shares() {
        let mut rng = rand_core::OsRng;

        let secret_key = Secp256k1::random_scalar(&mut rng);

        let shares = deal::<Secp256k1>(&secret_key, 2, 3, &mut rng);

        assert_eq!(shares.len(), 3);

        let expected_public_key = Secp256k1::generator() * secret_key;
        for (i, share) in shares.iter().enumerate() {
            assert_eq!(share.party_index, i as u16);
            assert_eq!(share.public_key, expected_public_key);
            assert_eq!(share.vss_setup.threshold, 2);
            assert_eq!(share.vss_setup.total, 3);
        }

        for (i, share) in shares.iter().enumerate() {
            let expected_public_share = Secp256k1::generator() * share.secret_share;
            assert_eq!(share.public_shares[i], expected_public_share);
        }
    }
}
