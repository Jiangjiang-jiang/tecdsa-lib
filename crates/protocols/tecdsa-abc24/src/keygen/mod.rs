pub mod interactive;
pub(crate) mod machine;
pub(crate) mod wire;

use elliptic_curve::{sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField};
pub use interactive::{
    client_finalize_keygen, client_keygen_step2, client_verify_step3, interactive_keygen,
    server_finalize_keygen, server_keygen_step1, server_keygen_step1_with_dk, server_keygen_step3,
    ClientStep2Msg, ClientStep2State, ServerStep1Msg, ServerStep1State, ServerStep3Msg,
    ServerStep3State,
};
pub use machine::{Abc24KeyShare, Abc24KeygenMachine, Abc24KeygenMsg, TwoPartyRole};
use rand_core::CryptoRngCore;
use tecdsa_curve::TecdsaCurve;

use crate::{
    key_share::{Abc24ClientKeyShare, Abc24ServerKeyShare},
    setup::SetupData,
};

pub fn trusted_dealer_keygen<C: TecdsaCurve>(
    rng: &mut impl CryptoRngCore,
) -> (Abc24ServerKeyShare<C>, Abc24ClientKeyShare<C>)
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let x1 = C::random_scalar(rng);
    let x2 = C::random_scalar(rng);

    let x = x1 + x2;
    let public_key = C::generator() * x;
    let x1_point = C::generator() * x1;
    let x2_point = C::generator() * x2;

    let dk = tecdsa_paillier::keygen(rng).expect("Paillier keygen failed");
    let ek = dk.encryption_key().clone();

    let setup = SetupData::from_ek(&ek);

    let x2_bytes = x2.to_repr();
    let x2_plaintext = tecdsa_paillier::backend::Integer::from_bytes_msf(x2_bytes.as_ref());

    let (enc_x2, _nonce) = dk
        .encrypt_with_random(rng, &x2_plaintext)
        .expect("Paillier encryption of x_2 failed");

    let server_share = Abc24ServerKeyShare {
        secret_share: x2,
        public_key,
        client_public_share: x1_point,
        dk,
        setup: setup.clone(),
    };

    let client_share = Abc24ClientKeyShare {
        secret_share: x1,
        public_key,
        server_public_share: x2_point,
        enc_x2,
        ek,
        setup,
    };

    (server_share, client_share)
}

#[cfg(test)]
mod tests {
    use k256::Secp256k1;

    use super::*;

    #[test]
    fn trusted_dealer_produces_consistent_shares() {
        let mut rng = rand_core::OsRng;
        let (server, client) = trusted_dealer_keygen::<Secp256k1>(&mut rng);

        assert_eq!(server.public_key, client.public_key);

        let x = server.secret_share + client.secret_share;
        let expected_pk = Secp256k1::generator() * x;
        assert_eq!(server.public_key, expected_pk);
    }

    #[test]
    fn paillier_encrypts_x2_correctly() {
        let mut rng = rand_core::OsRng;
        let (server, client) = trusted_dealer_keygen::<Secp256k1>(&mut rng);

        let decrypted = server
            .dk
            .decrypt(&client.enc_x2)
            .expect("decryption failed");
        let x2_bytes = server.secret_share.to_repr();
        let x2_int = tecdsa_paillier::backend::Integer::from_bytes_msf(x2_bytes.as_ref());
        assert_eq!(decrypted, x2_int);
    }

    #[test]
    fn public_shares_are_consistent() {
        let mut rng = rand_core::OsRng;
        let (server, client) = trusted_dealer_keygen::<Secp256k1>(&mut rng);

        let x1_point = Secp256k1::generator() * client.secret_share;
        let x2_point = Secp256k1::generator() * server.secret_share;

        assert_eq!(server.client_public_share, x1_point);
        assert_eq!(client.server_public_share, x2_point);
        assert_eq!(x1_point + x2_point, server.public_key);
    }
}
