use elliptic_curve::{CurveArithmetic, FieldBytes, PrimeField};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use tecdsa_curve::TecdsaCurve;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const MSG_LEN: usize = 32;

const HASH_TAG: &[u8] = b"tecdsa/base-ot/key-derive";

fn derive_key(point_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(HASH_TAG);
    hasher.update(point_bytes);
    hasher.finalize().into()
}

fn xor_encrypt(key: &[u8; 32], msg: &[u8; MSG_LEN]) -> [u8; MSG_LEN] {
    let mut out = [0u8; MSG_LEN];
    for i in 0..MSG_LEN {
        out[i] = key[i] ^ msg[i];
    }
    out
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SenderSetup {
    pub public_key: Vec<u8>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ReceiverResponse {
    pub public_key: Vec<u8>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SenderPayload {
    pub ct0: [u8; MSG_LEN],
    pub ct1: [u8; MSG_LEN],
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct BaseOtSender {
    secret: [u8; 32],
    #[zeroize(skip)]
    public_key: Vec<u8>,
}

impl BaseOtSender {
    #[must_use]
    pub fn setup(rng: &mut impl CryptoRngCore) -> (Self, SenderSetup) {
        use k256::Secp256k1;
        let a = Secp256k1::random_scalar(rng);

        let big_a: <Secp256k1 as CurveArithmetic>::ProjectivePoint = Secp256k1::generator() * a;
        let big_a_affine: <Secp256k1 as CurveArithmetic>::AffinePoint = big_a.into();
        let pk_bytes = Secp256k1::point_to_bytes(&big_a_affine);

        let a_repr: FieldBytes<Secp256k1> = a.into();
        let mut secret = [0u8; 32];
        secret.copy_from_slice(a_repr.as_ref());

        let sender = Self {
            secret,
            public_key: pk_bytes.clone(),
        };
        let setup = SenderSetup {
            public_key: pk_bytes,
        };
        (sender, setup)
    }

    pub fn encrypt(
        self,
        response: &ReceiverResponse,
        m0: &[u8; MSG_LEN],
        m1: &[u8; MSG_LEN],
    ) -> Result<SenderPayload, OtError> {
        use k256::Secp256k1;
        type Point = <Secp256k1 as CurveArithmetic>::ProjectivePoint;
        type Scalar = <Secp256k1 as CurveArithmetic>::Scalar;

        let a_bytes: FieldBytes<Secp256k1> = self
            .secret
            .as_slice()
            .try_into()
            .map_err(|_| OtError("invalid sender secret length".into()))?;
        let a: Scalar = Option::from(Scalar::from_repr(a_bytes))
            .ok_or_else(|| OtError("invalid sender secret scalar".into()))?;

        let receiver_point = Secp256k1::point_from_bytes(&response.public_key)
            .map_err(|e| OtError(format!("invalid receiver key: {e}")))?;
        let big_b = Point::from(receiver_point);

        let sender_point = Secp256k1::point_from_bytes(&self.public_key)
            .map_err(|e| OtError(format!("invalid sender public key: {e}")))?;
        let big_a = Point::from(sender_point);

        let dh_for_zero: <Secp256k1 as CurveArithmetic>::AffinePoint = (big_b * a).into();
        let k0 = derive_key(&Secp256k1::point_to_bytes(&dh_for_zero));

        let dh_for_one: <Secp256k1 as CurveArithmetic>::AffinePoint = ((big_b - big_a) * a).into();
        let k1 = derive_key(&Secp256k1::point_to_bytes(&dh_for_one));

        let ct0 = xor_encrypt(&k0, m0);
        let ct1 = xor_encrypt(&k1, m1);

        Ok(SenderPayload { ct0, ct1 })
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct BaseOtReceiver {
    key: [u8; 32],
    #[zeroize(skip)]
    choice: bool,
}

impl BaseOtReceiver {
    pub fn choose(
        setup: &SenderSetup,
        choice: bool,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self, ReceiverResponse), OtError> {
        use k256::Secp256k1;
        type Point = <Secp256k1 as CurveArithmetic>::ProjectivePoint;

        let sender_point = Secp256k1::point_from_bytes(&setup.public_key)
            .map_err(|e| OtError(format!("invalid sender key: {e}")))?;
        let big_a = Point::from(sender_point);

        let x = Secp256k1::random_scalar(rng);

        let x_g = Secp256k1::generator() * x;
        let big_b = if choice { big_a + x_g } else { x_g };

        let response_point: <Secp256k1 as CurveArithmetic>::AffinePoint = big_b.into();
        let b_bytes = Secp256k1::point_to_bytes(&response_point);

        let shared: <Secp256k1 as CurveArithmetic>::AffinePoint = (big_a * x).into();
        let key = derive_key(&Secp256k1::point_to_bytes(&shared));

        let receiver = Self { key, choice };
        let response = ReceiverResponse {
            public_key: b_bytes,
        };
        Ok((receiver, response))
    }

    #[must_use]
    pub fn decrypt(self, payload: &SenderPayload) -> [u8; MSG_LEN] {
        let ct = if self.choice {
            &payload.ct1
        } else {
            &payload.ct0
        };
        xor_encrypt(&self.key, ct)
    }
}

#[derive(Debug, Clone)]
pub struct OtError(pub String);

impl std::fmt::Display for OtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OtError: {}", self.0)
    }
}

impl std::error::Error for OtError {}

#[cfg(test)]
mod tests {
    use rand_core::{OsRng, RngCore};

    use super::*;

    #[test]
    fn sender_receiver_choice_zero() {
        let mut rng = OsRng;
        let m0 = [0xAA_u8; MSG_LEN];
        let m1 = [0xBB_u8; MSG_LEN];

        let (sender, setup) = BaseOtSender::setup(&mut rng);
        let (receiver, response) =
            BaseOtReceiver::choose(&setup, false, &mut rng).expect("choose should succeed");
        let payload = sender
            .encrypt(&response, &m0, &m1)
            .expect("encrypt should succeed");
        let result = receiver.decrypt(&payload);

        assert_eq!(result, m0, "choice=0 should yield m0");
    }

    #[test]
    fn sender_receiver_choice_one() {
        let mut rng = OsRng;
        let m0 = [0xAA_u8; MSG_LEN];
        let m1 = [0xBB_u8; MSG_LEN];

        let (sender, setup) = BaseOtSender::setup(&mut rng);
        let (receiver, response) =
            BaseOtReceiver::choose(&setup, true, &mut rng).expect("choose should succeed");
        let payload = sender
            .encrypt(&response, &m0, &m1)
            .expect("encrypt should succeed");
        let result = receiver.decrypt(&payload);

        assert_eq!(result, m1, "choice=1 should yield m1");
    }

    #[test]
    fn receiver_cannot_learn_other_message() {
        let mut rng = OsRng;
        let m0 = [0xAA_u8; MSG_LEN];
        let m1 = [0xBB_u8; MSG_LEN];

        let (sender, setup) = BaseOtSender::setup(&mut rng);
        let (receiver, response) =
            BaseOtReceiver::choose(&setup, false, &mut rng).expect("choose should succeed");
        let payload = sender
            .encrypt(&response, &m0, &m1)
            .expect("encrypt should succeed");

        let result = receiver.decrypt(&payload);
        assert_eq!(result, m0);

        let wrong_decrypt = xor_encrypt(&[0u8; 32], &payload.ct1);
        assert_ne!(
            wrong_decrypt, m1,
            "receiver should not be able to get m1 trivially"
        );
    }

    #[test]
    fn random_messages_roundtrip() {
        let mut rng = OsRng;

        for choice in [false, true] {
            let mut m0 = [0u8; MSG_LEN];
            let mut m1 = [0u8; MSG_LEN];
            rng.fill_bytes(&mut m0);
            rng.fill_bytes(&mut m1);

            let (sender, setup) = BaseOtSender::setup(&mut rng);
            let (receiver, response) =
                BaseOtReceiver::choose(&setup, choice, &mut rng).expect("choose should succeed");
            let payload = sender
                .encrypt(&response, &m0, &m1)
                .expect("encrypt should succeed");
            let result = receiver.decrypt(&payload);

            let expected = if choice { m1 } else { m0 };
            assert_eq!(result, expected);
        }
    }
}
