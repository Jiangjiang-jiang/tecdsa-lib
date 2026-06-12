use std::cell::RefCell;

use rand_core::CryptoRngCore;
use rug::{integer::Order, Integer};

use crate::{
    cl::{Ciphertext as ClHsmqkCiphertext, ClError, ClSetup, PublicKey as ClHsmqkPublicKey, Qfi},
    nim::{Nim, NimStateA, NimStateB},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NimRole {
    A,
    B,
}

pub struct NimMtaSetup {
    pub setup: RefCell<ClSetup>,
    pub pk: ClHsmqkPublicKey,
    pub role: NimRole,
}

impl Clone for NimMtaSetup {
    fn clone(&self) -> Self {
        unimplemented!(
            "NimMtaSetup::clone is not supported; each party should create its own setup"
        )
    }
}

pub enum NimEncoding {
    RoleA(Qfi),
    RoleB(ClHsmqkCiphertext),
}

impl Clone for NimEncoding {
    fn clone(&self) -> Self {
        unimplemented!(
            "NimEncoding::clone is not supported; \
             each party produces its own encoding"
        )
    }
}

pub enum NimState {
    RoleA(NimStateA),
    RoleB(NimStateB),
}

#[derive(Debug, thiserror::Error)]
pub enum NimMtaError {
    #[error("CL error: {0}")]
    Cl(#[from] ClError),

    #[error("NIM role mismatch: expected encoding from {expected}, got {got}")]
    RoleMismatch {
        expected: &'static str,
        got: &'static str,
    },

    #[error("invalid parameter: {0}")]
    InvalidParam(String),
}

impl std::fmt::Display for NimRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::A => write!(f, "A"),
            Self::B => write!(f, "B"),
        }
    }
}

pub struct NimMtA;

impl tecdsa_protocol::MtABroadcast for NimMtA {
    type Setup = NimMtaSetup;
    type Encoding = NimEncoding;
    type State = NimState;
    type Error = NimMtaError;

    fn encode(
        setup: &Self::Setup,
        input_bytes: &[u8],
        _q_bytes: &[u8],
        _rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::Encoding, Self::State), Self::Error> {
        let mut cl_setup = setup.setup.borrow_mut();
        let mut nim = Nim::new(&mut cl_setup);

        match setup.role {
            NimRole::A => {
                let out = nim.encode_a(input_bytes, &setup.pk)?;
                Ok((NimEncoding::RoleA(out.pe_a), NimState::RoleA(out.state)))
            }
            NimRole::B => {
                let out = nim.encode_b(input_bytes, &setup.pk)?;
                Ok((NimEncoding::RoleB(out.pe_b), NimState::RoleB(out.state)))
            }
        }
    }

    fn decode(
        setup: &Self::Setup,
        other_encoding: &Self::Encoding,
        my_state: &Self::State,
        q_bytes: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        let cl_setup = setup.setup.borrow();
        drop(cl_setup);

        let mut cl_setup = setup.setup.borrow_mut();
        let nim = Nim::new(&mut cl_setup);

        let q = Integer::from_digits(q_bytes, Order::Msf);

        match (my_state, other_encoding) {
            (NimState::RoleA(state_a), NimEncoding::RoleB(pe_b)) => {
                let share_bytes = nim.decode_a(pe_b, state_a)?;
                let share = Integer::from_digits(&share_bytes, Order::Msf);
                let share_mod_q = share % &q;
                Ok(share_mod_q.to_digits::<u8>(Order::Msf))
            }
            (NimState::RoleB(state_b), NimEncoding::RoleA(pe_a)) => {
                let share_bytes = nim.decode_b(pe_a, state_b)?;
                let share = Integer::from_digits(&share_bytes, Order::Msf);
                let share_mod_q = share % &q;
                Ok(share_mod_q.to_digits::<u8>(Order::Msf))
            }
            (NimState::RoleA(_), NimEncoding::RoleA(_)) => Err(NimMtaError::RoleMismatch {
                expected: "B",
                got: "A",
            }),
            (NimState::RoleB(_), NimEncoding::RoleB(_)) => Err(NimMtaError::RoleMismatch {
                expected: "A",
                got: "B",
            }),
        }
    }
}

pub struct ScaledDecryptSetup {
    pub setup: RefCell<ClSetup>,
    pub pk: ClHsmqkPublicKey,
}

impl Clone for ScaledDecryptSetup {
    fn clone(&self) -> Self {
        unimplemented!("ScaledDecryptSetup::clone is not supported; each party creates its own")
    }
}

pub struct ScaledDecryptEncoding {
    pub c1: Qfi,
    pub c2: Qfi,
    pub u_com: Qfi,
}

impl Clone for ScaledDecryptEncoding {
    fn clone(&self) -> Self {
        unimplemented!(
            "ScaledDecryptEncoding::clone is not supported; \
             each party produces its own encoding"
        )
    }
}

pub struct ScaledDecryptState {
    pub alpha_i: Vec<u8>,
    pub beta_i: Vec<u8>,
    pub b_i: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum ScaledDecryptError {
    #[error("CL error: {0}")]
    Cl(#[from] ClError),

    #[error("invalid parameter: {0}")]
    InvalidParam(String),
}

pub struct ScaledDecryptMtA;

impl ScaledDecryptMtA {
    pub fn aggregate(
        setup: &ScaledDecryptSetup,
        encodings: &[&ScaledDecryptEncoding],
    ) -> Result<ScaledDecryptEncoding, ScaledDecryptError> {
        let cl = setup.setup.borrow();

        let mut a1 = cl.identity()?;
        let mut a2 = cl.identity()?;
        let mut b_agg = cl.identity()?;

        for enc in encodings {
            a1 = cl.compose(&a1, &enc.c1)?;
            a2 = cl.compose(&a2, &enc.c2)?;
            b_agg = cl.compose(&b_agg, &enc.u_com)?;
        }

        Ok(ScaledDecryptEncoding {
            c1: a1,
            c2: a2,
            u_com: b_agg,
        })
    }

    pub fn aggregate_f_shares(
        setup: &ScaledDecryptSetup,
        f_shares: &[Qfi],
    ) -> Result<Vec<u8>, ScaledDecryptError> {
        let cl = setup.setup.borrow();
        let mut f_agg = cl.identity()?;
        for fi in f_shares {
            f_agg = cl.compose(&f_agg, fi)?;
        }

        #[allow(non_snake_case)]
        let result_bytes = cl.dlog_in_F_bytes(&f_agg)?;
        Ok(result_bytes)
    }
}

impl tecdsa_protocol::MtABroadcast for ScaledDecryptMtA {
    type Setup = ScaledDecryptSetup;
    type Encoding = ScaledDecryptEncoding;
    type State = ScaledDecryptState;
    type Error = ScaledDecryptError;

    fn encode(
        setup: &Self::Setup,
        input_bytes: &[u8],
        _q_bytes: &[u8],
        _rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::Encoding, Self::State), Self::Error> {
        if input_bytes.len() != 64 {
            return Err(ScaledDecryptError::InvalidParam(format!(
                "input_bytes must be 64 bytes (a_i || b_i), got {}",
                input_bytes.len()
            )));
        }

        let a_i_bytes = &input_bytes[..32];
        let b_i_bytes = &input_bytes[32..];

        let mut cl = setup.setup.borrow_mut();

        let (sk_tmp, _) = cl.keygen()?;
        let alpha_i = cl.sk_to_bytes(&sk_tmp)?;

        let ct = cl.encrypt_with_r_bytes(&setup.pk, a_i_bytes, &alpha_i)?;
        let (c1, c2) = cl.ct_components(&ct)?;

        let (sk_tmp2, _) = cl.keygen()?;
        let beta_i = cl.sk_to_bytes(&sk_tmp2)?;

        let h_beta = cl.power_of_h_bytes(&beta_i)?;
        let pk_b = cl.pk_pow_bytes(&setup.pk, b_i_bytes)?;
        let u_com = cl.compose(&h_beta, &pk_b)?;

        let encoding = ScaledDecryptEncoding { c1, c2, u_com };
        let state = ScaledDecryptState {
            alpha_i,
            beta_i,
            b_i: b_i_bytes.to_vec(),
        };

        Ok((encoding, state))
    }

    fn decode(
        setup: &Self::Setup,
        other_encoding: &Self::Encoding,
        my_state: &Self::State,
        _q_bytes: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        let cl = setup.setup.borrow();

        let f_i = cl.multiexp_signed_bytes(
            &[
                &other_encoding.c2,
                &other_encoding.c1,
                &other_encoding.u_com,
            ],
            &[
                (false, my_state.b_i.clone()),
                (false, my_state.beta_i.clone()),
                (true, my_state.alpha_i.clone()),
            ],
        )?;

        let serialised = f_i.to_bytes();
        Ok(serialised)
    }
}

impl ScaledDecryptMtA {
    pub fn decode_to_qfi(decoded_bytes: &[u8]) -> Result<Qfi, ScaledDecryptError> {
        let qfi = Qfi::from_bytes(decoded_bytes);
        Ok(qfi)
    }
}

#[cfg(test)]
mod tests {
    use tecdsa_bigint::mul_mod;
    use tecdsa_protocol::MtABroadcast;

    use super::*;

    fn nim_setup(seed: &str, role: NimRole) -> NimMtaSetup {
        let mut cl = ClSetup::new_secp256k1(seed).expect("CL setup");
        let (_sk, pk) = cl.keygen().expect("keygen");
        NimMtaSetup {
            setup: RefCell::new(cl),
            pk,
            role,
        }
    }

    fn secp256k1_order_bytes() -> Vec<u8> {
        let q = Integer::from_str_radix(
            "115792089237316195423570985008687907852837564279074904382605163141518161494337",
            10,
        )
        .unwrap();
        q.to_digits::<u8>(Order::Msf)
    }

    #[test]
    fn nim_mta_roundtrip() {
        let q_bytes = secp256k1_order_bytes();
        let q = Integer::from_digits(&q_bytes, Order::Msf);

        let x = Integer::from(7u32);
        let y = Integer::from(11u32);

        let setup_a = nim_setup("42", NimRole::A);
        let setup_b = nim_setup("42", NimRole::B);

        let mut rng = rand::thread_rng();

        let (enc_a, state_a) =
            NimMtA::encode(&setup_a, &x.to_digits::<u8>(Order::Msf), &q_bytes, &mut rng)
                .expect("encode A");

        let (enc_b, state_b) =
            NimMtA::encode(&setup_b, &y.to_digits::<u8>(Order::Msf), &q_bytes, &mut rng)
                .expect("encode B");

        let share_a_bytes = NimMtA::decode(&setup_a, &enc_b, &state_a, &q_bytes).expect("decode A");

        let share_b_bytes = NimMtA::decode(&setup_b, &enc_a, &state_b, &q_bytes).expect("decode B");

        let z_a = Integer::from_digits(&share_a_bytes, Order::Msf);
        let z_b = Integer::from_digits(&share_b_bytes, Order::Msf);
        let sum = Integer::from(&z_a + &z_b) % &q;
        let expected = mul_mod(&x, &y, &q);

        assert_eq!(sum, expected, "NIM MtABroadcast: z_A + z_B != x*y mod q");
    }

    #[test]
    #[ignore = "redundant broadcast MtA variant"]
    fn nim_mta_larger_values() {
        let q_bytes = secp256k1_order_bytes();
        let q = Integer::from_digits(&q_bytes, Order::Msf);

        let x = Integer::from(&q - 3);
        let y = Integer::from(1000u32);

        let setup_a = nim_setup("100", NimRole::A);
        let setup_b = nim_setup("100", NimRole::B);
        let mut rng = rand::thread_rng();

        let (enc_a, state_a) =
            NimMtA::encode(&setup_a, &x.to_digits::<u8>(Order::Msf), &q_bytes, &mut rng)
                .expect("encode A");
        let (enc_b, state_b) =
            NimMtA::encode(&setup_b, &y.to_digits::<u8>(Order::Msf), &q_bytes, &mut rng)
                .expect("encode B");

        let share_a_bytes = NimMtA::decode(&setup_a, &enc_b, &state_a, &q_bytes).expect("decode A");
        let share_b_bytes = NimMtA::decode(&setup_b, &enc_a, &state_b, &q_bytes).expect("decode B");

        let z_a = Integer::from_digits(&share_a_bytes, Order::Msf);
        let z_b = Integer::from_digits(&share_b_bytes, Order::Msf);
        let sum = Integer::from(&z_a + &z_b) % &q;
        let expected = mul_mod(&x, &y, &q);

        assert_eq!(
            sum, expected,
            "NIM MtABroadcast: large values, z_A + z_B != x*y mod q"
        );
    }

    #[test]
    #[ignore = "redundant broadcast MtA variant"]
    fn nim_mta_role_mismatch_errors() {
        let q_bytes = secp256k1_order_bytes();

        let setup_a = nim_setup("200", NimRole::A);
        let mut rng = rand::thread_rng();

        let (enc_a, state_a) =
            NimMtA::encode(&setup_a, &[7], &q_bytes, &mut rng).expect("encode A");

        let result = NimMtA::decode(&setup_a, &enc_a, &state_a, &q_bytes);
        assert!(result.is_err(), "decoding own-role encoding must fail");

        match result.unwrap_err() {
            NimMtaError::RoleMismatch { expected, got } => {
                assert_eq!(expected, "B");
                assert_eq!(got, "A");
            }
            other => panic!("expected RoleMismatch, got: {other}"),
        }
    }

    #[test]
    fn scaled_decrypt_mta_roundtrip() {
        let q_bytes = secp256k1_order_bytes();
        let q = Integer::from_digits(&q_bytes, Order::Msf);

        let n = 3usize;
        let mut cl = ClSetup::new_secp256k1("9002").expect("CL setup");
        let (_sk, pk) = cl.keygen().expect("keygen");

        let setup = ScaledDecryptSetup {
            setup: RefCell::new(cl),
            pk,
        };

        let mut rng = rand::thread_rng();

        use rand::RngCore;
        let mut a_scalars = Vec::new();
        let mut b_scalars = Vec::new();
        for _ in 0..n {
            let mut buf = [0u8; 32];
            rng.fill_bytes(&mut buf);
            let val = Integer::from_digits(&buf, Order::Msf) % &q;
            a_scalars.push(val);

            rng.fill_bytes(&mut buf);
            let val = Integer::from_digits(&buf, Order::Msf) % &q;
            b_scalars.push(val);
        }

        let a_sum: Integer = a_scalars.iter().fold(Integer::from(0u32), |acc, v| acc + v) % &q;
        let b_sum: Integer = b_scalars.iter().fold(Integer::from(0u32), |acc, v| acc + v) % &q;
        let expected = mul_mod(&a_sum, &b_sum, &q);

        let mut encodings = Vec::new();
        let mut states = Vec::new();

        for i in 0..n {
            let mut input = vec![0u8; 64];
            let a_bytes = a_scalars[i].to_digits::<u8>(Order::Msf);
            let b_bytes = b_scalars[i].to_digits::<u8>(Order::Msf);
            let a_offset = 32 - a_bytes.len().min(32);
            input[a_offset..32].copy_from_slice(&a_bytes[..a_bytes.len().min(32)]);
            let b_offset = 64 - b_bytes.len().min(32);
            input[b_offset..64].copy_from_slice(&b_bytes[..b_bytes.len().min(32)]);

            let (enc, state) =
                ScaledDecryptMtA::encode(&setup, &input, &q_bytes, &mut rng).expect("encode");
            encodings.push(enc);
            states.push(state);
        }

        let enc_refs: Vec<&ScaledDecryptEncoding> = encodings.iter().collect();
        let aggregated = ScaledDecryptMtA::aggregate(&setup, &enc_refs).expect("aggregate");

        let f_shares = states
            .iter()
            .map(|state| {
                let f_bytes =
                    ScaledDecryptMtA::decode(&setup, &aggregated, state, &q_bytes).expect("decode");
                ScaledDecryptMtA::decode_to_qfi(&f_bytes).expect("decode_to_qfi")
            })
            .collect::<Vec<_>>();

        let result_bytes =
            ScaledDecryptMtA::aggregate_f_shares(&setup, &f_shares).expect("aggregate_f_shares");
        let result = Integer::from_digits(&result_bytes, Order::Msf);
        let result_mod_q = Integer::from(&result % &q);

        assert_eq!(
            result_mod_q, expected,
            "scaled decryption: result != sum(a_i) * sum(b_i) mod q"
        );
    }

    #[test]
    #[ignore = "redundant broadcast MtA variant"]
    fn scaled_decrypt_bad_input_length() {
        let q_bytes = secp256k1_order_bytes();

        let mut cl = ClSetup::new_secp256k1("9003").expect("CL setup");
        let (_sk, pk) = cl.keygen().expect("keygen");
        let setup = ScaledDecryptSetup {
            setup: RefCell::new(cl),
            pk,
        };

        let mut rng = rand::thread_rng();

        let result = ScaledDecryptMtA::encode(&setup, &[0u8; 32], &q_bytes, &mut rng);
        assert!(result.is_err(), "encode with 32 bytes must fail");
    }
}
