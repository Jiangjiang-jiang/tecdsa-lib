use std::marker::PhantomData;

use fast_paillier::{backend::Integer, DecryptionKey, EncryptionKey};
use rand_core::CryptoRngCore;
use sha2::Sha256;
use tecdsa_protocol::MtA;

pub trait PaillierMtaProofs: 'static {
    type ProofSetup: Clone;

    type SenderProof;

    type ReceiverProof;

    fn prove_sender(
        ek: &EncryptionKey,
        plaintext: &Integer,
        ciphertext: &Integer,
        nonce: &Integer,
        proof_setup: &Self::ProofSetup,
        q: &Integer,
        rng: &mut impl CryptoRngCore,
    ) -> Self::SenderProof;

    fn verify_sender(
        ek: &EncryptionKey,
        ciphertext: &Integer,
        proof: &Self::SenderProof,
        proof_setup: &Self::ProofSetup,
        q: &Integer,
    ) -> bool;

    #[allow(clippy::too_many_arguments)]
    fn prove_receiver(
        ek: &EncryptionKey,
        a: &Integer,
        alpha_prime: &Integer,
        c_a: &Integer,
        c_b: &Integer,
        nonce: &Integer,
        proof_setup: &Self::ProofSetup,
        q: &Integer,
        rng: &mut impl CryptoRngCore,
    ) -> Self::ReceiverProof;

    fn verify_receiver(
        ek: &EncryptionKey,
        c_a: &Integer,
        c_b: &Integer,
        proof: &Self::ReceiverProof,
        proof_setup: &Self::ProofSetup,
        q: &Integer,
    ) -> bool;
}

pub use crate::zk::pia_pib::{PiAProof, PiBProof};

pub struct SimpleProofs;

impl PaillierMtaProofs for SimpleProofs {
    type ProofSetup = ();
    type SenderProof = PiBProof;
    type ReceiverProof = PiAProof;

    fn prove_sender(
        ek: &EncryptionKey,
        plaintext: &Integer,
        ciphertext: &Integer,
        nonce: &Integer,
        _proof_setup: &Self::ProofSetup,
        q: &Integer,
        rng: &mut impl CryptoRngCore,
    ) -> Self::SenderProof {
        PiBProof::prove(ek, ciphertext, plaintext, nonce, q, rng)
    }

    fn verify_sender(
        ek: &EncryptionKey,
        ciphertext: &Integer,
        proof: &Self::SenderProof,
        _proof_setup: &Self::ProofSetup,
        q: &Integer,
    ) -> bool {
        proof.verify(ek, ciphertext, q)
    }

    fn prove_receiver(
        ek: &EncryptionKey,
        a: &Integer,
        alpha_prime: &Integer,
        c_a: &Integer,
        c_b: &Integer,
        nonce: &Integer,
        _proof_setup: &Self::ProofSetup,
        q: &Integer,
        rng: &mut impl CryptoRngCore,
    ) -> Self::ReceiverProof {
        PiAProof::prove(ek, c_b, c_a, a, alpha_prime, nonce, q, rng)
    }

    fn verify_receiver(
        ek: &EncryptionKey,
        c_a: &Integer,
        c_b: &Integer,
        proof: &Self::ReceiverProof,
        _proof_setup: &Self::ProofSetup,
        q: &Integer,
    ) -> bool {
        proof.verify(ek, c_b, c_a, q)
    }
}

use crate::zk::mta_range::{AliceProof, BobProof, NTildeParams};

#[derive(Clone)]
pub struct Gg18ProofSetup {
    pub ntilde: NTildeParams,
}

pub struct Gg18Proofs;

impl PaillierMtaProofs for Gg18Proofs {
    type ProofSetup = Gg18ProofSetup;
    type SenderProof = AliceProof;
    type ReceiverProof = BobProof;

    fn prove_sender(
        ek: &EncryptionKey,
        plaintext: &Integer,
        ciphertext: &Integer,
        nonce: &Integer,
        proof_setup: &Self::ProofSetup,
        _q: &Integer,
        rng: &mut impl CryptoRngCore,
    ) -> Self::SenderProof {
        AliceProof::prove::<k256::Secp256k1>(
            plaintext,
            ciphertext,
            ek.n(),
            ek.nn(),
            &proof_setup.ntilde,
            nonce,
            rng,
        )
    }

    fn verify_sender(
        ek: &EncryptionKey,
        ciphertext: &Integer,
        proof: &Self::SenderProof,
        proof_setup: &Self::ProofSetup,
        _q: &Integer,
    ) -> bool {
        proof
            .verify::<k256::Secp256k1>(ciphertext, ek.n(), ek.nn(), &proof_setup.ntilde)
            .is_ok()
    }

    fn prove_receiver(
        ek: &EncryptionKey,
        a: &Integer,
        alpha_prime: &Integer,
        c_a: &Integer,
        c_b: &Integer,
        nonce: &Integer,
        proof_setup: &Self::ProofSetup,
        _q: &Integer,
        rng: &mut impl CryptoRngCore,
    ) -> Self::ReceiverProof {
        let (proof, _) = BobProof::prove::<k256::Secp256k1>(
            c_a,
            c_b,
            a,
            alpha_prime,
            ek.n(),
            ek.nn(),
            &proof_setup.ntilde,
            nonce,
            false,
            rng,
        );
        proof
    }

    fn verify_receiver(
        ek: &EncryptionKey,
        c_a: &Integer,
        c_b: &Integer,
        proof: &Self::ReceiverProof,
        proof_setup: &Self::ProofSetup,
        _q: &Integer,
    ) -> bool {
        proof
            .verify::<k256::Secp256k1>(c_a, c_b, ek.n(), ek.nn(), &proof_setup.ntilde)
            .is_ok()
    }
}

use generic_ec::curves::Secp256k1 as GE;
use paillier_zk::{
    paillier_affine_operation_in_range as pi_aff, paillier_encryption_in_range as pi_enc,
    IntegerExt,
};

#[derive(Clone)]
pub struct Cggmp20ProofSetup {
    pub aux: pi_enc::Aux,

    pub sender_security: pi_enc::SecurityParams,

    pub receiver_security: pi_aff::SecurityParams,

    pub prover_ek: EncryptionKey,
}

pub type Cggmp20SenderProof = pi_enc::NiProof;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Cggmp20ReceiverProof {
    pub proof: pi_aff::NiProof<GE>,
    pub x: generic_ec::Point<GE>,
    pub y: fast_paillier::Ciphertext,
}

#[derive(udigest::Digestable)]
#[udigest(tag = "tecdsa.paillier.mta.cggmp20")]
struct Cggmp20MtaFsTag;

pub struct Cggmp20Proofs;

impl PaillierMtaProofs for Cggmp20Proofs {
    type ProofSetup = Cggmp20ProofSetup;
    type SenderProof = Cggmp20SenderProof;
    type ReceiverProof = Cggmp20ReceiverProof;

    fn prove_sender(
        ek: &EncryptionKey,
        plaintext: &Integer,
        ciphertext: &Integer,
        nonce: &Integer,
        proof_setup: &Self::ProofSetup,
        _q: &Integer,
        rng: &mut impl CryptoRngCore,
    ) -> Self::SenderProof {
        pi_enc::non_interactive::prove::<Sha256>(
            &Cggmp20MtaFsTag,
            &proof_setup.aux,
            pi_enc::Data {
                key: ek,
                ciphertext,
            },
            pi_enc::PrivateData { plaintext, nonce },
            &proof_setup.sender_security,
            rng,
        )
        .expect("pi_enc proof generation must succeed for valid inputs")
    }

    fn verify_sender(
        ek: &EncryptionKey,
        ciphertext: &Integer,
        proof: &Self::SenderProof,
        proof_setup: &Self::ProofSetup,
        _q: &Integer,
    ) -> bool {
        pi_enc::non_interactive::verify::<Sha256>(
            &Cggmp20MtaFsTag,
            &proof_setup.aux,
            pi_enc::Data {
                key: ek,
                ciphertext,
            },
            &proof_setup.sender_security,
            proof,
        )
        .is_ok()
    }

    fn prove_receiver(
        ek: &EncryptionKey,
        a: &Integer,
        alpha_prime: &Integer,
        c_a: &Integer,
        c_b: &Integer,
        nonce: &Integer,
        proof_setup: &Self::ProofSetup,
        _q: &Integer,
        rng: &mut impl CryptoRngCore,
    ) -> Self::ReceiverProof {
        let x_point = generic_ec::Point::<GE>::generator() * a.to_scalar::<GE>();

        let (y_ciphertext, nonce_y) = proof_setup
            .prover_ek
            .encrypt_with_random(rng, alpha_prime)
            .expect("encryption of alpha_prime under prover key must succeed");

        let proof = pi_aff::non_interactive::prove::<GE, Sha256>(
            &Cggmp20MtaFsTag,
            &proof_setup.aux,
            pi_aff::Data {
                key_j: ek,
                key_i: &proof_setup.prover_ek,
                c: c_a,
                d: c_b,
                y: &y_ciphertext,
                x: &x_point,
            },
            pi_aff::PrivateData {
                x: a,
                y: alpha_prime,
                nonce,
                nonce_y: &nonce_y,
            },
            &proof_setup.receiver_security,
            rng,
        )
        .expect("pi_aff proof generation must succeed for valid inputs");

        Cggmp20ReceiverProof {
            proof,
            x: x_point,
            y: y_ciphertext,
        }
    }

    fn verify_receiver(
        ek: &EncryptionKey,
        c_a: &Integer,
        c_b: &Integer,
        proof: &Self::ReceiverProof,
        proof_setup: &Self::ProofSetup,
        _q: &Integer,
    ) -> bool {
        pi_aff::non_interactive::verify::<GE, Sha256>(
            &Cggmp20MtaFsTag,
            &proof_setup.aux,
            pi_aff::Data {
                key_j: ek,
                key_i: &proof_setup.prover_ek,
                c: c_a,
                d: c_b,
                y: &proof.y,
                x: &proof.x,
            },
            &proof_setup.receiver_security,
            &proof.proof,
        )
        .is_ok()
    }
}

pub struct PaillierMtA<P: PaillierMtaProofs = SimpleProofs>(PhantomData<P>);

pub struct PaillierMtaSetup<P: PaillierMtaProofs = SimpleProofs> {
    pub ek: EncryptionKey,
    pub dk: DecryptionKey,
    pub proof_setup: P::ProofSetup,
}

impl<P: PaillierMtaProofs> Clone for PaillierMtaSetup<P> {
    fn clone(&self) -> Self {
        Self {
            ek: self.ek.clone(),
            dk: self.dk.clone(),
            proof_setup: self.proof_setup.clone(),
        }
    }
}

pub struct PaillierSenderState<P: PaillierMtaProofs = SimpleProofs> {
    pub nonce: Integer,
    pub ciphertext: Integer,
    _marker: PhantomData<P>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(bound(
    serialize = "P::SenderProof: serde::Serialize",
    deserialize = "P::SenderProof: serde::de::DeserializeOwned"
))]
pub struct PaillierSenderMsg<P: PaillierMtaProofs = SimpleProofs> {
    pub ciphertext: fast_paillier::Ciphertext,
    pub proof: P::SenderProof,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(bound(
    serialize = "P::ReceiverProof: serde::Serialize",
    deserialize = "P::ReceiverProof: serde::de::DeserializeOwned"
))]
pub struct PaillierReceiverMsg<P: PaillierMtaProofs = SimpleProofs> {
    pub ciphertext: fast_paillier::Ciphertext,
    pub proof: P::ReceiverProof,
}

#[derive(Debug, thiserror::Error)]
pub enum PaillierMtaError {
    #[error("Paillier error: {0}")]
    Paillier(String),

    #[error("sender proof verification failed")]
    SenderProofVerification,

    #[error("receiver proof verification failed")]
    ReceiverProofVerification,
}

impl PaillierMtaError {
    pub fn pib_verification() -> Self {
        Self::SenderProofVerification
    }

    pub fn pia_verification() -> Self {
        Self::ReceiverProofVerification
    }
}

impl<P: PaillierMtaProofs> MtA for PaillierMtA<P> {
    type Setup = PaillierMtaSetup<P>;
    type SenderState = PaillierSenderState<P>;
    type SenderMsg = PaillierSenderMsg<P>;
    type ReceiverMsg = PaillierReceiverMsg<P>;
    type Error = PaillierMtaError;

    fn sender_encrypt(
        setup: &Self::Setup,
        b_bytes: &[u8],
        q_bytes: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::SenderMsg, Self::SenderState), Self::Error> {
        let b = Integer::from_bytes_msf(b_bytes);
        let q = Integer::from_bytes_msf(q_bytes);

        let (ciphertext, nonce) = setup
            .ek
            .encrypt_with_random(rng, &b)
            .map_err(|e| PaillierMtaError::Paillier(format!("encryption of b failed: {e}")))?;

        let proof = P::prove_sender(
            &setup.ek,
            &b,
            &ciphertext,
            &nonce,
            &setup.proof_setup,
            &q,
            rng,
        );

        let state = PaillierSenderState {
            nonce,
            ciphertext: ciphertext.clone(),
            _marker: PhantomData,
        };
        let msg = PaillierSenderMsg { ciphertext, proof };

        Ok((msg, state))
    }

    fn receiver_compute(
        setup: &Self::Setup,
        a_bytes: &[u8],
        q_bytes: &[u8],
        sender_msg: &Self::SenderMsg,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::ReceiverMsg, Vec<u8>), Self::Error> {
        let a = Integer::from_bytes_msf(a_bytes);
        let q = Integer::from_bytes_msf(q_bytes);

        if !P::verify_sender(
            &setup.ek,
            &sender_msg.ciphertext,
            &sender_msg.proof,
            &setup.proof_setup,
            &q,
        ) {
            return Err(PaillierMtaError::SenderProofVerification);
        }

        let q_squared = &q * &q;
        let alpha_prime = q_squared.random_below_ref(rng);

        let c_scaled = setup.ek.omul(&a, &sender_msg.ciphertext).map_err(|e| {
            PaillierMtaError::Paillier(format!("homomorphic scalar mult failed: {e}"))
        })?;

        let (c_alpha, r_prime) = setup
            .ek
            .encrypt_with_random(rng, &alpha_prime)
            .map_err(|e| PaillierMtaError::Paillier(format!("encryption of alpha' failed: {e}")))?;

        let c_A = setup
            .ek
            .oadd(&c_scaled, &c_alpha)
            .map_err(|e| PaillierMtaError::Paillier(format!("homomorphic addition failed: {e}")))?;

        let proof = P::prove_receiver(
            &setup.ek,
            &a,
            &alpha_prime,
            &sender_msg.ciphertext,
            &c_A,
            &r_prime,
            &setup.proof_setup,
            &q,
            rng,
        );

        let alpha = (&q - &alpha_prime.modulo(&q)).modulo(&q);
        let alpha_bytes = alpha.to_bytes_msf();

        let msg = PaillierReceiverMsg {
            ciphertext: c_A,
            proof,
        };

        Ok((msg, alpha_bytes))
    }

    fn sender_decrypt(
        setup: &Self::Setup,
        state: &Self::SenderState,
        q_bytes: &[u8],
        receiver_msg: &Self::ReceiverMsg,
    ) -> Result<Vec<u8>, Self::Error> {
        let q = Integer::from_bytes_msf(q_bytes);

        if !P::verify_receiver(
            &setup.ek,
            &state.ciphertext,
            &receiver_msg.ciphertext,
            &receiver_msg.proof,
            &setup.proof_setup,
            &q,
        ) {
            return Err(PaillierMtaError::ReceiverProofVerification);
        }

        let plaintext = setup
            .dk
            .decrypt(&receiver_msg.ciphertext)
            .map_err(|e| PaillierMtaError::Paillier(format!("MtA decryption failed: {e}")))?;

        let beta = plaintext.modulo(&q);
        let beta_bytes = beta.to_bytes_msf();

        Ok(beta_bytes)
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::*;

    fn gen_paillier_keys(rng: &mut impl CryptoRngCore) -> (EncryptionKey, DecryptionKey) {
        let dk = crate::keygen(rng).expect("Paillier keygen failed");
        let ek = dk.encryption_key().clone();
        (ek, dk)
    }

    fn curve_order_int() -> Integer {
        use elliptic_curve::PrimeField;
        let neg_one = -k256::Scalar::ONE;
        let neg_one_bytes = neg_one.to_repr();
        let q_minus_1 = Integer::from_bytes_msf(neg_one_bytes.as_ref());
        &q_minus_1 + 1u8
    }

    #[test]
    #[ignore = "slow: redundant MtA/proof variant test"]
    fn pib_proof_honest_verifies() {
        let mut rng = OsRng;
        let (ek, _dk) = gen_paillier_keys(&mut rng);
        let q = curve_order_int();

        let b = q.random_below_ref(&mut rng);
        let (c_B, nonce) = ek
            .encrypt_with_random(&mut rng, &b)
            .expect("encryption should succeed");

        let proof = PiBProof::prove(&ek, &c_B, &b, &nonce, &q, &mut rng);
        assert!(proof.verify(&ek, &c_B, &q), "honest PiB proof must verify");
    }

    #[test]
    #[ignore = "slow: redundant MtA/proof variant test"]
    fn pib_proof_wrong_ciphertext_fails() {
        let mut rng = OsRng;
        let (ek, _dk) = gen_paillier_keys(&mut rng);
        let q = curve_order_int();

        let b = q.random_below_ref(&mut rng);
        let (c_B, nonce) = ek
            .encrypt_with_random(&mut rng, &b)
            .expect("encryption should succeed");

        let proof = PiBProof::prove(&ek, &c_B, &b, &nonce, &q, &mut rng);

        let b2 = q.random_below_ref(&mut rng);
        let (c_B2, _) = ek
            .encrypt_with_random(&mut rng, &b2)
            .expect("encryption should succeed");

        assert!(
            !proof.verify(&ek, &c_B2, &q),
            "PiB proof for wrong ciphertext must not verify"
        );
    }

    #[test]
    fn pia_proof_honest_verifies() {
        let mut rng = OsRng;
        let (ek, _dk) = gen_paillier_keys(&mut rng);
        let q = curve_order_int();
        let K = &q * &q * &Integer::u_pow_u(2, 416);

        let k2 = q.random_below_ref(&mut rng);
        let (c_B, _) = ek
            .encrypt_with_random(&mut rng, &k2)
            .expect("encryption should succeed");

        let a = q.random_below_ref(&mut rng);
        let alpha_prime = K.random_below_ref(&mut rng);

        let c_B_a = ek.omul(&a, &c_B).expect("omul");
        let (c_alpha, r_prime) = ek.encrypt_with_random(&mut rng, &alpha_prime).expect("enc");
        let c_A = ek.oadd(&c_B_a, &c_alpha).expect("oadd");

        let proof = PiAProof::prove(&ek, &c_A, &c_B, &a, &alpha_prime, &r_prime, &q, &mut rng);
        assert!(
            proof.verify(&ek, &c_A, &c_B, &q),
            "honest PiA proof must verify"
        );
    }

    #[test]
    fn mta_trait_correctness() {
        let mut rng = OsRng;
        let (ek, dk) = gen_paillier_keys(&mut rng);
        let q = curve_order_int();
        let q_bytes = q.to_bytes_msf();

        let setup: PaillierMtaSetup<SimpleProofs> = PaillierMtaSetup {
            ek,
            dk,
            proof_setup: (),
        };

        let b = q.random_below_ref(&mut rng);
        let b_bytes = b.to_bytes_msf();

        let a = q.random_below_ref(&mut rng);
        let a_bytes = a.to_bytes_msf();

        let (sender_msg, sender_state) =
            PaillierMtA::sender_encrypt(&setup, &b_bytes, &q_bytes, &mut rng)
                .expect("sender_encrypt should succeed");

        let (receiver_msg, alpha_bytes) =
            PaillierMtA::receiver_compute(&setup, &a_bytes, &q_bytes, &sender_msg, &mut rng)
                .expect("receiver_compute should succeed");

        let beta_bytes =
            PaillierMtA::sender_decrypt(&setup, &sender_state, &q_bytes, &receiver_msg)
                .expect("sender_decrypt should succeed");

        let alpha = Integer::from_bytes_msf(&alpha_bytes);
        let beta = Integer::from_bytes_msf(&beta_bytes);
        let sum = (&alpha + &beta).modulo(&q);
        let expected = (&a * &b).modulo(&q);

        assert_eq!(sum, expected, "alpha + beta must equal a * b mod q");
    }

    #[test]
    #[ignore = "slow: redundant MtA/proof variant test"]
    fn mta_trait_multiple_runs() {
        let mut rng = OsRng;
        let (ek, dk) = gen_paillier_keys(&mut rng);
        let q = curve_order_int();
        let q_bytes = q.to_bytes_msf();

        let setup: PaillierMtaSetup<SimpleProofs> = PaillierMtaSetup {
            ek,
            dk,
            proof_setup: (),
        };

        for _ in 0..3 {
            let b = q.random_below_ref(&mut rng);
            let a = q.random_below_ref(&mut rng);

            let (sender_msg, sender_state) =
                PaillierMtA::sender_encrypt(&setup, &b.to_bytes_msf(), &q_bytes, &mut rng)
                    .expect("sender_encrypt");

            let (receiver_msg, alpha_bytes) = PaillierMtA::receiver_compute(
                &setup,
                &a.to_bytes_msf(),
                &q_bytes,
                &sender_msg,
                &mut rng,
            )
            .expect("receiver_compute");

            let beta_bytes =
                PaillierMtA::sender_decrypt(&setup, &sender_state, &q_bytes, &receiver_msg)
                    .expect("sender_decrypt");

            let alpha = Integer::from_bytes_msf(&alpha_bytes);
            let beta = Integer::from_bytes_msf(&beta_bytes);
            let sum = (&alpha + &beta).modulo(&q);
            let expected = (&a * &b).modulo(&q);

            assert_eq!(sum, expected, "MtA correctness must hold in all runs");
        }
    }

    #[test]
    #[ignore = "slow: redundant MtA/proof variant test"]
    fn mta_gg18_proofs_correctness() {
        use crate::zk::{mta_range::NTildeParams, pdl_slack::sample_below};

        let mut rng = OsRng;

        let (ek, dk) = gen_paillier_keys(&mut rng);

        let p2 = Integer::generate_safe_prime(&mut rng, 256);
        let q2 = Integer::generate_safe_prime(&mut rng, 256);
        let n_tilde = &p2 * &q2;
        let h1 = Integer::sample_in_mult_group_of(&mut rng, &n_tilde);
        let phi_n = (&p2 - Integer::one()) * (&q2 - Integer::one());
        let lambda = sample_below(&phi_n, &mut rng);
        let h2 = h1.pow_mod_ref(&lambda, &n_tilde).expect("pow_mod defined");
        let ntilde = NTildeParams {
            N_tilde: n_tilde,
            h1,
            h2,
        };

        let q = curve_order_int();
        let q_bytes = q.to_bytes_msf();

        let proof_setup = Gg18ProofSetup { ntilde };

        let setup: PaillierMtaSetup<Gg18Proofs> = PaillierMtaSetup {
            ek,
            dk,
            proof_setup,
        };

        let b = q.random_below_ref(&mut rng);
        let a = q.random_below_ref(&mut rng);

        let (sender_msg, sender_state) = PaillierMtA::<Gg18Proofs>::sender_encrypt(
            &setup,
            &b.to_bytes_msf(),
            &q_bytes,
            &mut rng,
        )
        .expect("sender_encrypt");

        let (receiver_msg, alpha_bytes) = PaillierMtA::<Gg18Proofs>::receiver_compute(
            &setup,
            &a.to_bytes_msf(),
            &q_bytes,
            &sender_msg,
            &mut rng,
        )
        .expect("receiver_compute");

        let beta_bytes = PaillierMtA::<Gg18Proofs>::sender_decrypt(
            &setup,
            &sender_state,
            &q_bytes,
            &receiver_msg,
        )
        .expect("sender_decrypt");

        let alpha = Integer::from_bytes_msf(&alpha_bytes);
        let beta = Integer::from_bytes_msf(&beta_bytes);
        let sum = (&alpha + &beta).modulo(&q);
        let expected = (&a * &b).modulo(&q);

        assert_eq!(
            sum, expected,
            "GG18 MtA: alpha + beta must equal a * b mod q"
        );
    }

    #[test]
    #[ignore = "slow: redundant MtA/proof variant test"]
    fn mta_cggmp20_proofs_correctness() {
        let mut rng = OsRng;

        let (ek, dk) = gen_paillier_keys(&mut rng);

        let q = curve_order_int();
        let q_bytes = q.to_bytes_msf();

        let aux = {
            let p = generate_blum_prime(&mut rng, 1024);
            let q_rp = generate_blum_prime(&mut rng, 1024);
            let n = &p * &q_rp;
            let phi_n = (&p - Integer::one()) * (&q_rp - Integer::one());
            let r = Integer::sample_in_mult_group_of(&mut rng, &n);
            let lambda = phi_n.random_below(&mut rng);
            let t = r.square().modulo(&n);
            let s = t.pow_mod_ref(&lambda, &n).expect("pow_mod must succeed");
            pi_enc::Aux {
                s,
                t,
                rsa_modulo: n,
                multiexp: None,
                crt: None,
            }
        };

        let sender_security = pi_enc::SecurityParams {
            l: 256,
            epsilon: 512,
            q: q.clone(),
        };
        let receiver_security = pi_aff::SecurityParams {
            l_x: 256,
            l_y: 1280,
            epsilon: 512,
        };

        let proof_setup = Cggmp20ProofSetup {
            aux,
            sender_security,
            receiver_security,
            prover_ek: ek.clone(),
        };

        let setup: PaillierMtaSetup<Cggmp20Proofs> = PaillierMtaSetup {
            ek,
            dk,
            proof_setup,
        };

        let b = q.random_below_ref(&mut rng);
        let a = q.random_below_ref(&mut rng);

        let (sender_msg, sender_state) = PaillierMtA::<Cggmp20Proofs>::sender_encrypt(
            &setup,
            &b.to_bytes_msf(),
            &q_bytes,
            &mut rng,
        )
        .expect("sender_encrypt");

        let (receiver_msg, alpha_bytes) = PaillierMtA::<Cggmp20Proofs>::receiver_compute(
            &setup,
            &a.to_bytes_msf(),
            &q_bytes,
            &sender_msg,
            &mut rng,
        )
        .expect("receiver_compute");

        let beta_bytes = PaillierMtA::<Cggmp20Proofs>::sender_decrypt(
            &setup,
            &sender_state,
            &q_bytes,
            &receiver_msg,
        )
        .expect("sender_decrypt");

        let alpha = Integer::from_bytes_msf(&alpha_bytes);
        let beta = Integer::from_bytes_msf(&beta_bytes);
        let sum = (&alpha + &beta).modulo(&q);
        let expected = (&a * &b).modulo(&q);

        assert_eq!(
            sum, expected,
            "CGGMP20 MtA: alpha + beta must equal a * b mod q"
        );
    }

    fn generate_blum_prime(rng: &mut impl CryptoRngCore, bits: u32) -> Integer {
        loop {
            let p = Integer::generate_prime(rng, bits);
            if p.mod_u(4) == 3 {
                return p;
            }
        }
    }
}
