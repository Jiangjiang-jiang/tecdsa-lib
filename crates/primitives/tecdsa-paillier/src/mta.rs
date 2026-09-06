// SPDX-License-Identifier: MIT OR Apache-2.0
//! Paillier-based MtA (Multiplicative-to-Additive) sub-protocol.
//!
//! Implements `tecdsa_protocol::MtA` using Paillier homomorphic encryption,
//! parameterized over the ZK proof system via the `PaillierMtaProofs` trait.
//!
//! Two proof system variants are provided:
//!
//! - **`SimpleProofs`** (default): Uses PiB/PiA proofs from XAL+21 (Appendix C.2,
//!   Figure 4). No extra setup beyond Paillier keys.
//!
//! - **`Gg18Proofs`**: Uses AliceProof/BobProofExt from GG18 (Appendix A of
//!   <https://eprint.iacr.org/2019/114.pdf>), requiring Ring-Pedersen N-tilde
//!   auxiliary parameters.
//!
//! ## Default type parameter
//!
//! `PaillierMtA` defaults to `SimpleProofs`, so `PaillierMtA` (without type
//! parameter) is backwards-compatible with the original implementation.
//!
//! ## Security parameters (SimpleProofs only)
//!
//! - `tau = 256` (curve order bits for secp256k1)
//! - `kappa = 80` (statistical security parameter)
//! - `K = q^2 * 2^{tau + 2*kappa}` (range for alpha')

use std::marker::PhantomData;

use fast_paillier::{
    backend::{BigIntExt, Integer},
    DecryptionKey, EncryptionKey,
};
use rand_core::CryptoRngCore;
use rug::Complete;
use sha2::Sha256;
use tecdsa_protocol::MtA;

// ---------------------------------------------------------------------------
// PaillierMtaProofs trait: abstracts over the ZK proof system
// ---------------------------------------------------------------------------

/// Trait abstracting the ZK proof system used with Paillier MtA.
///
/// Different protocols use different proof systems for the same underlying
/// Paillier MtA computation. For example:
/// - XAL+21 uses PiB/PiA (simple range proofs, no auxiliary parameters)
/// - GG18 uses AliceProof/BobProofExt (Ring-Pedersen range proofs with N-tilde)
pub trait PaillierMtaProofs: 'static {
    /// Extra setup data beyond Paillier keys (e.g., Ring-Pedersen params).
    type ProofSetup: Clone;

    /// Proof accompanying the sender's ciphertext.
    type SenderProof;

    /// Proof accompanying the receiver's affine computation.
    type ReceiverProof;

    /// Generate a proof for the sender's ciphertext.
    ///
    /// Proves: `ciphertext = Enc(ek, plaintext; nonce)` with range bound.
    fn prove_sender(
        ek: &EncryptionKey,
        plaintext: &Integer,
        ciphertext: &Integer,
        nonce: &Integer,
        proof_setup: &Self::ProofSetup,
        q: &Integer,
        rng: &mut impl CryptoRngCore,
    ) -> Self::SenderProof;

    /// Verify the sender's proof.
    fn verify_sender(
        ek: &EncryptionKey,
        ciphertext: &Integer,
        proof: &Self::SenderProof,
        proof_setup: &Self::ProofSetup,
        q: &Integer,
    ) -> bool;

    /// Generate a proof for the receiver's affine computation.
    ///
    /// Proves: `c_b = c_a^a * Enc(ek, alpha_prime; nonce)` with range bounds.
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

    /// Verify the receiver's proof.
    fn verify_receiver(
        ek: &EncryptionKey,
        c_a: &Integer,
        c_b: &Integer,
        proof: &Self::ReceiverProof,
        proof_setup: &Self::ProofSetup,
        q: &Integer,
    ) -> bool;
}

// ---------------------------------------------------------------------------
// PiB / PiA re-exports from zk::pia_pib
// ---------------------------------------------------------------------------

pub use crate::zk::pia_pib::{PiAProof, PiBProof};

// ---------------------------------------------------------------------------
// SimpleProofs: default PiB/PiA proof system (XAL+21)
// ---------------------------------------------------------------------------

/// Default proof system using PiB/PiA from XAL+21.
///
/// No extra setup is needed beyond the Paillier keys themselves.
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

// ---------------------------------------------------------------------------
// Gg18Proofs: GG18-specific proof system with Ring-Pedersen N-tilde params
// ---------------------------------------------------------------------------

use crate::zk::mta_range::{AliceProof, BobProof, NTildeParams};

/// GG18 proof setup: the Ring-Pedersen auxiliary parameters to use for
/// proof generation and verification.
///
/// In GG18, each Alice-Bob pair uses a specific set of N-tilde parameters.
/// The caller is responsible for constructing the setup with the correct
/// N-tilde for each proof direction:
///
/// - For Alice's range proof: use the VERIFIER's (Bob's) N-tilde params
/// - For Bob's range proof: use the VERIFIER's (Alice's) N-tilde params
///
/// Since `prove_*` and `verify_*` use the same N-tilde, both sides of a
/// given proof must construct `Gg18ProofSetup` with the same `ntilde`.
#[derive(Clone)]
pub struct Gg18ProofSetup {
    /// Ring-Pedersen auxiliary parameters $(N', h_1, h_2)$.
    pub ntilde: NTildeParams,
}

/// GG18-specific proof system using AliceProof/BobProof from GG18.
///
/// Uses Ring-Pedersen commitments with auxiliary N-tilde parameters for
/// range proofs with stronger security properties than SimpleProofs.
///
/// Note: This uses `BobProof` (without EC check) as the `ReceiverProof`.
/// The `BobProofExt` variant (with EC DLog check on `g_gamma_j`) requires
/// additional data not available during the MtA computation and must be
/// handled at the protocol level.
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
            false, // no EC check for basic BobProof
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

// ---------------------------------------------------------------------------
// Cggmp20Proofs: CGGMP20-specific proof system with pi_enc + pi_aff-g
// ---------------------------------------------------------------------------

use generic_ec::curves::Secp256k1 as GE;
use paillier_zk::{
    paillier_affine_operation_in_range as pi_aff, paillier_encryption_in_range as pi_enc,
    IntegerExt,
};

/// CGGMP20 proof setup: Ring-Pedersen auxiliary parameters, security
/// parameters, and the prover's own Paillier key.
///
/// In CGGMP20's presign protocol, two ZK proofs accompany each MtA:
///
/// - **Sender (pi_enc)**: proves that `K = Enc(ek, k; rho)` with `|k| <= 2^l`.
///   This is a simplification of the full `pi_enc_elg` used by the protocol,
///   which additionally ties the ciphertext to an El-Gamal commitment. The
///   El-Gamal binding is protocol-level data that cannot flow through the MtA
///   trait; the protocol layer must verify `pi_enc_elg` separately.
///
/// - **Receiver (pi_aff-g)**: proves the affine homomorphic computation
///   `D = C^x * Enc(key_j, y; rho) ` was performed correctly, with `|x| <= 2^l`
///   and `|y| <= 2^l'`, and that `X = x*G` is the EC commitment to the scalar.
///
/// ## What CANNOT fit through the `PaillierMtaProofs` trait
///
/// The full CGGMP20 presign protocol uses three additional proofs:
/// 1. `pi_enc_elg` (encryption-in-range with El-Gamal) for the sender --
///    requires El-Gamal commitment pairs `(Y, a, b)` from protocol-level state.
/// 2. `pi_elog` (DLog with El-Gamal commitment) for `Gamma_i` and `Delta_i` --
///    entirely protocol-level, not MtA-related.
/// 3. The `pi_aff-g` verifier uses the **verifier's** Ring-Pedersen `Aux` and
///    the prover's EC public key. In the full protocol these are managed
///    per-pair; through this trait, a single `ProofSetup` is used for both
///    prove and verify.
///
/// Protocol code that uses full CGGMP20 security should verify `pi_enc_elg`
/// and `pi_elog` inline (as `tecdsa-cggmp20` already does) and use this
/// `Cggmp20Proofs` variant only for the MtA-specific proofs.
#[derive(Clone)]
pub struct Cggmp20ProofSetup {
    /// Ring-Pedersen auxiliary parameters `(s, t, N^)` of the **verifier**.
    ///
    /// For `prove_sender`/`prove_receiver`: use the peer's (verifier's) Aux.
    /// For `verify_sender`/`verify_receiver`: use your own (verifier's) Aux.
    pub aux: pi_enc::Aux,

    /// Security parameter for the sender proof (`pi_enc`): bit-length bound
    /// on the plaintext.
    pub sender_security: pi_enc::SecurityParams,

    /// Security parameters for the receiver proof (`pi_aff-g`): bit-length
    /// bounds on the multiplicative scalar (`l_x`) and additive mask (`l_y`).
    pub receiver_security: pi_aff::SecurityParams,

    /// The prover's own Paillier encryption key.
    ///
    /// In `pi_aff-g`, the proof references two Paillier keys:
    /// - `key_j` (the key that encrypted the input ciphertext `C`) -- this is
    ///   the `ek` parameter passed to the trait methods.
    /// - `key_i` (the prover's own key, used to encrypt `Y = Enc(key_i, y)`)
    ///   -- this is stored here.
    ///
    /// When verifying, this field should be set to the **prover's** encryption
    /// key (the party whose proof you are checking).
    pub prover_ek: EncryptionKey,
}

/// CGGMP20 sender proof: non-interactive `pi_enc` (Paillier encryption in range).
///
/// This is a simplified version of what CGGMP20 actually sends. The full
/// protocol uses `pi_enc_elg` which additionally binds the ciphertext to
/// an El-Gamal commitment. That binding requires protocol-level data
/// (El-Gamal base points Y, a, b) not available at the MtA layer.
pub type Cggmp20SenderProof = pi_enc::NiProof;

/// CGGMP20 receiver proof: the non-interactive `pi_aff-g` proof bundled with
/// the public statement data it is checked against.
///
/// `pi_aff-g`'s verifier needs the EC commitment `X = a*G` and the ciphertext
/// `Y = Enc(key_i, alpha')`; neither is recoverable from the `NiProof` alone,
/// so the receiver transmits them alongside the proof. (In the full CGGMP20
/// presign these public values are already broadcast for other reasons.)
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Cggmp20ReceiverProof {
    /// The `pi_aff-g` non-interactive proof.
    pub proof: pi_aff::NiProof<GE>,
    /// EC commitment `X = a * G` (public input to `pi_aff-g`).
    pub x: generic_ec::Point<GE>,
    /// Ciphertext `Y = Enc(key_i, alpha')` under the prover's own key.
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub y: fast_paillier::Ciphertext,
}

/// Fiat-Shamir domain separator for CGGMP20 MtA proofs generated through the
/// PaillierMtaProofs trait. Uses a fixed tag so that proofs are deterministic
/// given the same inputs.
#[derive(udigest::Digestable)]
#[udigest(tag = "tecdsa.paillier.mta.cggmp20")]
struct Cggmp20MtaFsTag;

/// CGGMP20-specific proof system using `pi_enc` (sender) and `pi_aff-g`
/// (receiver) from the `paillier-zk` crate.
///
/// This variant captures the essential MtA ZK proofs from CGGMP20:
/// - Range proof on the sender's encrypted value
/// - Affine-operation range proof with EC commitment on the receiver's
///   computation
///
/// See [`Cggmp20ProofSetup`] for details on what the full CGGMP20 protocol
/// checks beyond what this trait provides.
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

    /// Generate a receiver proof (`pi_aff-g`) for the affine MtA computation.
    ///
    /// Internally computes:
    /// - `X = a * G` (EC commitment to the scalar)
    /// - `Y = Enc(prover_ek, alpha_prime; nonce_y)` (encryption of additive
    ///   mask under prover's own key)
    ///
    /// The proof demonstrates that `c_b = c_a^a * Enc(ek, alpha_prime; nonce)`
    /// was computed correctly, with `a` and `alpha_prime` in the specified
    /// ranges, and that `X` is consistent with `a`.
    ///
    /// Note: `nonce` here is the nonce used in `Enc(ek, alpha_prime)` under
    /// the **verifier's** key (i.e., the key that encrypted `c_a`). The proof
    /// also needs a separate encryption of `alpha_prime` under the prover's own
    /// key (`prover_ek` from the setup). This second encryption and its nonce
    /// are generated internally.
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
        // Compute EC commitment: X = a * G
        let x_point = generic_ec::Point::<GE>::generator() * a.to_scalar::<GE>();

        // Encrypt alpha_prime under the prover's own key to get Y
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

        // Bundle X and Y so the sender can verify the proof.
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
        // The EC commitment `X` and ciphertext `Y` travel inside the bundled
        // `Cggmp20ReceiverProof`, so the full pi_aff-g statement can be
        // reconstructed and verified here: `c_a = c_B` (the input), `c_b = c_A`
        // (the affine result), `Y = proof.y`, `X = proof.x`.
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

// ---------------------------------------------------------------------------
// PaillierMtA: MtA trait implementation, generic over proof system
// ---------------------------------------------------------------------------

/// Paillier-based MtA backend, generic over the ZK proof system.
///
/// Uses Paillier homomorphic encryption with configurable zero-knowledge proofs.
///
/// Defaults to `SimpleProofs` (XAL+21 PiB/PiA) for backwards compatibility.
/// Use `PaillierMtA<Gg18Proofs>` for GG18's AliceProof/BobProof system.
pub struct PaillierMtA<P: PaillierMtaProofs = SimpleProofs>(PhantomData<P>);

/// Setup material for Paillier MtA: Paillier keys plus proof-system-specific
/// parameters.
///
/// Defaults to `SimpleProofs` where `ProofSetup = ()`.
pub struct PaillierMtaSetup<P: PaillierMtaProofs = SimpleProofs> {
    /// Paillier encryption key (public).
    pub ek: EncryptionKey,
    /// Paillier decryption key (secret, owned by the sender).
    pub dk: DecryptionKey,
    /// Proof-system-specific setup data.
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

/// Sender's internal state between encrypt and decrypt.
pub struct PaillierSenderState<P: PaillierMtaProofs = SimpleProofs> {
    /// The nonce used to encrypt the sender's input.
    pub nonce: Integer,
    /// The sender's own ciphertext `c_B = Enc(pk, b)`, retained so that
    /// `sender_decrypt` can verify the receiver's proof (which is stated over
    /// `c_B` and the affine result `c_A`).
    pub ciphertext: Integer,
    _marker: PhantomData<P>,
}

/// Message from sender (P2) to receiver (P1): encrypted input + proof.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(bound(
    serialize = "P::SenderProof: serde::Serialize",
    deserialize = "P::SenderProof: serde::de::DeserializeOwned"
))]
pub struct PaillierSenderMsg<P: PaillierMtaProofs = SimpleProofs> {
    /// `c_B = Enc(pk, b; r)`: Paillier ciphertext of the sender's input.
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub ciphertext: fast_paillier::Ciphertext,
    /// Proof accompanying the sender's ciphertext.
    pub proof: P::SenderProof,
}

/// Message from receiver (P1) to sender (P2): affine result + proof.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(bound(
    serialize = "P::ReceiverProof: serde::Serialize",
    deserialize = "P::ReceiverProof: serde::de::DeserializeOwned"
))]
pub struct PaillierReceiverMsg<P: PaillierMtaProofs = SimpleProofs> {
    /// `c_A = c_B^a * Enc(pk, alpha'; r')`: the affine ciphertext.
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub ciphertext: fast_paillier::Ciphertext,
    /// Proof accompanying the receiver's affine computation.
    pub proof: P::ReceiverProof,
}

/// Error type for the Paillier MtA backend.
#[derive(Debug, thiserror::Error)]
pub enum PaillierMtaError {
    /// Paillier encryption/decryption error.
    #[error("Paillier error: {0}")]
    Paillier(String),

    /// Sender proof (PiB / AliceProof) verification failed.
    #[error("sender proof verification failed")]
    SenderProofVerification,

    /// Receiver proof (PiA / BobProof) verification failed.
    #[error("receiver proof verification failed")]
    ReceiverProofVerification,
}

// Keep old error variant names available for backwards compatibility.
impl PaillierMtaError {
    /// Alias for `SenderProofVerification` (backwards compat with PiB name).
    pub fn pib_verification() -> Self {
        Self::SenderProofVerification
    }

    /// Alias for `ReceiverProofVerification` (backwards compat with PiA name).
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

    /// Step 1: Sender (P2) encrypts input `b` and generates a sender proof.
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

    /// Step 2: Receiver (P1) verifies sender proof, performs homomorphic affine
    /// operation, generates receiver proof, and obtains `alpha`.
    ///
    /// Computes:
    ///   `c_A = c_B^a * Enc(pk, alpha'; r')`
    ///   `alpha = -alpha' mod q`
    fn receiver_compute(
        setup: &Self::Setup,
        a_bytes: &[u8],
        q_bytes: &[u8],
        sender_msg: &Self::SenderMsg,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::ReceiverMsg, Vec<u8>), Self::Error> {
        let a = Integer::from_bytes_msf(a_bytes);
        let q = Integer::from_bytes_msf(q_bytes);

        // 1. Verify sender proof
        if !P::verify_sender(
            &setup.ek,
            &sender_msg.ciphertext,
            &sender_msg.proof,
            &setup.proof_setup,
            &q,
        ) {
            return Err(PaillierMtaError::SenderProofVerification);
        }

        // 2. Sample alpha' from Z_{q^2} for masking
        let q_squared = (&q * &q).complete();
        let alpha_prime = q_squared.sample_below_ref(rng);

        // 3. Homomorphic computation:
        //    c_scaled = c_B^a = Enc(pk, a * b)
        //    c_alpha = Enc(pk, alpha'; r')
        //    c_A = c_scaled (+) c_alpha = Enc(pk, a * b + alpha')
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

        // 4. Generate receiver proof
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

        // 5. alpha = -alpha' mod q
        let alpha = (&q - alpha_prime.modulo(&q)).modulo(&q);
        let alpha_bytes = alpha.to_bytes_msf();

        let msg = PaillierReceiverMsg {
            ciphertext: c_A,
            proof,
        };

        Ok((msg, alpha_bytes))
    }

    /// Step 3: Sender (P2) verifies receiver proof and decrypts to obtain `beta`.
    ///
    /// `beta = Dec(dk, c_A) mod q = (a * b + alpha') mod q`
    fn sender_decrypt(
        setup: &Self::Setup,
        state: &Self::SenderState,
        q_bytes: &[u8],
        receiver_msg: &Self::ReceiverMsg,
    ) -> Result<Vec<u8>, Self::Error> {
        let q = Integer::from_bytes_msf(q_bytes);

        // 1. Verify the receiver's proof (GG18 Bob / CGGMP20 pi_aff-g) before
        //    decrypting. The proof is stated over `c_B` (the sender's own
        //    ciphertext, retained in state) and `c_A` (the affine result), so
        //    the sender can verify it without any extra protocol-level data.
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

        // 2. Decrypt
        let plaintext = setup
            .dk
            .decrypt(&receiver_msg.ciphertext)
            .map_err(|e| PaillierMtaError::Paillier(format!("MtA decryption failed: {e}")))?;

        // 3. Reduce mod q
        let beta = plaintext.modulo(&q);
        let beta_bytes = beta.to_bytes_msf();

        Ok(beta_bytes)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::*;

    /// Helper: generate a Paillier key pair and return (ek, dk).
    fn gen_paillier_keys(rng: &mut impl CryptoRngCore) -> (EncryptionKey, DecryptionKey) {
        let dk = crate::keygen(rng).expect("Paillier keygen failed");
        let ek = dk.encryption_key().clone();
        (ek, dk)
    }

    /// Helper: compute curve order q as a big integer.
    fn curve_order_int() -> Integer {
        tecdsa_curve::conv::curve_order::<k256::Secp256k1>()
    }

    #[test]
    #[ignore = "slow: redundant MtA/proof variant test"]
    fn pib_proof_honest_verifies() {
        let mut rng = OsRng;
        let (ek, _dk) = gen_paillier_keys(&mut rng);
        let q = curve_order_int();

        let b = q.sample_below_ref(&mut rng);
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

        let b = q.sample_below_ref(&mut rng);
        let (c_B, nonce) = ek
            .encrypt_with_random(&mut rng, &b)
            .expect("encryption should succeed");

        let proof = PiBProof::prove(&ek, &c_B, &b, &nonce, &q, &mut rng);

        let b2 = q.sample_below_ref(&mut rng);
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
        // K = q^2 * 2^{tau + 2*kappa} = q^2 * 2^{256 + 2*80} = q^2 * 2^{416}
        let K = Integer::two_pow(416) * &q * &q;

        let k2 = q.sample_below_ref(&mut rng);
        let (c_B, _) = ek
            .encrypt_with_random(&mut rng, &k2)
            .expect("encryption should succeed");

        let a = q.sample_below_ref(&mut rng);
        let alpha_prime = K.sample_below_ref(&mut rng);

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

        // Sender's input b
        let b = q.sample_below_ref(&mut rng);
        let b_bytes = b.to_bytes_msf();

        // Receiver's input a
        let a = q.sample_below_ref(&mut rng);
        let a_bytes = a.to_bytes_msf();

        // Step 1: Sender encrypts
        let (sender_msg, sender_state) =
            PaillierMtA::sender_encrypt(&setup, &b_bytes, &q_bytes, &mut rng)
                .expect("sender_encrypt should succeed");

        // Step 2: Receiver computes
        let (receiver_msg, alpha_bytes) =
            PaillierMtA::receiver_compute(&setup, &a_bytes, &q_bytes, &sender_msg, &mut rng)
                .expect("receiver_compute should succeed");

        // Step 3: Sender decrypts
        let beta_bytes =
            PaillierMtA::sender_decrypt(&setup, &sender_state, &q_bytes, &receiver_msg)
                .expect("sender_decrypt should succeed");

        // Verify: alpha + beta = a * b mod q
        let alpha = Integer::from_bytes_msf(&alpha_bytes);
        let beta = Integer::from_bytes_msf(&beta_bytes);
        let sum = (alpha + beta).modulo(&q);
        let expected = (a * b).modulo(&q);

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
            let b = q.sample_below_ref(&mut rng);
            let a = q.sample_below_ref(&mut rng);

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
            let sum = (alpha + beta).modulo(&q);
            let expected = (a * b).modulo(&q);

            assert_eq!(sum, expected, "MtA correctness must hold in all runs");
        }
    }

    #[test]
    #[ignore = "slow: redundant MtA/proof variant test"]
    fn mta_gg18_proofs_correctness() {
        use crate::zk::mta_range::NTildeParams;

        let mut rng = OsRng;

        // Generate Paillier keys (full-size for MtA correctness)
        let (ek, dk) = gen_paillier_keys(&mut rng);

        // Generate N-tilde params (can use smaller primes since these
        // are only commitment parameters, not encryption keys)
        let p2 = Integer::generate_safe_prime(&mut rng, 256);
        let q2 = Integer::generate_safe_prime(&mut rng, 256);
        let n_tilde = (&p2 * &q2).complete();
        let h1 = Integer::sample_in_mult_group_of(&mut rng, &n_tilde);
        let phi_n = (p2 - Integer::one()) * (q2 - Integer::one());
        let lambda = phi_n.sample_below_ref(&mut rng);
        let h2 = h1
            .pow_mod_ref(&lambda, &n_tilde)
            .expect("pow_mod defined")
            .complete();
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

        let b = q.sample_below_ref(&mut rng);
        let a = q.sample_below_ref(&mut rng);

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
        let sum = (alpha + beta).modulo(&q);
        let expected = (a * b).modulo(&q);

        assert_eq!(
            sum, expected,
            "GG18 MtA: alpha + beta must equal a * b mod q"
        );
    }

    #[test]
    #[ignore = "slow: redundant MtA/proof variant test"]
    fn mta_cggmp20_proofs_correctness() {
        let mut rng = OsRng;

        // Generate Paillier keys (full-size for MtA correctness)
        let (ek, dk) = gen_paillier_keys(&mut rng);

        let q = curve_order_int();
        let q_bytes = q.to_bytes_msf();

        // Generate Ring-Pedersen Aux parameters for pi_enc / pi_aff-g proofs.
        // Use Blum primes (p = 3 mod 4) for the RSA modulus, matching
        // paillier-zk's test conventions.
        let aux = {
            let p = generate_blum_prime(&mut rng, 1024);
            let q_rp = generate_blum_prime(&mut rng, 1024);
            let phi_n = (&p - Integer::one()) * (&q_rp - Integer::one());
            let n = p * q_rp;
            let r = Integer::sample_in_mult_group_of(&mut rng, &n);
            let lambda = phi_n.sample_below(&mut rng);
            let t = r.square().modulo(&n);
            let s = t
                .pow_mod_ref(&lambda, &n)
                .expect("pow_mod must succeed")
                .complete();
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

        let b = q.sample_below_ref(&mut rng);
        let a = q.sample_below_ref(&mut rng);

        // Step 1: Sender encrypts
        let (sender_msg, sender_state) = PaillierMtA::<Cggmp20Proofs>::sender_encrypt(
            &setup,
            &b.to_bytes_msf(),
            &q_bytes,
            &mut rng,
        )
        .expect("sender_encrypt");

        // Step 2: Receiver computes
        let (receiver_msg, alpha_bytes) = PaillierMtA::<Cggmp20Proofs>::receiver_compute(
            &setup,
            &a.to_bytes_msf(),
            &q_bytes,
            &sender_msg,
            &mut rng,
        )
        .expect("receiver_compute");

        // Step 3: Sender decrypts
        let beta_bytes = PaillierMtA::<Cggmp20Proofs>::sender_decrypt(
            &setup,
            &sender_state,
            &q_bytes,
            &receiver_msg,
        )
        .expect("sender_decrypt");

        // Verify: alpha + beta = a * b mod q
        let alpha = Integer::from_bytes_msf(&alpha_bytes);
        let beta = Integer::from_bytes_msf(&beta_bytes);
        let sum = (alpha + beta).modulo(&q);
        let expected = (a * b).modulo(&q);

        assert_eq!(
            sum, expected,
            "CGGMP20 MtA: alpha + beta must equal a * b mod q"
        );
    }

    /// Generate a Blum prime (p = 3 mod 4) of the specified bit size.
    fn generate_blum_prime(rng: &mut impl CryptoRngCore, bits: u32) -> Integer {
        loop {
            let p = Integer::generate_prime(rng, bits);
            if p.mod_u(4) == 3 {
                return p;
            }
        }
    }
}
