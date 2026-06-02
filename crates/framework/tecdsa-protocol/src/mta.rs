// SPDX-License-Identifier: MIT OR Apache-2.0
//! Multiplicative-to-Additive (MtA) share conversion traits.
//!
//! The F_MtA functionality: two parties P_sender (with input `b`) and
//! P_receiver (with input `a`) obtain outputs `beta` and `alpha` respectively,
//! such that `alpha + beta = a * b mod q`.
//!
//! Three trait families cover all known MtA patterns:
//!
//! - [`MtA`] -- classic two-message (encrypt / compute / decrypt) pattern.
//!   Extended by [`MtAWithCheck`] for consistency proofs (MtAwc).
//! - [`MtAInteractive`] -- three-message interactive pattern for OT/RVOLE-based
//!   backends where the multiplication sub-protocol needs an extra round.
//! - [`MtABroadcast`] -- non-interactive broadcast-then-decode pattern for
//!   NIM or scaled-decryption backends where both parties independently
//!   encode, broadcast, and locally decode.
//!
//! Four concrete backends are planned:
//! - `PaillierMtA` in `tecdsa-paillier` (MIT) -- implements [`MtA`]
//! - `ClMtA` in `tecdsa-class-group` (GPL-3.0) -- implements [`MtA`] + [`MtAWithCheck`]
//! - `OtMtA` in `tecdsa-ot` (MIT) -- implements [`MtAInteractive`]
//! - `JlMtA` in `tecdsa-joye-libert` (MIT) -- implements [`MtA`]

use rand_core::CryptoRngCore;

/// Output of a single MtA execution: additive shares `(alpha, beta)` such
/// that `alpha + beta = a * b mod q` for the two parties' inputs `a` and `b`.
pub struct MtaShares {
    /// Receiver's (P1's) output share, big-endian bytes.
    pub alpha: Vec<u8>,
    /// Sender's (P2's) output share, big-endian bytes.
    pub beta: Vec<u8>,
}

/// Trait for MtA (Multiplicative-to-Additive) sub-protocols.
///
/// The protocol has three steps:
/// 1. **Sender encrypt**: P2 encrypts input `b` and sends `SenderMsg` to P1.
/// 2. **Receiver compute**: P1 homomorphically computes on `SenderMsg` with
///    input `a`, sends `ReceiverMsg` to P2, and obtains `alpha`.
/// 3. **Sender decrypt**: P2 decrypts `ReceiverMsg` to obtain `beta`.
///
/// After completion: `alpha + beta = a * b mod q`.
pub trait MtA: Sized + 'static {
    /// Setup material (keys, parameters). Cloneable for multi-use.
    type Setup: Clone;

    /// Sender's internal state between encrypt and decrypt.
    type SenderState;

    /// Message from sender (P2) to receiver (P1): encrypted `b` + ZK proof.
    type SenderMsg;

    /// Message from receiver (P1) to sender (P2): affine result + ZK proof.
    type ReceiverMsg;

    /// Error type for this MtA backend.
    type Error: core::fmt::Debug + core::fmt::Display;

    /// Step 1: Sender (P2) encrypts input `b`.
    ///
    /// `b_bytes` is the big-endian representation of scalar `b`.
    /// `q_bytes` is the big-endian representation of the curve order.
    ///
    /// Returns `(message_for_receiver, sender_state)`.
    fn sender_encrypt(
        setup: &Self::Setup,
        b_bytes: &[u8],
        q_bytes: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::SenderMsg, Self::SenderState), Self::Error>;

    /// Step 2: Receiver (P1) computes affine operation with input `a`.
    ///
    /// `a_bytes` is the big-endian representation of scalar `a`.
    /// `q_bytes` is the big-endian representation of the curve order.
    ///
    /// Returns `(message_for_sender, alpha_bytes)` where `alpha` is the
    /// receiver's MtA output share (big-endian).
    fn receiver_compute(
        setup: &Self::Setup,
        a_bytes: &[u8],
        q_bytes: &[u8],
        sender_msg: &Self::SenderMsg,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::ReceiverMsg, Vec<u8>), Self::Error>;

    /// Step 3: Sender (P2) decrypts to obtain `beta`.
    ///
    /// Returns `beta_bytes` (big-endian), the sender's MtA output share.
    fn sender_decrypt(
        setup: &Self::Setup,
        state: &Self::SenderState,
        q_bytes: &[u8],
        receiver_msg: &Self::ReceiverMsg,
    ) -> Result<Vec<u8>, Self::Error>;
}

/// Extension trait for MtA with consistency check (MtAwc).
///
/// Used by protocols like WMY23 where the MtA output is accompanied by
/// a verifiable consistency proof.  The check proves that the receiver
/// computed the affine operation honestly, so that `alpha + beta = a * b`.
///
/// # Verification context
///
/// The sender-side consistency check typically requires:
/// - The decrypted result `beta` from `sender_decrypt`
/// - The sender's original state from `sender_encrypt`
/// - A public value `g^b` (the receiver's EC public point)
///
/// `verify_check` takes `sender_state` and extra public context
/// (`aux_bytes`) to support protocols like WMY23 where the check is
/// `g^{beta} * g^{alpha} == (g^b)^a`, requiring `b` from sender state
/// and `g^a` implicitly through the algebraic relation.
pub trait MtAWithCheck: MtA {
    /// Proof data for the consistency check.
    type CheckProof;

    /// Receiver compute with consistency proof generation.
    ///
    /// Returns `(receiver_msg, alpha_bytes, check_proof)`.  The `check_proof`
    /// is sent alongside `receiver_msg` to the sender for verification.
    // The 3-tuple of associated types is documented above; a type alias over
    // associated types would be more obscure than the tuple itself.
    #[allow(clippy::type_complexity)]
    fn receiver_compute_with_check(
        setup: &Self::Setup,
        a_bytes: &[u8],
        q_bytes: &[u8],
        sender_msg: &Self::SenderMsg,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::ReceiverMsg, Vec<u8>, Self::CheckProof), Self::Error>;

    /// Verify the consistency check on the sender side after decryption.
    ///
    /// # Arguments
    ///
    /// * `setup` - Setup material (keys, parameters).
    /// * `state` - Sender's internal state from `sender_encrypt`.
    /// * `q_bytes` - Curve order (big-endian).
    /// * `beta_bytes` - Sender's decrypted share from `sender_decrypt` (big-endian).
    /// * `check_proof` - Proof data from receiver's `receiver_compute_with_check`.
    /// * `aux_bytes` - Protocol-specific auxiliary data for the check.
    ///   For CL MtAwc (WMY23), this is `g^a` compressed EC point bytes.
    fn verify_check(
        setup: &Self::Setup,
        state: &Self::SenderState,
        q_bytes: &[u8],
        beta_bytes: &[u8],
        check_proof: &Self::CheckProof,
        aux_bytes: &[u8],
    ) -> Result<bool, Self::Error>;
}

/// Multi-round MtA for protocols where the multiplication sub-protocol
/// requires more than two messages (e.g., OT/RVOLE-based MtA).
///
/// The protocol has four steps with three messages:
///
/// ```text
/// Sender(a)                     Receiver(b)
///    |--- InitMsg ------------------>|
///    |<-- ResponseMsg ---------------|  (receiver incorporates b)
///    |--- ComputeMsg --------------->|  (sender incorporates a)
///
///    alpha = local                beta = local
///    alpha + beta = a*b mod q
/// ```
pub trait MtAInteractive: Sized + 'static {
    type Setup: Clone;
    type SenderState;
    type ReceiverState;
    type InitMsg;
    type ResponseMsg;
    type ComputeMsg;
    type Error: core::fmt::Debug + core::fmt::Display;

    fn sender_init(
        setup: &Self::Setup,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::InitMsg, Self::SenderState), Self::Error>;

    fn receiver_respond(
        setup: &Self::Setup,
        b_bytes: &[u8],
        q_bytes: &[u8],
        init_msg: &Self::InitMsg,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::ResponseMsg, Self::ReceiverState), Self::Error>;

    fn sender_compute(
        state: Self::SenderState,
        a_bytes: &[u8],
        q_bytes: &[u8],
        response_msg: &Self::ResponseMsg,
    ) -> Result<(Self::ComputeMsg, Vec<u8>), Self::Error>;

    fn receiver_finish(
        state: Self::ReceiverState,
        compute_msg: &Self::ComputeMsg,
        q_bytes: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;
}

/// Non-interactive broadcast-then-decode MtA for protocols using NIM
/// (Non-Interactive Multiplication) or scaled decryption.
///
/// Both parties independently encode their inputs, broadcast the
/// encodings, and locally decode using their private state plus the
/// other party's public encoding.  No back-and-forth interaction needed.
///
/// ```text
/// Party_i(v_i)                  Party_j(v_j)
///    |--- Encoding_i (broadcast) -->|
///    |<-- Encoding_j (broadcast) ---|
///
///    z_i = Decode(Encoding_j, state_i)   -- local
///    z_j = Decode(Encoding_i, state_j)   -- local
///    z_i + z_j = v_i * v_j mod q
/// ```
///
/// Encode and decode are intentionally decoupled: some protocols encode
/// in the presign phase and decode in the sign phase (e.g., LLZ25).
pub trait MtABroadcast: Sized + 'static {
    type Setup: Clone;
    type Encoding: Clone;
    type State;
    type Error: core::fmt::Debug + core::fmt::Display;

    fn encode(
        setup: &Self::Setup,
        input_bytes: &[u8],
        q_bytes: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::Encoding, Self::State), Self::Error>;

    fn decode(
        setup: &Self::Setup,
        other_encoding: &Self::Encoding,
        my_state: &Self::State,
        q_bytes: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;
}
