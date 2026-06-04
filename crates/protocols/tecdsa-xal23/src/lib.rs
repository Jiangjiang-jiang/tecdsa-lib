// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]
#![allow(non_snake_case)]

//! XAL23 threshold ECDSA protocol (Xue, Au, Liu, et al., ACM CCS 2023).
//!
//! "Efficient multiplicative-to-additive function from Joye-Libert cryptosystem"
//!
//! This protocol follows the GG18 structure but uses Joye-Libert encryption
//! for the MtA (multiplicative-to-additive) share conversion instead of Paillier.
//!
//! ## JL ZK Proof Coverage
//!
//! The XAL23 paper (Section 5.1) requires the following ZK proofs:
//!
//! | Proof | Layer | Status | Notes |
//! |-------|-------|--------|-------|
//! | `zkjl_aff` (Pi_JLAff) | MtA | Wired into `JlMtA::receiver_compute` | Proves affine ciphertext correctness |
//! | `zkjl_enc` (Pi_JLEnc) | MtA | Wired into `JlMtA::sender_encrypt` | Proves encryption correctness |
//! | `zkjl_equ` (Pi_JLEqu) | Primitive | Implemented in `tecdsa-joye-libert` | Proves plaintext equality across two JL instances |
//! | `zkjl_com` (Pi_JLCom) | Primitive | Implemented in `tecdsa-joye-libert` | Proves JL commitment opening |
//! | `zkjlv_com` (Pi_JLvCom) | Primitive | Implemented in `tecdsa-joye-libert` | Vector commitment variant |
//! | `zkjlv_equ` (Pi_JLvEqu) | Primitive | Implemented in `tecdsa-joye-libert` | Vector equality variant |
//! | `zkjlmod` (Pi_JLMod) | Setup/Keygen | Implemented in `tecdsa-joye-libert` | Bundles zkqr2k + zkqr2kdl; NOT yet wired into keygen |
//! | `zkqr2k` (Pi_QR2k) | Setup | Implemented in `tecdsa-joye-libert` | Proves h is 2^k-th power residue |
//! | `zkqr2kdl` (Pi_QR2kDL) | Setup | Implemented in `tecdsa-joye-libert` | Proves y = h^alpha relationship |
//!
//! ### What is covered by the JlMtA backend
//!
//! The `JlMtA` trait implementation (`tecdsa-joye-libert/src/mta.rs`) performs
//! the homomorphic affine computation with full ZK proof coverage:
//! - `sender_encrypt`: produces `ZkJlEncProof` proving the JL ciphertext
//!   encrypts the claimed plaintext.
//! - `receiver_compute`: verifies the sender's `ZkJlEncProof`, then produces
//!   `ZkJlAffProof` proving the affine operation was correct.
//! - `sender_decrypt`: verifies the receiver's `ZkJlAffProof` before decrypting.
//!
//! ### What needs protocol-layer wiring
//!
//! - **Keygen**: `zkjlmod` (bundling `zkqr2k` + `zkqr2kdl`) should be proved
//!   by each party during key generation and verified by all peers. The
//!   `generate_keypair_with_qnr()` API already exposes the QNR witness `x`
//!   needed for the proof. The keygen state machine (`Xal23KeygenMachine`)
//!   does not yet generate or verify `zkjlmod` proofs.
//!
//! MtA message proofs (`zkjl_equ`, `zkjl_aff`) are fully wired. Keygen
//! modulus proofs (`zkjlmod`) are still deferred.

pub mod key_share;
pub mod keygen;
pub mod metadata;
pub mod presign;
pub mod sign;
// ---------------------------------------------------------------------------
// Protocol trait implementation
// ---------------------------------------------------------------------------

use tecdsa_protocol::{NoOpMachine, Protocol, ProtocolMetadata};

/// XAL23 threshold ECDSA protocol descriptor.
///
/// Uses Joye-Libert encryption for the MtA (multiplicative-to-additive)
/// sub-protocol.  The protocol has 4-round presign + 1-round online sign.
///
/// ## Presign
///
/// [`presign::Xal23PresignMachine`] is a proper 4-round interactive
/// StateMachine driven by the Orchestrator/Session layer.  Use
/// `Xal23PresignMachine::new()` for the interactive protocol, or
/// `Xal23PresignMachine::new_simulation()` for backward-compatible
/// simulation mode.  The free functions `presign::presign_all` and
/// `presign::presign_all_with_sec` remain available for orchestrated
/// simulation usage.
///
/// ## Sign
///
/// [`sign::Xal23SignMachine`] is a proper 1-round interactive StateMachine.
/// On construction it computes the local partial signature and queues it for
/// broadcast.  After receiving all peers' partial signatures, it combines
/// them into a verified ECDSA signature.  The free functions
/// `sign::partial_sign` and `sign::combine_signatures` remain available for
/// orchestrated/simulation usage.
pub struct Xal23;

impl Protocol for Xal23 {
    type Curve = k256::Secp256k1;

    type KeyShare = key_share::Xal23KeyShare<k256::Secp256k1>;
    type PublicKey = k256::ProjectivePoint;
    type AuxInfo = ();
    type Presignature = presign::Xal23Presignature<k256::Secp256k1>;
    type Signature = tecdsa_protocol::Signature<k256::Secp256k1>;

    type KeyGen = keygen::Xal23KeygenMachine<k256::Secp256k1>;
    type AuxGen = NoOpMachine;
    /// Presign StateMachine (4-round interactive protocol with JL MtA).
    type Presign = presign::Xal23PresignMachine<k256::Secp256k1>;
    /// Sign StateMachine (proper 1-round interactive protocol).
    type Sign = sign::Xal23SignMachine<k256::Secp256k1>;
    type Refresh = tecdsa_protocol::NoRefreshMachine<Self::KeyShare>;

    const METADATA: ProtocolMetadata = XAL23_METADATA;
}

/// Protocol metadata for XAL23.
pub const XAL23_METADATA: ProtocolMetadata = metadata::METADATA;
