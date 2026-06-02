// SPDX-License-Identifier: MIT OR Apache-2.0
//! Message types for the CGGMP20 auxiliary-info generation protocol.

use serde::{Deserialize, Serialize};
use tecdsa_commit::HashCommitment;
use tecdsa_paillier::EncryptionKey;
use tecdsa_pedersen_mod::{PedersenModParams, PiPrm};

use tecdsa_paillier::zk::paillier_zk::no_small_factor as pi_fac;
use tecdsa_pedersen_mod::PiMod;

/// Round 1 broadcast: hash commitment to the party's auxiliary material.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MsgRound1 {
    pub commitment: HashCommitment,
}

/// Round 2 broadcast: decommitment data containing the party's Paillier
/// encryption key, ring-Pedersen parameters, a PiPrm proof, the random
/// session contribution `rho`, and the decommitment nonce.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MsgRound2 {
    pub paillier_ek: EncryptionKey,
    pub pedersen_params: PedersenModParams,
    pub pi_prm: PiPrm,
    pub rho: [u8; 32],
    pub decommit_nonce: [u8; 32],
}

/// Round 3 P2P message: π_mod proof that the Paillier modulus is a
/// Blum modulus, and π_fac proof that its prime factors are large enough.
///
/// Sent point-to-point because π_fac is computed against each verifier's
/// ring-Pedersen parameters.
#[derive(Clone, Serialize, Deserialize)]
pub struct MsgRound3 {
    pub pi_mod: PiMod,
    pub pi_fac: pi_fac::NiProof,
}

impl std::fmt::Debug for MsgRound3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MsgRound3")
            .field("pi_mod", &"<PiMod>")
            .field("pi_fac", &"<NiProof>")
            .finish()
    }
}

/// Unified envelope for all aux-info messages.
///
/// Uses a single type for both `Inbound` and `Outbound` so that the
/// `Orchestrator` constraint `Outbound: Into<Inbound>` is trivially satisfied.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AuxInfoMsg {
    Round1(MsgRound1),
    Round2(MsgRound2),
    Round3(MsgRound3),
}
