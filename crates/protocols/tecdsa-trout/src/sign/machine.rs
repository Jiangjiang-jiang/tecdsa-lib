// SPDX-License-Identifier: GPL-3.0-or-later
#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    non_snake_case
)]

//! StateMachine wrapper for the Trout online signing protocol.
//!
//! Wraps the `sign_round2` function into a `StateMachine` that handles
//! message-driven execution. In the centralized simulation, all parties'
//! presign outputs are available locally, so the machine immediately
//! computes the signature on construction.
//!
//! In a real distributed setting, the sign phase would involve each party
//! broadcasting its scaled decryption shares (F_i) and optionally R_affCom
//! proofs for identifiable abort.

use serde::{Deserialize, Serialize};

use tecdsa_class_group::bicycl_glue::ClSetup;
use tecdsa_core::TecdsaError;
use tecdsa_protocol::ecdsa::{DataToSign, Signature};
use tecdsa_protocol::{state_machine::Outgoing, IaReport, PartyId, StateMachine};

use super::sign_round2;
use crate::key_share::TroutKeyShare;
use crate::presign::types::TroutPresignOutput;

// ---------------------------------------------------------------------------
// Wire message types
// ---------------------------------------------------------------------------

/// Sign message (Round 2).
///
/// In the Trout protocol, the sign phase is computed locally by each party
/// using all presign outputs. The message is a placeholder to support the
/// StateMachine interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TroutSignMsg {
    /// Round 2 completion notification. In a distributed setting, this would
    /// contain the party's scaled decryption shares.
    Round2Complete,
}

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

/// StateMachine wrapper for Trout online signing.
///
/// The Trout sign phase (Round 2) is computed locally using all parties'
/// presign outputs and the message hash. The StateMachine wrapper
/// immediately computes the signature during construction.
pub struct TroutSignMachine {
    output: Option<Signature<k256::Secp256k1>>,
    done: bool,
    ia_report: Option<IaReport>,
}

impl TroutSignMachine {
    /// Create a new sign state machine and immediately compute the signature.
    ///
    /// # Arguments
    /// - `all_presigns`: presign outputs from ALL participating parties
    /// - `message`: the message digest to sign
    /// - `share`: this party's key share (for public key verification)
    /// - `setup`: CL-HSM setup
    /// - `cl_pk`: the joint CL public key
    pub fn new(
        all_presigns: &[TroutPresignOutput],
        message: &DataToSign<k256::Secp256k1>,
        share: &TroutKeyShare,
        setup: &ClSetup,
        cl_pk: &tecdsa_class_group::bicycl_glue::BicyclPublicKey,
    ) -> tecdsa_core::Result<Self> {
        match sign_round2(all_presigns, message, share, setup, cl_pk) {
            Ok(sig) => Ok(Self {
                output: Some(sig),
                done: true,
                ia_report: None,
            }),
            Err(e) => {
                // In the IA variant, we would examine F_i proofs here
                // to identify the cheater. For now, propagate the error.
                Err(TecdsaError::Other(format!("sign_round2 failed: {e}")))
            }
        }
    }
}

impl StateMachine for TroutSignMachine {
    type Output = Signature<k256::Secp256k1>;
    type Inbound = TroutSignMsg;
    type Outbound = TroutSignMsg;

    fn handle(&mut self, _from: PartyId, _msg: Self::Inbound) -> tecdsa_core::Result<()> {
        if self.done {
            return Err(TecdsaError::Other("sign machine already done".into()));
        }
        // The sign phase is computed locally; no inbound messages expected.
        Err(TecdsaError::Other(
            "TroutSignMachine does not accept inbound messages".into(),
        ))
    }

    fn drain_outgoing(&mut self) -> Vec<Outgoing<Self::Outbound>> {
        Vec::new()
    }

    fn is_done(&self) -> bool {
        self.done
    }

    fn finish(self) -> tecdsa_core::Result<Self::Output> {
        self.output
            .ok_or_else(|| TecdsaError::Other("sign not complete".into()))
    }

    fn current_round(&self) -> u16 {
        if self.done {
            2
        } else {
            1
        }
    }

    fn ia_report(&self) -> Option<&IaReport> {
        self.ia_report.as_ref()
    }
}
