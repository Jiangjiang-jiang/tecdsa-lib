// SPDX-License-Identifier: MIT OR Apache-2.0
//! Presign `StateMachine` wrapper for XAL23.
//!
//! ## Simulation mode
//!
//! The `presign_all` function runs all 4 presign rounds internally in a single
//! orchestrated call (every party's state is available locally).  Decomposing it
//! into a genuine multi-round `StateMachine` would require splitting the `MtA`
//! calls into separate send/receive steps with message serialization, which is
//! deferred to a future iteration.
//!
//! This wrapper takes the pragmatic approach: **on construction** it runs
//! `presign_all` and stores the presignature result.  The `StateMachine`
//! interface exposes this as an immediately-done machine that accepts no
//! messages.
//!
//! Callers that need real message exchange should use `presign_all` /
//! `presign_all_with_sec` directly until the multi-round decomposition is
//! implemented.

#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    non_snake_case
)]

use elliptic_curve::{sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField};
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{state_machine::Outgoing, IaReport, PartyId, StateMachine};

use super::msg::Xal23PresignMsg;
use crate::{key_share::Xal23KeyShare, presign::Xal23Presignature};

/// Simulation-mode presign `StateMachine` for XAL23.
///
/// On construction, runs the full 4-round presigning protocol internally
/// via `presign_all_with_sec`, producing presignatures for all parties.
/// The machine immediately transitions to the "done" state.
///
/// **This is a simulation wrapper.** It requires key shares for ALL signing
/// parties (not just the local party) and does not perform real network
/// message exchange.  A proper multi-round decomposition is planned for a
/// future iteration.
pub struct Xal23PresignMachine<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Presignatures for all signing parties (indexed by position in
    /// `signer_indices`). The local party's presignature is at the
    /// position corresponding to its index in `signer_indices`.
    presignatures: Vec<Xal23Presignature<C>>,
    /// Index of the local party within the `signer_indices` array.
    local_index: usize,
    done: bool,
}

impl<C: TecdsaCurve> Xal23PresignMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// Create a new simulation-mode presign machine.
    ///
    /// Immediately runs all 4 presign rounds internally.
    ///
    /// # Arguments
    ///
    /// * `key_shares` - Key shares for ALL signing parties
    /// * `signer_indices` - Indices of the signing parties (0-based, into `key_shares`)
    /// * `local_signer_pos` - Position of the local party within `signer_indices`
    /// * `rng` - Cryptographic RNG
    pub fn new(
        key_shares: &[Xal23KeyShare<C>],
        signer_indices: &[usize],
        local_signer_pos: usize,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Self {
        Self::with_sec(key_shares, signer_indices, local_signer_pos, 40, 40, rng)
    }

    /// Create with configurable statistical security parameters.
    ///
    /// `s` and `t` are the `MtA` statistical security parameters.
    pub fn with_sec(
        key_shares: &[Xal23KeyShare<C>],
        signer_indices: &[usize],
        local_signer_pos: usize,
        s: u32,
        t: u32,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Self {
        let presignatures = super::presign_all_with_sec(key_shares, signer_indices, s, t, rng);
        Self {
            presignatures,
            local_index: local_signer_pos,
            done: true,
        }
    }

    /// Access the presignature for the local party.
    pub fn local_presignature(&self) -> &Xal23Presignature<C> {
        &self.presignatures[self.local_index]
    }

    /// Consume the machine and return ALL presignatures (one per signer).
    ///
    /// This is useful for simulation/testing where all presignatures are
    /// needed to drive the sign phase for every party.
    pub fn into_all_presignatures(self) -> Vec<Xal23Presignature<C>> {
        self.presignatures
    }
}

impl<C: TecdsaCurve> StateMachine for Xal23PresignMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    type Output = Xal23Presignature<C>;
    type Inbound = Xal23PresignMsg;
    type Outbound = Xal23PresignMsg;

    fn handle(&mut self, _from: PartyId, _msg: Self::Inbound) -> tecdsa_core::Result<()> {
        Err(TecdsaError::Other(
            "Xal23PresignMachine (simulation mode) does not accept messages; \
             presign was computed on construction"
                .into(),
        ))
    }

    fn drain_outgoing(&mut self) -> Vec<Outgoing<Self::Outbound>> {
        Vec::new()
    }

    fn is_done(&self) -> bool {
        self.done
    }

    fn finish(mut self) -> tecdsa_core::Result<Self::Output> {
        if !self.done {
            return Err(TecdsaError::Other("presign not complete".into()));
        }
        // Return the local party's presignature.
        Ok(self.presignatures.swap_remove(self.local_index))
    }

    fn current_round(&self) -> u16 {
        if self.done {
            5
        } else {
            0
        }
    }

    fn ia_report(&self) -> Option<&IaReport> {
        None
    }
}
