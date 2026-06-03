// SPDX-License-Identifier: MIT OR Apache-2.0
//! CGGMP20 full-signing protocol (presign + signing round).
//!
//! A convenience wrapper that runs the 3-round presigning protocol to
//! completion and then executes a 4th round in which parties exchange partial
//! signatures and combine them into a full ECDSA signature.

pub mod msg;

use std::collections::BTreeMap;

use elliptic_curve::{
    ops::LinearCombination, sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField,
};
use msg::{FullSignMsg, MsgRound4};
use rand_core::CryptoRngCore;
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{
    state_machine::Outgoing, IaReport, PartyId, Recipient, SessionConfig, StateMachine,
};

use crate::{
    key_share::{AuxInfo, Cggmp20CoreKeyShare},
    presign::Cggmp20PresignMachine,
    security_level::{Cggmp20SecurityParams, SecurityLevel128},
    sign::types::{DataToSign, PartialSignature, PresignaturePublicData, Signature},
};

// ---------------------------------------------------------------------------
// Round 4 state
// ---------------------------------------------------------------------------

/// State held while collecting partial signatures in round 4.
pub(crate) struct Round4State<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// This party's ID.
    pub my_id: PartyId,
    /// Partial signature scalars received from peers (keyed by sender PartyId).
    pub received: BTreeMap<PartyId, C::Scalar>,
    /// This party's own partial signature.
    pub own_partial: PartialSignature<C>,
    /// Public presignature data (contains R).
    pub presig_public: PresignaturePublicData<C>,
    /// Joint ECDSA public key.
    pub public_key: C::ProjectivePoint,
    /// The message digest being signed.
    pub message: DataToSign<C>,
    /// Outgoing messages queued when entering this state (the own broadcast).
    pub outgoing: Vec<Outgoing<FullSignMsg<C>>>,
    /// Number of peer partial signatures to wait for (= signers - 1).
    pub expected: usize,
}

// ---------------------------------------------------------------------------
// Phase enum (with Gone sentinel for mem::take)
// ---------------------------------------------------------------------------

#[derive(Default)]
pub(crate) enum FullSignPhase<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Rounds 1–3: delegated to the inner Cggmp20PresignMachine.
    Presigning(Cggmp20PresignMachine<C>),
    /// Round 4: collecting partial signatures.
    Signing(Round4State<C>),
    /// Protocol complete.
    Done(Signature<C>),
    /// Sentinel so `std::mem::take` can be used for phase transitions.
    #[default]
    Gone,
}

// ---------------------------------------------------------------------------
// FullSignMachine
// ---------------------------------------------------------------------------

/// Full-signing state machine: presign (3 rounds) followed by signing (1 round).
pub struct FullSignMachine<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    phase: FullSignPhase<C>,
    /// This party's ID.
    my_id: PartyId,
    /// The message to sign.
    message: DataToSign<C>,
    /// Joint ECDSA public key.
    public_key: C::ProjectivePoint,
    /// Total number of signing parties (used to compute expected peer count for round 4).
    signers_count: usize,
}

impl<C: TecdsaCurve> FullSignMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
    C: crate::bridge::BridgeCurve,
{
    /// Create a new full-signing state machine with the default 128-bit security level.
    ///
    /// * `config`     — session configuration (must contain only the signing subset)
    /// * `core_share` — this party's key share from key generation
    /// * `aux`        — this party's auxiliary info (Paillier keys, Pedersen params)
    /// * `signers`    — 1-based indices of the signing participants
    /// * `message`    — the message digest to sign
    /// * `rng`        — cryptographic RNG
    pub fn new(
        config: &SessionConfig,
        core_share: &Cggmp20CoreKeyShare<C>,
        aux: &AuxInfo,
        signers: &[u16],
        message: DataToSign<C>,
        rng: &mut impl CryptoRngCore,
    ) -> Self {
        Self::with_security::<SecurityLevel128>(config, core_share, aux, signers, message, rng)
    }

    /// Create a new full-signing state machine with a custom security level.
    pub fn with_security<L: Cggmp20SecurityParams>(
        config: &SessionConfig,
        core_share: &Cggmp20CoreKeyShare<C>,
        aux: &AuxInfo,
        signers: &[u16],
        message: DataToSign<C>,
        rng: &mut impl CryptoRngCore,
    ) -> Self {
        let public_key = core_share.public_key;
        let signers_count = signers.len();
        let my_id = config.local_party.id;
        let presign =
            Cggmp20PresignMachine::with_security::<L>(config, core_share, aux, signers, rng);
        Self {
            phase: FullSignPhase::Presigning(presign),
            my_id,
            message,
            public_key,
            signers_count,
        }
    }
}

impl<C: TecdsaCurve> StateMachine for FullSignMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::ProjectivePoint: LinearCombination<[(C::ProjectivePoint, C::Scalar); 2]>,
    C::Scalar:
        PrimeField<Repr = FieldBytes<C>> + serde::Serialize + for<'de> serde::Deserialize<'de>,
    C: crate::bridge::BridgeCurve,
{
    type Output = Signature<C>;
    type Inbound = FullSignMsg<C>;
    type Outbound = FullSignMsg<C>;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        match &mut self.phase {
            FullSignPhase::Presigning(presign) => {
                // Only accept Presign-wrapped messages during rounds 1–3.
                let pmsg = match msg {
                    FullSignMsg::Presign(m) => m,
                    FullSignMsg::Round4(_) => {
                        return Err(TecdsaError::RoundMismatch {
                            expected: 1,
                            got: 4,
                        });
                    }
                };

                presign.handle(from, pmsg)?;

                // Check if the presign protocol is now complete.
                if presign.is_done() {
                    // Take ownership of the presign machine.
                    let old = std::mem::take(&mut self.phase);
                    let presign_machine = match old {
                        FullSignPhase::Presigning(pm) => pm,
                        _ => unreachable!(),
                    };

                    // Finish to get presignature + public data.
                    let (presignature, presig_public) = presign_machine.finish()?;

                    // Compute own partial signature.
                    let own_partial = presignature.partial_sign(&self.message);

                    // Broadcast own partial signature.
                    let outgoing = vec![Outgoing {
                        to: Recipient::Broadcast,
                        msg: FullSignMsg::Round4(MsgRound4 {
                            sigma: own_partial.sigma,
                        }),
                    }];

                    // expected = number of peers = signers_count - 1
                    let expected = self.signers_count - 1;

                    self.phase = FullSignPhase::Signing(Round4State {
                        my_id: self.my_id,
                        received: BTreeMap::new(),
                        own_partial,
                        presig_public,
                        public_key: self.public_key,
                        message: self.message,
                        outgoing,
                        expected,
                    });
                }
                Ok(())
            }

            FullSignPhase::Signing(state) => {
                let r4msg = match msg {
                    FullSignMsg::Round4(m) => m,
                    FullSignMsg::Presign(_) => {
                        return Err(TecdsaError::RoundMismatch {
                            expected: 4,
                            got: 1,
                        });
                    }
                };

                if state.received.contains_key(&from) {
                    return Err(TecdsaError::DuplicateMessage(from.0));
                }
                state.received.insert(from, r4msg.sigma);

                // Check if we have all expected partial signatures.
                if state.received.len() == state.expected {
                    let old = std::mem::take(&mut self.phase);
                    let s4 = match old {
                        FullSignPhase::Signing(s) => s,
                        _ => unreachable!(),
                    };

                    // Collect all partial signatures sorted by PartyId
                    // (must match the commitment order from presign finish).
                    let mut all_partials: BTreeMap<PartyId, PartialSignature<C>> = BTreeMap::new();
                    all_partials.insert(s4.my_id, s4.own_partial);
                    for (pid, sigma) in s4.received {
                        all_partials.insert(pid, PartialSignature { sigma });
                    }
                    let partials: Vec<_> = all_partials.into_values().collect();

                    // Combine into a full signature.
                    let sig = PartialSignature::combine(
                        &partials,
                        &s4.presig_public,
                        &s4.public_key,
                        &s4.message,
                    )?;

                    self.phase = FullSignPhase::Done(sig);
                }
                Ok(())
            }

            FullSignPhase::Done(_) | FullSignPhase::Gone => {
                Err(TecdsaError::Other("protocol already finished".into()))
            }
        }
    }

    fn drain_outgoing(&mut self) -> Vec<Outgoing<Self::Outbound>> {
        match &mut self.phase {
            FullSignPhase::Presigning(presign) => presign
                .drain_outgoing()
                .into_iter()
                .map(|o| Outgoing {
                    to: o.to,
                    msg: FullSignMsg::Presign(o.msg),
                })
                .collect(),
            FullSignPhase::Signing(state) => std::mem::take(&mut state.outgoing),
            FullSignPhase::Done(_) | FullSignPhase::Gone => Vec::new(),
        }
    }

    fn is_done(&self) -> bool {
        matches!(self.phase, FullSignPhase::Done(_))
    }

    fn finish(self) -> tecdsa_core::Result<Self::Output> {
        match self.phase {
            FullSignPhase::Done(sig) => Ok(sig),
            _ => Err(TecdsaError::Other("protocol not yet complete".into())),
        }
    }

    fn current_round(&self) -> u16 {
        match &self.phase {
            FullSignPhase::Presigning(presign) => presign.current_round(),
            FullSignPhase::Signing(_) => 4,
            FullSignPhase::Done(_) => 5,
            FullSignPhase::Gone => 0,
        }
    }

    fn ia_report(&self) -> Option<&IaReport> {
        None
    }
}
