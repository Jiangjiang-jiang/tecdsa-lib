// SPDX-License-Identifier: MIT OR Apache-2.0
//! StateMachine wrapper for the XAL+21 two-party interactive DKG.
//!
//! Wraps the pure functions from [`super::interactive`] into a
//! [`StateMachine`] that exchanges serialized messages between Party1 and
//! Party2.
//!
//! ## Message flow
//!
//! ```text
//! Party1                            Party2
//!   |--- Round1 (commitment) -------->|
//!   |<-- Round2 (Q2,ek,proofs) -------|
//!   |--- Round3 (decommit Q1) ------->|
//!   |                                 | (verify + finalize)
//!   done                              done
//! ```

use elliptic_curve::{sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField};
use serde::{Deserialize, Serialize};
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{
    state_machine::Outgoing, AbortReason, IaReport, PartyId, Recipient, StateMachine,
};
use zeroize::Zeroize;

use crate::{
    key_share::{Xal21Party1KeyShare, Xal21Party2KeyShare},
    keygen::{
        interactive::{
            party1_finalize, party1_keygen_round1, party1_keygen_round3, party2_finalize,
            party2_keygen_round2, party2_keygen_round2_with_setup, party2_verify_round3,
            KeyGenP1Round1Msg, KeyGenP1Round3Msg, KeyGenP1State, KeyGenP2Round2Msg, KeyGenP2State,
        },
        wire::{decode_r1, decode_r2, decode_r3, encode_r1, encode_r2, encode_r3},
    },
};

// ---------------------------------------------------------------------------
// Two-party role
// ---------------------------------------------------------------------------

/// Role in the two-party protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TwoPartyRole {
    /// P1 (server): initiates keygen with commitment, holds secret share x1.
    Party1,
    /// P2 (client): generates Paillier keys, holds decryption key.
    Party2,
}

// ---------------------------------------------------------------------------
// Combined key share
// ---------------------------------------------------------------------------

/// Combined key share wrapping both party types.
///
/// The variant indicates which role this party played during keygen.
pub enum Xal21KeyShare<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    Party1(Xal21Party1KeyShare<C>),
    Party2(Xal21Party2KeyShare<C>),
}

impl<C: TecdsaCurve> Zeroize for Xal21KeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn zeroize(&mut self) {
        match self {
            Self::Party1(s) => s.zeroize(),
            Self::Party2(s) => s.zeroize(),
        }
    }
}

impl<C: TecdsaCurve> std::fmt::Debug for Xal21KeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Party1(_) => f.write_str("Xal21KeyShare::Party1(...)"),
            Self::Party2(_) => f.write_str("Xal21KeyShare::Party2(...)"),
        }
    }
}

// ---------------------------------------------------------------------------
// Wire message envelope
// ---------------------------------------------------------------------------

/// Envelope message for the keygen state machine.
///
/// Each variant carries the serialized payload for the corresponding round.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Xal21KeygenMsg {
    /// P1 -> P2: commitment to (Q1, DLog proof).
    Round1(Vec<u8>),
    /// P2 -> P1: Q2, DLog proof, Paillier ek, Pi_GCD.
    Round2(Vec<u8>),
    /// P1 -> P2: decommitment of (Q1, DLog proof).
    Round3(Vec<u8>),
}

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

enum Xal21KeygenState<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// Party1: sent Round1 commitment, waiting for Round2 from P2.
    P1WaitingForR2 { p1_state: KeyGenP1State<C> },
    /// Party2 initial state: waiting for Round1 from P1.
    P2WaitingForR1,
    /// Party2: received Round1, sent Round2, waiting for Round3 from P1.
    P2WaitingForR3 {
        p2_state: KeyGenP2State<C>,
        p1_r1_msg: KeyGenP1Round1Msg,
    },
    /// Terminal state: output has been produced.
    Done,
}

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

/// XAL+21 interactive keygen state machine.
///
/// Construct via [`Xal21KeygenMachine::new`], specifying the role, own party
/// ID, and peer party ID.  For `Party1`, the constructor immediately produces
/// the Round1 message (queued in `outgoing`).  For `Party2`, the machine
/// waits for the Round1 message from `Party1`.
pub struct Xal21KeygenMachine<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    #[allow(dead_code)]
    role: TwoPartyRole,
    #[allow(dead_code)]
    my_id: PartyId,
    peer_id: PartyId,
    state: Xal21KeygenState<C>,
    outgoing: Vec<Outgoing<Xal21KeygenMsg>>,
    output: Option<Xal21KeyShare<C>>,
    round: u16,
    ia_report: Option<IaReport>,
    /// Optional precomputed MtA setup for P2 (Paillier key + Ring-Pedersen
    /// params), injected via [`Xal21KeygenMachine::new_with_setup`]. When
    /// present, P2 uses it in round 2 instead of generating fresh material (the
    /// setup is a one-time step, kept out of the DKG round timing).
    precomputed_setup:
        Option<(tecdsa_paillier::DecryptionKey, tecdsa_paillier::zk::mta_range::NTildeParams)>,
}

impl<C: TecdsaCurve> Xal21KeygenMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// Create a new keygen state machine.
    ///
    /// - `Party1` role: immediately samples `x1`, creates a commitment, and
    ///   queues the Round1 message.
    /// - `Party2` role: enters the waiting-for-Round1 state.
    ///
    /// # Errors
    ///
    /// Returns an error if `my_id == peer_id`.
    pub fn new(
        role: TwoPartyRole,
        my_id: PartyId,
        peer_id: PartyId,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Result<Self, TecdsaError> {
        Self::new_with_setup(role, my_id, peer_id, None, rng)
    }

    /// Like [`Xal21KeygenMachine::new`], but lets the caller inject P2's
    /// **precomputed** MtA setup (Paillier decryption key + Ring-Pedersen
    /// parameters).
    ///
    /// XAL+21's MtA setup is a one-time, message-independent step. By generating
    /// it up front (see [`super::generate_setup`]) and passing it here, callers
    /// (e.g. benchmark harnesses) keep the (multi-second) safe-prime generation
    /// out of the measured DKG rounds. `precomputed_setup` is only consumed by
    /// `Party2` (in round 2); for `Party1` it is ignored.
    ///
    /// # Errors
    ///
    /// Returns an error if `my_id == peer_id`.
    pub fn new_with_setup(
        role: TwoPartyRole,
        my_id: PartyId,
        peer_id: PartyId,
        precomputed_setup: Option<(
            tecdsa_paillier::DecryptionKey,
            tecdsa_paillier::zk::mta_range::NTildeParams,
        )>,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Result<Self, TecdsaError> {
        if my_id == peer_id {
            return Err(TecdsaError::Other("my_id and peer_id must differ".into()));
        }

        let (state, outgoing, round) = match role {
            TwoPartyRole::Party1 => {
                let (r1_msg, p1_state) = party1_keygen_round1::<C>(rng);
                let payload = encode_r1::<C>(&r1_msg)?;
                let out = Outgoing {
                    to: Recipient::Party(peer_id),
                    msg: Xal21KeygenMsg::Round1(payload),
                };
                (Xal21KeygenState::P1WaitingForR2 { p1_state }, vec![out], 1)
            }
            TwoPartyRole::Party2 => (Xal21KeygenState::P2WaitingForR1, Vec::new(), 0),
        };

        Ok(Self {
            role,
            my_id,
            peer_id,
            state,
            outgoing,
            output: None,
            round,
            ia_report: None,
            precomputed_setup,
        })
    }

    fn handle_p2_waiting_for_r1(
        &mut self,
        from: PartyId,
        payload: Vec<u8>,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> tecdsa_core::Result<()> {
        self.validate_sender(from)?;

        let p1_r1_msg = decode_r1(&payload)?;

        // Use the precomputed MtA setup if one was injected via
        // `new_with_setup`; otherwise generate fresh material in-round.
        let (r2_msg, p2_state) = match self.precomputed_setup.take() {
            Some((dk, ntilde)) => party2_keygen_round2_with_setup::<C>(dk, ntilde, rng),
            None => party2_keygen_round2::<C>(rng),
        }
        .map_err(|e| TecdsaError::Other(format!("P2 round2 failed: {e}")))?;

        let payload = encode_r2::<C>(&r2_msg)?;

        self.outgoing.push(Outgoing {
            to: Recipient::Party(self.peer_id),
            msg: Xal21KeygenMsg::Round2(payload),
        });

        self.state = Xal21KeygenState::P2WaitingForR3 {
            p2_state,
            p1_r1_msg,
        };
        self.round = 2;
        Ok(())
    }

    fn handle_p1_waiting_for_r2(
        &mut self,
        from: PartyId,
        payload: Vec<u8>,
        p1_state: KeyGenP1State<C>,
    ) -> tecdsa_core::Result<()> {
        self.validate_sender(from)?;

        let p2_r2_msg: KeyGenP2Round2Msg<C> = decode_r2::<C>(&payload)?;

        let p1_r3_msg = match party1_keygen_round3::<C>(&p1_state, &p2_r2_msg) {
            Ok(msg) => msg,
            Err(e) => {
                self.ia_report = Some(IaReport {
                    blamed: vec![from],
                    reason: AbortReason::InvalidProof {
                        round: 2,
                        party: from,
                    },
                });
                return Err(TecdsaError::InvalidProof(format!(
                    "P1 verification of P2 round2 failed: {e}"
                )));
            }
        };

        let payload = encode_r3::<C>(&p1_r3_msg)?;

        self.outgoing.push(Outgoing {
            to: Recipient::Party(self.peer_id),
            msg: Xal21KeygenMsg::Round3(payload),
        });

        // Zeroize transient secret scalar: p1_state is consumed by
        // party1_finalize, but x1 is Copy so the local copy persists.
        let mut x1_residual = p1_state.x1;
        let share = party1_finalize::<C>(p1_state, &p2_r2_msg);
        x1_residual.zeroize();
        self.output = Some(Xal21KeyShare::Party1(share));
        self.state = Xal21KeygenState::Done;
        self.round = 3;
        Ok(())
    }

    fn handle_p2_waiting_for_r3(
        &mut self,
        from: PartyId,
        payload: Vec<u8>,
        p2_state: KeyGenP2State<C>,
        p1_r1_msg: KeyGenP1Round1Msg,
    ) -> tecdsa_core::Result<()> {
        self.validate_sender(from)?;

        let p1_r3_msg: KeyGenP1Round3Msg<C> = decode_r3::<C>(&payload)?;

        if let Err(e) = party2_verify_round3::<C>(&p1_r1_msg, &p1_r3_msg) {
            self.ia_report = Some(IaReport {
                blamed: vec![from],
                reason: AbortReason::InvalidProof {
                    round: 3,
                    party: from,
                },
            });
            return Err(TecdsaError::InvalidProof(format!(
                "P2 verification of P1 round3 failed: {e}"
            )));
        }

        // Zeroize transient secret scalar: p2_state is consumed by
        // party2_finalize, but x2 is Copy so the local copy persists.
        let mut x2_residual = p2_state.x2;
        let share = party2_finalize::<C>(p2_state, &p1_r3_msg);
        x2_residual.zeroize();
        self.output = Some(Xal21KeyShare::Party2(share));
        self.state = Xal21KeygenState::Done;
        self.round = 3;
        Ok(())
    }

    fn validate_sender(&self, from: PartyId) -> tecdsa_core::Result<()> {
        if from != self.peer_id {
            return Err(TecdsaError::Other(format!(
                "unexpected sender {from}, expected {}",
                self.peer_id
            )));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// StateMachine impl
// ---------------------------------------------------------------------------

// The `handle` method needs an RNG to call `party2_keygen_round2`, but the
// `StateMachine` trait's `handle` signature does not accept an RNG parameter.
// We use `OsRng` internally, which is the standard choice for production.

impl<C: TecdsaCurve> StateMachine for Xal21KeygenMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    type Output = Xal21KeyShare<C>;
    type Inbound = Xal21KeygenMsg;
    type Outbound = Xal21KeygenMsg;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        let mut rng = rand_core::OsRng;

        let expected = match &self.state {
            Xal21KeygenState::P2WaitingForR1 => "Round1",
            Xal21KeygenState::P1WaitingForR2 { .. } => "Round2",
            Xal21KeygenState::P2WaitingForR3 { .. } => "Round3",
            Xal21KeygenState::Done => {
                return Err(TecdsaError::Other("keygen already completed".into()));
            }
        };

        let msg_matches = matches!(
            (&self.state, &msg),
            (Xal21KeygenState::P2WaitingForR1, Xal21KeygenMsg::Round1(_))
                | (
                    Xal21KeygenState::P1WaitingForR2 { .. },
                    Xal21KeygenMsg::Round2(_)
                )
                | (
                    Xal21KeygenState::P2WaitingForR3 { .. },
                    Xal21KeygenMsg::Round3(_)
                )
        );

        if !msg_matches {
            let got = match &msg {
                Xal21KeygenMsg::Round1(_) => "Round1",
                Xal21KeygenMsg::Round2(_) => "Round2",
                Xal21KeygenMsg::Round3(_) => "Round3",
            };
            return Err(TecdsaError::Other(format!(
                "unexpected message {got} in state expecting {expected}"
            )));
        }

        let prev = std::mem::replace(&mut self.state, Xal21KeygenState::Done);

        match (prev, msg) {
            (Xal21KeygenState::P2WaitingForR1, Xal21KeygenMsg::Round1(payload)) => {
                self.handle_p2_waiting_for_r1(from, payload, &mut rng)
            }
            (Xal21KeygenState::P1WaitingForR2 { p1_state }, Xal21KeygenMsg::Round2(payload)) => {
                self.handle_p1_waiting_for_r2(from, payload, p1_state)
            }
            (
                Xal21KeygenState::P2WaitingForR3 {
                    p2_state,
                    p1_r1_msg,
                },
                Xal21KeygenMsg::Round3(payload),
            ) => self.handle_p2_waiting_for_r3(from, payload, p2_state, p1_r1_msg),
            _ => unreachable!(),
        }
    }

    fn drain_outgoing(&mut self) -> Vec<Outgoing<Self::Outbound>> {
        std::mem::take(&mut self.outgoing)
    }

    fn is_done(&self) -> bool {
        matches!(self.state, Xal21KeygenState::Done)
    }

    fn finish(self) -> tecdsa_core::Result<Self::Output> {
        self.output
            .ok_or_else(|| TecdsaError::Other("keygen did not complete".into()))
    }

    fn current_round(&self) -> u16 {
        self.round
    }

    fn ia_report(&self) -> Option<&IaReport> {
        self.ia_report.as_ref()
    }
}
