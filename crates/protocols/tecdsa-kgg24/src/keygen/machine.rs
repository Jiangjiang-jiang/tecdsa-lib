// SPDX-License-Identifier: MIT OR Apache-2.0
//! StateMachine wrapper for the KGG24 two-party interactive DKG.
//!
//! Wraps the pure functions from [`super::interactive`] into a
//! [`StateMachine`] that exchanges serialized messages between Party1 and
//! Party2.
//!
//! ## Message flow
//!
//! ```text
//! Party2                            Party1
//!   |--- Round1 (commitment) -------->|
//!   |<-- Round2 (X1,C,proofs) --------|
//!   |--- Round3 (decommit X2) ------->|
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
    key_share::{Kgg24Party1KeyShare, Kgg24Party2KeyShare},
    keygen::{
        interactive::{
            party1_finalize_keygen, party1_keygen_round2, party1_keygen_round2_with_dk,
            party1_verify_round3, party2_finalize_keygen, party2_keygen_round1, party2_keygen_round3,
            KeyGenP1Round2Msg, KeyGenP1State, KeyGenP2Round1Msg, KeyGenP2Round3Msg, KeyGenP2State,
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
    /// P1 (server): generates Paillier keys, holds decryption key.
    Party1,
    /// P2 (client): initiates keygen, holds encryption key and ciphertext.
    Party2,
}

// ---------------------------------------------------------------------------
// Combined key share
// ---------------------------------------------------------------------------

/// Combined key share wrapping both party types.
///
/// The variant indicates which role this party played during keygen.
pub enum Kgg24KeyShare<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    Party1(Kgg24Party1KeyShare<C>),
    Party2(Kgg24Party2KeyShare<C>),
}

impl<C: TecdsaCurve> Zeroize for Kgg24KeyShare<C>
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

impl<C: TecdsaCurve> std::fmt::Debug for Kgg24KeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Party1(_) => f.write_str("Kgg24KeyShare::Party1(...)"),
            Self::Party2(_) => f.write_str("Kgg24KeyShare::Party2(...)"),
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
pub enum Kgg24KeygenMsg {
    /// P2 -> P1: commitment to (X2, DLog proof).
    Round1(Vec<u8>),
    /// P1 -> P2: X1, Paillier key, ciphertext C, Pi_GCD, Pi_eq.
    Round2(Vec<u8>),
    /// P2 -> P1: decommitment of (X2, DLog proof).
    Round3(Vec<u8>),
}

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

enum Kgg24KeygenState<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// Party1 initial state: waiting for Round1 from P2.
    P1WaitingForR1,
    /// Party1: received Round1, sent Round2, waiting for Round3 from P2.
    P1WaitingForR3 {
        p1_state: KeyGenP1State<C>,
        p2_r1_msg: KeyGenP2Round1Msg,
    },
    /// Party2: sent Round1, waiting for Round2 from P1.
    P2WaitingForR2 { p2_state: KeyGenP2State<C> },
    /// Terminal state: output has been produced.
    Done,
}

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

/// KGG24 interactive keygen state machine.
///
/// Construct via [`Kgg24KeygenMachine::new`], specifying the role, own party
/// ID, and peer party ID.  For `Party2`, the constructor immediately produces
/// the Round1 message (queued in `outgoing`).  For `Party1`, the machine
/// waits for the Round1 message from `Party2`.
pub struct Kgg24KeygenMachine<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    #[allow(dead_code)]
    role: TwoPartyRole,
    #[allow(dead_code)]
    my_id: PartyId,
    peer_id: PartyId,
    state: Kgg24KeygenState<C>,
    outgoing: Vec<Outgoing<Kgg24KeygenMsg>>,
    output: Option<Kgg24KeyShare<C>>,
    round: u16,
    ia_report: Option<IaReport>,
    /// Optional precomputed Paillier key for P1, injected via
    /// [`Kgg24KeygenMachine::new_with_setup`]. When present, P1 uses it in
    /// round 2 instead of generating a fresh keypair (the keypair is a one-time
    /// setup step, kept out of the DKG round timing).
    precomputed_dk: Option<tecdsa_paillier::DecryptionKey>,
}

impl<C: TecdsaCurve> Kgg24KeygenMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// Create a new keygen state machine.
    ///
    /// - `Party2` role: immediately samples `x2`, creates a commitment, and
    ///   queues the Round1 message.
    /// - `Party1` role: enters the waiting-for-Round1 state.
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

    /// Like [`Kgg24KeygenMachine::new`], but lets the caller inject P1's
    /// **precomputed** Paillier decryption key.
    ///
    /// P1's Paillier keypair is a one-time, message-independent setup step. By
    /// generating it up front and passing it here, callers (e.g. benchmark
    /// harnesses) keep the (multi-second) safe-prime generation out of the
    /// measured DKG rounds. `precomputed_dk` is only consumed by `Party1`
    /// (in round 2); for `Party2` it is ignored.
    ///
    /// # Errors
    ///
    /// Returns an error if `my_id == peer_id`.
    pub fn new_with_setup(
        role: TwoPartyRole,
        my_id: PartyId,
        peer_id: PartyId,
        precomputed_dk: Option<tecdsa_paillier::DecryptionKey>,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Result<Self, TecdsaError> {
        if my_id == peer_id {
            return Err(TecdsaError::Other("my_id and peer_id must differ".into()));
        }

        let (state, outgoing, round) = match role {
            TwoPartyRole::Party2 => {
                let (r1_msg, p2_state) = party2_keygen_round1::<C>(rng);
                let payload = encode_r1::<C>(&r1_msg)?;
                let out = Outgoing {
                    to: Recipient::Party(peer_id),
                    msg: Kgg24KeygenMsg::Round1(payload),
                };
                (Kgg24KeygenState::P2WaitingForR2 { p2_state }, vec![out], 1)
            }
            TwoPartyRole::Party1 => (Kgg24KeygenState::P1WaitingForR1, Vec::new(), 0),
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
            precomputed_dk,
        })
    }

    fn handle_p1_waiting_for_r1(
        &mut self,
        from: PartyId,
        payload: Vec<u8>,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> tecdsa_core::Result<()> {
        self.validate_sender(from)?;

        let p2_r1_msg = decode_r1(&payload)?;

        // Use the precomputed Paillier key if one was injected via
        // `new_with_setup`; otherwise generate a fresh keypair in-round.
        let (r2_msg, p1_state) = match self.precomputed_dk.take() {
            Some(dk) => party1_keygen_round2_with_dk::<C>(dk, rng),
            None => party1_keygen_round2::<C>(rng),
        }
        .map_err(|e| TecdsaError::Other(format!("P1 round2 failed: {e}")))?;

        let payload = encode_r2::<C>(&r2_msg)?;

        self.outgoing.push(Outgoing {
            to: Recipient::Party(self.peer_id),
            msg: Kgg24KeygenMsg::Round2(payload),
        });

        self.state = Kgg24KeygenState::P1WaitingForR3 {
            p1_state,
            p2_r1_msg,
        };
        self.round = 2;
        Ok(())
    }

    fn handle_p1_waiting_for_r3(
        &mut self,
        from: PartyId,
        payload: Vec<u8>,
        p1_state: KeyGenP1State<C>,
        p2_r1_msg: KeyGenP2Round1Msg,
    ) -> tecdsa_core::Result<()> {
        self.validate_sender(from)?;

        let p2_r3_msg: KeyGenP2Round3Msg<C> = decode_r3::<C>(&payload)?;

        if let Err(e) = party1_verify_round3::<C>(&p2_r1_msg, &p2_r3_msg) {
            self.ia_report = Some(IaReport {
                blamed: vec![from],
                reason: AbortReason::InvalidProof {
                    round: 3,
                    party: from,
                },
            });
            return Err(TecdsaError::InvalidProof(format!(
                "P1 verification of P2 round3 failed: {e}"
            )));
        }

        let share = party1_finalize_keygen::<C>(p1_state, &p2_r3_msg.x2_point);
        self.output = Some(Kgg24KeyShare::Party1(share));
        self.state = Kgg24KeygenState::Done;
        self.round = 3;
        Ok(())
    }

    fn handle_p2_waiting_for_r2(
        &mut self,
        from: PartyId,
        payload: Vec<u8>,
        mut p2_state: KeyGenP2State<C>,
    ) -> tecdsa_core::Result<()> {
        self.validate_sender(from)?;

        let p1_r2_msg: KeyGenP1Round2Msg<C> = decode_r2::<C>(&payload)?;

        let p2_r3_msg = match party2_keygen_round3::<C>(&p2_state, &p1_r2_msg) {
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
                    "P2 verification of P1 round2 failed: {e}"
                )));
            }
        };

        let payload = encode_r3::<C>(&p2_r3_msg)?;

        self.outgoing.push(Outgoing {
            to: Recipient::Party(self.peer_id),
            msg: Kgg24KeygenMsg::Round3(payload),
        });

        let share = party2_finalize_keygen::<C>(&p2_state, &p1_r2_msg);
        // Zeroize transient secret scalar before dropping p2_state.
        p2_state.x2.zeroize();
        self.output = Some(Kgg24KeyShare::Party2(share));
        self.state = Kgg24KeygenState::Done;
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

// The `handle` method needs an RNG to call `party1_keygen_round2`, but the
// `StateMachine` trait's `handle` signature does not accept an RNG parameter.
// We use `OsRng` internally, which is the standard choice for production.

impl<C: TecdsaCurve> StateMachine for Kgg24KeygenMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    type Output = Kgg24KeyShare<C>;
    type Inbound = Kgg24KeygenMsg;
    type Outbound = Kgg24KeygenMsg;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        let mut rng = rand_core::OsRng;

        // Validate the message variant matches the expected state before
        // consuming it, so we can return a clean error on mismatch.
        let expected = match &self.state {
            Kgg24KeygenState::P1WaitingForR1 => "Round1",
            Kgg24KeygenState::P1WaitingForR3 { .. } => "Round3",
            Kgg24KeygenState::P2WaitingForR2 { .. } => "Round2",
            Kgg24KeygenState::Done => {
                return Err(TecdsaError::Other("keygen already completed".into()));
            }
        };

        let msg_matches = matches!(
            (&self.state, &msg),
            (Kgg24KeygenState::P1WaitingForR1, Kgg24KeygenMsg::Round1(_))
                | (
                    Kgg24KeygenState::P1WaitingForR3 { .. },
                    Kgg24KeygenMsg::Round3(_)
                )
                | (
                    Kgg24KeygenState::P2WaitingForR2 { .. },
                    Kgg24KeygenMsg::Round2(_)
                )
        );

        if !msg_matches {
            let got = match &msg {
                Kgg24KeygenMsg::Round1(_) => "Round1",
                Kgg24KeygenMsg::Round2(_) => "Round2",
                Kgg24KeygenMsg::Round3(_) => "Round3",
            };
            return Err(TecdsaError::Other(format!(
                "unexpected message {got} in state expecting {expected}"
            )));
        }

        // Take ownership of the state. Any error from here on means the
        // machine is dead (proof failure = abort, serialization error =
        // unrecoverable).
        let prev = std::mem::replace(&mut self.state, Kgg24KeygenState::Done);

        match (prev, msg) {
            (Kgg24KeygenState::P1WaitingForR1, Kgg24KeygenMsg::Round1(payload)) => {
                self.handle_p1_waiting_for_r1(from, payload, &mut rng)
            }
            (
                Kgg24KeygenState::P1WaitingForR3 {
                    p1_state,
                    p2_r1_msg,
                },
                Kgg24KeygenMsg::Round3(payload),
            ) => self.handle_p1_waiting_for_r3(from, payload, p1_state, p2_r1_msg),
            (Kgg24KeygenState::P2WaitingForR2 { p2_state }, Kgg24KeygenMsg::Round2(payload)) => {
                self.handle_p2_waiting_for_r2(from, payload, p2_state)
            }
            _ => unreachable!(),
        }
    }

    fn drain_outgoing(&mut self) -> Vec<Outgoing<Self::Outbound>> {
        std::mem::take(&mut self.outgoing)
    }

    fn is_done(&self) -> bool {
        matches!(self.state, Kgg24KeygenState::Done)
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
