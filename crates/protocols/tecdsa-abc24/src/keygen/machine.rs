// SPDX-License-Identifier: MIT OR Apache-2.0
//! StateMachine wrapper for the ABC+24 two-party interactive DKG.
//!
//! Wraps the pure functions from [`super::interactive`] into a
//! [`StateMachine`] that exchanges serialized messages between Server and
//! Client.
//!
//! ## Message flow
//!
//! ```text
//! Server (Party1)                   Client (Party2)
//!   |--- Step1 (commitment,ek,pi) --->|
//!   |<-- Step2 (X1, dlog_proof) ------|
//!   |--- Step3 (X2, nonce, E) ------->|
//!   done                              done (verify + finalize)
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
    key_share::{Abc24ClientKeyShare, Abc24ServerKeyShare},
    keygen::{
        interactive::{
            client_finalize_keygen, client_keygen_step2, client_verify_step3,
            server_finalize_keygen, server_keygen_step1, server_keygen_step1_with_dk,
            server_keygen_step3, ClientStep2Msg, ClientStep2State, ServerStep1State,
            ServerStep3Msg,
        },
        wire::{
            decode_step1, decode_step2, decode_step3, encode_step1, encode_step2, encode_step3,
        },
    },
};

// ---------------------------------------------------------------------------
// Two-party role
// ---------------------------------------------------------------------------

/// Role in the two-party protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TwoPartyRole {
    /// Server (Party1): generates Paillier keys, holds decryption key.
    Party1,
    /// Client (Party2): initiates verification, holds encryption key and ciphertext.
    Party2,
}

// ---------------------------------------------------------------------------
// Combined key share
// ---------------------------------------------------------------------------

/// Combined key share wrapping both party types.
///
/// The variant indicates which role this party played during keygen.
pub enum Abc24KeyShare<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    Party1(Abc24ServerKeyShare<C>),
    Party2(Abc24ClientKeyShare<C>),
}

impl<C: TecdsaCurve> Zeroize for Abc24KeyShare<C>
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

impl<C: TecdsaCurve> std::fmt::Debug for Abc24KeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Party1(_) => f.write_str("Abc24KeyShare::Party1(...)"),
            Self::Party2(_) => f.write_str("Abc24KeyShare::Party2(...)"),
        }
    }
}

// ---------------------------------------------------------------------------
// Wire message envelope
// ---------------------------------------------------------------------------

/// Envelope message for the keygen state machine.
///
/// Each variant carries the serialized payload for the corresponding step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Abc24KeygenMsg {
    /// Server -> Client: commitment to X_2, Paillier key, correct key proof.
    Step1(Vec<u8>),
    /// Client -> Server: X_1, DLog proof.
    Step2(Vec<u8>),
    /// Server -> Client: X_2, decommitment nonce, enc(x_2).
    Step3(Vec<u8>),
}

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

enum Abc24KeygenState<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// Server initial state: generates Step1 message, waiting for Step2.
    ServerWaitingForStep2 { server_state: ServerStep1State<C> },
    /// Client initial state: waiting for Step1 from Server.
    ClientWaitingForStep1,
    /// Client: received Step1, sent Step2, waiting for Step3.
    ClientWaitingForStep3 { client_state: ClientStep2State<C> },
    /// Terminal state: output has been produced.
    Done,
}

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

/// ABC+24 interactive keygen state machine.
///
/// Construct via [`Abc24KeygenMachine::new`], specifying the role, own party
/// ID, and peer party ID. For `Party1` (Server), the constructor immediately
/// produces the Step1 message (queued in `outgoing`). For `Party2` (Client),
/// the machine waits for the Step1 message from Server.
pub struct Abc24KeygenMachine<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    #[allow(dead_code)]
    role: TwoPartyRole,
    #[allow(dead_code)]
    my_id: PartyId,
    peer_id: PartyId,
    state: Abc24KeygenState<C>,
    outgoing: Vec<Outgoing<Abc24KeygenMsg>>,
    output: Option<Abc24KeyShare<C>>,
    round: u16,
    ia_report: Option<IaReport>,
}

impl<C: TecdsaCurve> Abc24KeygenMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// Create a new keygen state machine.
    ///
    /// - `Party1` (Server) role: immediately samples keys, creates commitment,
    ///   and queues the Step1 message.
    /// - `Party2` (Client) role: enters the waiting-for-Step1 state.
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

    /// Like [`Abc24KeygenMachine::new`], but lets the caller inject the Server's
    /// **precomputed** Paillier decryption key.
    ///
    /// The server's Paillier keypair is part of the one-time `SetupData` it
    /// publishes non-interactively; it is message-independent. By generating it
    /// up front and passing it here, callers (e.g. benchmark harnesses) keep the
    /// (multi-second) safe-prime generation out of the measured DKG steps.
    /// `precomputed_dk` is only consumed by `Party1` (the Server, in step 1);
    /// for `Party2` (the Client) it is ignored.
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
            TwoPartyRole::Party1 => {
                let (s1_msg, s1_state) = match precomputed_dk {
                    Some(dk) => server_keygen_step1_with_dk::<C>(dk, rng),
                    None => server_keygen_step1::<C>(rng),
                };
                let payload = encode_step1(&s1_msg)?;
                let out = Outgoing {
                    to: Recipient::Party(peer_id),
                    msg: Abc24KeygenMsg::Step1(payload),
                };
                (
                    Abc24KeygenState::ServerWaitingForStep2 {
                        server_state: s1_state,
                    },
                    vec![out],
                    1,
                )
            }
            TwoPartyRole::Party2 => (Abc24KeygenState::ClientWaitingForStep1, Vec::new(), 0),
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
        })
    }

    fn handle_client_waiting_for_step1(
        &mut self,
        from: PartyId,
        payload: Vec<u8>,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> tecdsa_core::Result<()> {
        self.validate_sender(from)?;

        let s1_msg = decode_step1(&payload)?;

        let (c2_msg, c2_state) = client_keygen_step2::<C>(&s1_msg, rng).map_err(|e| {
            self.ia_report = Some(IaReport {
                blamed: vec![from],
                reason: AbortReason::InvalidProof {
                    round: 1,
                    party: from,
                },
            });
            TecdsaError::InvalidProof(format!("Client verification of server Step1 failed: {e}"))
        })?;

        let payload = encode_step2::<C>(&c2_msg)?;

        self.outgoing.push(Outgoing {
            to: Recipient::Party(self.peer_id),
            msg: Abc24KeygenMsg::Step2(payload),
        });

        self.state = Abc24KeygenState::ClientWaitingForStep3 {
            client_state: c2_state,
        };
        self.round = 2;
        Ok(())
    }

    fn handle_server_waiting_for_step2(
        &mut self,
        from: PartyId,
        payload: Vec<u8>,
        mut server_state: ServerStep1State<C>,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> tecdsa_core::Result<()> {
        self.validate_sender(from)?;

        let c2_msg: ClientStep2Msg<C> = decode_step2::<C>(&payload)?;

        let (s3_msg, mut s3_state) = server_keygen_step3::<C>(&server_state, &c2_msg, rng)
            .map_err(|e| {
                self.ia_report = Some(IaReport {
                    blamed: vec![from],
                    reason: AbortReason::InvalidProof {
                        round: 2,
                        party: from,
                    },
                });
                TecdsaError::InvalidProof(format!(
                    "Server verification of client Step2 failed: {e}"
                ))
            })?;

        let payload = encode_step3::<C>(&s3_msg)?;

        self.outgoing.push(Outgoing {
            to: Recipient::Party(self.peer_id),
            msg: Abc24KeygenMsg::Step3(payload),
        });

        let share = server_finalize_keygen::<C>(&s3_state);
        // Zeroize transient secret scalars before dropping state objects.
        server_state.x2.zeroize();
        s3_state.x2.zeroize();
        self.output = Some(Abc24KeyShare::Party1(share));
        self.state = Abc24KeygenState::Done;
        self.round = 3;
        Ok(())
    }

    fn handle_client_waiting_for_step3(
        &mut self,
        from: PartyId,
        payload: Vec<u8>,
        mut client_state: ClientStep2State<C>,
    ) -> tecdsa_core::Result<()> {
        self.validate_sender(from)?;

        let s3_msg: ServerStep3Msg<C> = decode_step3::<C>(&payload)?;

        if let Err(e) = client_verify_step3::<C>(&client_state, &s3_msg) {
            self.ia_report = Some(IaReport {
                blamed: vec![from],
                reason: AbortReason::InvalidProof {
                    round: 3,
                    party: from,
                },
            });
            return Err(TecdsaError::InvalidProof(format!(
                "Client verification of server Step3 failed: {e}"
            )));
        }

        let share = client_finalize_keygen::<C>(&client_state, &s3_msg);
        // Zeroize transient secret scalar before dropping client_state.
        client_state.x1.zeroize();
        self.output = Some(Abc24KeyShare::Party2(share));
        self.state = Abc24KeygenState::Done;
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

impl<C: TecdsaCurve> StateMachine for Abc24KeygenMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    type Output = Abc24KeyShare<C>;
    type Inbound = Abc24KeygenMsg;
    type Outbound = Abc24KeygenMsg;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        let mut rng = rand_core::OsRng;

        let expected = match &self.state {
            Abc24KeygenState::ClientWaitingForStep1 => "Step1",
            Abc24KeygenState::ServerWaitingForStep2 { .. } => "Step2",
            Abc24KeygenState::ClientWaitingForStep3 { .. } => "Step3",
            Abc24KeygenState::Done => {
                return Err(TecdsaError::Other("keygen already completed".into()));
            }
        };

        let msg_matches = matches!(
            (&self.state, &msg),
            (
                Abc24KeygenState::ClientWaitingForStep1,
                Abc24KeygenMsg::Step1(_)
            ) | (
                Abc24KeygenState::ServerWaitingForStep2 { .. },
                Abc24KeygenMsg::Step2(_)
            ) | (
                Abc24KeygenState::ClientWaitingForStep3 { .. },
                Abc24KeygenMsg::Step3(_)
            )
        );

        if !msg_matches {
            let got = match &msg {
                Abc24KeygenMsg::Step1(_) => "Step1",
                Abc24KeygenMsg::Step2(_) => "Step2",
                Abc24KeygenMsg::Step3(_) => "Step3",
            };
            return Err(TecdsaError::Other(format!(
                "unexpected message {got} in state expecting {expected}"
            )));
        }

        let prev = std::mem::replace(&mut self.state, Abc24KeygenState::Done);

        match (prev, msg) {
            (Abc24KeygenState::ClientWaitingForStep1, Abc24KeygenMsg::Step1(payload)) => {
                self.handle_client_waiting_for_step1(from, payload, &mut rng)
            }
            (
                Abc24KeygenState::ServerWaitingForStep2 { server_state },
                Abc24KeygenMsg::Step2(payload),
            ) => self.handle_server_waiting_for_step2(from, payload, server_state, &mut rng),
            (
                Abc24KeygenState::ClientWaitingForStep3 { client_state },
                Abc24KeygenMsg::Step3(payload),
            ) => self.handle_client_waiting_for_step3(from, payload, client_state),
            _ => unreachable!(),
        }
    }

    fn drain_outgoing(&mut self) -> Vec<Outgoing<Self::Outbound>> {
        std::mem::take(&mut self.outgoing)
    }

    fn is_done(&self) -> bool {
        matches!(self.state, Abc24KeygenState::Done)
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
