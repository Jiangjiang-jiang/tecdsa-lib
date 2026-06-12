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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TwoPartyRole {
    Party1,
    Party2,
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Kgg24KeygenMsg {
    Round1(Vec<u8>),
    Round2(Vec<u8>),
    Round3(Vec<u8>),
}

enum Kgg24KeygenState<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    P1WaitingForR1,
    P1WaitingForR3 {
        p1_state: KeyGenP1State<C>,
        p2_r1_msg: KeyGenP2Round1Msg,
    },
    P2WaitingForR2 { p2_state: KeyGenP2State<C> },
    Done,
}

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
    precomputed_dk: Option<tecdsa_paillier::DecryptionKey>,
}

impl<C: TecdsaCurve> Kgg24KeygenMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    pub fn new(
        role: TwoPartyRole,
        my_id: PartyId,
        peer_id: PartyId,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Result<Self, TecdsaError> {
        Self::new_with_setup(role, my_id, peer_id, None, rng)
    }

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
