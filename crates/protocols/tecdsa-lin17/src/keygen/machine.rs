use elliptic_curve::{sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField};
use serde::{Deserialize, Serialize};
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_paillier::zk::pdl::{
    prover_step1, prover_step2, verifier_finalize, verifier_step1, verifier_step2, PdlProverMsg1,
    PdlProverMsg2, PdlProverState, PdlVerifierMsg1, PdlVerifierState,
};
use tecdsa_protocol::{
    state_machine::Outgoing, AbortReason, IaReport, PartyId, Recipient, StateMachine,
};
use zeroize::Zeroize;

use crate::{
    key_share::{Lin17Party1KeyShare, Lin17Party2KeyShare},
    keygen::{
        interactive::{
            party1_finalize_keygen, party1_keygen_round1, party1_keygen_round3_with_dk,
            party1_keygen_round3_with_precomputed_dk, party2_finalize_keygen, party2_keygen_round2,
            party2_verify_round3, KeyGenP1Round1Msg, KeyGenP1Round3Msg, KeyGenP1State,
            KeyGenP2Round2Msg, KeyGenP2State,
        },
        wire::{
            decode_r1, decode_r2, decode_r3, decode_r4, decode_r5, decode_r6, decode_r7, encode_r1,
            encode_r2, encode_r3, encode_r4, encode_r5, encode_r6, encode_r7,
        },
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TwoPartyRole {
    Party1,
    Party2,
}

pub enum Lin17KeyShare<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    Party1(Lin17Party1KeyShare<C>),
    Party2(Lin17Party2KeyShare<C>),
}

impl<C: TecdsaCurve> Zeroize for Lin17KeyShare<C>
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

impl<C: TecdsaCurve> std::fmt::Debug for Lin17KeyShare<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Party1(_) => f.write_str("Lin17KeyShare::Party1(...)"),
            Self::Party2(_) => f.write_str("Lin17KeyShare::Party2(...)"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Lin17KeygenMsg {
    Round1(Vec<u8>),
    Round2(Vec<u8>),
    Round3(Vec<u8>),
    Round4(Vec<u8>),
    Round5(Vec<u8>),
    Round6(Vec<u8>),
    Round7(Vec<u8>),
}

enum Lin17KeygenState<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    P2WaitingForR1 {
        p2_state: KeyGenP2State<C>,
        p2_r2_msg: KeyGenP2Round2Msg<C>,
    },
    P1WaitingForR2 { p1_state: KeyGenP1State<C> },
    P2WaitingForR3 {
        p2_state: KeyGenP2State<C>,
        p1_r1_msg: KeyGenP1Round1Msg,
    },
    P1WaitingForR4 {
        p1_state: KeyGenP1State<C>,
        dk: tecdsa_paillier::DecryptionKey,
        ek: tecdsa_paillier::EncryptionKey,
        c_key: tecdsa_paillier::Ciphertext,
        p2_q2: C::ProjectivePoint,
    },
    P2WaitingForR5 {
        p2_state: KeyGenP2State<C>,
        p1_q1: C::ProjectivePoint,
        ek: tecdsa_paillier::EncryptionKey,
        c_key: tecdsa_paillier::Ciphertext,
        pdl_v_state: PdlVerifierState<C>,
    },
    P1WaitingForR6 {
        p1_state: KeyGenP1State<C>,
        dk: tecdsa_paillier::DecryptionKey,
        p2_q2: C::ProjectivePoint,
        pdl_v_msg1: PdlVerifierMsg1,
        pdl_p_state: PdlProverState<C>,
    },
    P2WaitingForR7 {
        p2_state: KeyGenP2State<C>,
        p1_q1: C::ProjectivePoint,
        ek: tecdsa_paillier::EncryptionKey,
        c_key: tecdsa_paillier::Ciphertext,
        pdl_v_state: PdlVerifierState<C>,
        pdl_p_msg1: PdlProverMsg1,
    },
    Done,
}

pub struct Lin17KeygenMachine<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    #[allow(dead_code)]
    role: TwoPartyRole,
    #[allow(dead_code)]
    my_id: PartyId,
    peer_id: PartyId,
    state: Lin17KeygenState<C>,
    outgoing: Vec<Outgoing<Lin17KeygenMsg>>,
    output: Option<Lin17KeyShare<C>>,
    round: u16,
    ia_report: Option<IaReport>,
    precomputed_dk: Option<tecdsa_paillier::DecryptionKey>,
}

impl<C: TecdsaCurve> Lin17KeygenMachine<C>
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
            TwoPartyRole::Party1 => {
                let (r1_msg, p1_state) = party1_keygen_round1::<C>(rng);
                let payload = encode_r1(&r1_msg)?;
                let out = Outgoing {
                    to: Recipient::Party(peer_id),
                    msg: Lin17KeygenMsg::Round1(payload),
                };
                (Lin17KeygenState::P1WaitingForR2 { p1_state }, vec![out], 1)
            }
            TwoPartyRole::Party2 => {
                let (p2_r2_msg, p2_state) = party2_keygen_round2::<C>(rng);
                (
                    Lin17KeygenState::P2WaitingForR1 {
                        p2_state,
                        p2_r2_msg,
                    },
                    Vec::new(),
                    0,
                )
            }
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

    fn validate_sender(&self, from: PartyId) -> tecdsa_core::Result<()> {
        if from != self.peer_id {
            return Err(TecdsaError::Other(format!(
                "unexpected sender {from}, expected {}",
                self.peer_id
            )));
        }
        Ok(())
    }

    fn handle_p2_waiting_for_r1(
        &mut self,
        from: PartyId,
        payload: Vec<u8>,
        p2_state: KeyGenP2State<C>,
        p2_r2_msg: KeyGenP2Round2Msg<C>,
    ) -> tecdsa_core::Result<()> {
        self.validate_sender(from)?;
        let p1_r1_msg = decode_r1(&payload)?;

        let r2_payload = encode_r2::<C>(&p2_r2_msg)?;
        self.outgoing.push(Outgoing {
            to: Recipient::Party(self.peer_id),
            msg: Lin17KeygenMsg::Round2(r2_payload),
        });

        self.state = Lin17KeygenState::P2WaitingForR3 {
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
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> tecdsa_core::Result<()> {
        self.validate_sender(from)?;
        let p2_r2_msg: KeyGenP2Round2Msg<C> = decode_r2::<C>(&payload)?;

        let (p1_r3_msg, dk) = match self.precomputed_dk.take() {
            Some(dk) => {
                party1_keygen_round3_with_precomputed_dk::<C>(&p1_state, &p2_r2_msg, dk, rng)
            }
            None => party1_keygen_round3_with_dk::<C>(&p1_state, &p2_r2_msg, rng),
        }
        .map_err(|e| TecdsaError::Other(format!("P1 round3 failed: {e}")))?;

        let ek = p1_r3_msg.ek.clone();
        let c_key = p1_r3_msg.c_key.clone();
        let p2_q2 = p2_r2_msg.q2;

        let r3_payload = encode_r3::<C>(&p1_r3_msg)?;
        self.outgoing.push(Outgoing {
            to: Recipient::Party(self.peer_id),
            msg: Lin17KeygenMsg::Round3(r3_payload),
        });

        self.state = Lin17KeygenState::P1WaitingForR4 {
            p1_state,
            dk,
            ek,
            c_key,
            p2_q2,
        };
        self.round = 3;
        Ok(())
    }

    fn handle_p2_waiting_for_r3(
        &mut self,
        from: PartyId,
        payload: Vec<u8>,
        p2_state: KeyGenP2State<C>,
        p1_r1_msg: KeyGenP1Round1Msg,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> tecdsa_core::Result<()> {
        self.validate_sender(from)?;
        let p1_r3_msg: KeyGenP1Round3Msg<C> = decode_r3::<C>(&payload)?;

        if let Err(e) = party2_verify_round3::<C>(&p2_state, &p1_r1_msg, &p1_r3_msg) {
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

        let p1_q1 = p1_r3_msg.q1;
        let ek = p1_r3_msg.ek.clone();
        let c_key = p1_r3_msg.c_key.clone();

        let (pdl_v_msg1, pdl_v_state) = verifier_step1::<C>(&ek, &c_key, &p1_q1, rng)
            .map_err(|e| TecdsaError::Other(format!("PDL verifier step1 failed: {e}")))?;

        let r4_payload = encode_r4(&pdl_v_msg1)?;
        self.outgoing.push(Outgoing {
            to: Recipient::Party(self.peer_id),
            msg: Lin17KeygenMsg::Round4(r4_payload),
        });

        self.state = Lin17KeygenState::P2WaitingForR5 {
            p2_state,
            p1_q1,
            ek,
            c_key,
            pdl_v_state,
        };
        self.round = 4;
        Ok(())
    }

    fn handle_p1_waiting_for_r4(
        &mut self,
        from: PartyId,
        payload: Vec<u8>,
        p1_state: KeyGenP1State<C>,
        dk: tecdsa_paillier::DecryptionKey,
        ek: tecdsa_paillier::EncryptionKey,
        c_key: tecdsa_paillier::Ciphertext,
        p2_q2: C::ProjectivePoint,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> tecdsa_core::Result<()> {
        self.validate_sender(from)?;
        let _ = ek;
        let _ = c_key;
        let pdl_v_msg1 = decode_r4(&payload)?;

        let (pdl_p_msg1, pdl_p_state) = prover_step1::<C>(&dk, &pdl_v_msg1, rng)
            .map_err(|e| TecdsaError::Other(format!("PDL prover step1 failed: {e}")))?;

        let r5_payload = encode_r5(&pdl_p_msg1)?;
        self.outgoing.push(Outgoing {
            to: Recipient::Party(self.peer_id),
            msg: Lin17KeygenMsg::Round5(r5_payload),
        });

        self.state = Lin17KeygenState::P1WaitingForR6 {
            p1_state,
            dk,
            p2_q2,
            pdl_v_msg1,
            pdl_p_state,
        };
        self.round = 5;
        Ok(())
    }

    fn handle_p2_waiting_for_r5(
        &mut self,
        from: PartyId,
        payload: Vec<u8>,
        p2_state: KeyGenP2State<C>,
        p1_q1: C::ProjectivePoint,
        ek: tecdsa_paillier::EncryptionKey,
        c_key: tecdsa_paillier::Ciphertext,
        pdl_v_state: PdlVerifierState<C>,
    ) -> tecdsa_core::Result<()> {
        self.validate_sender(from)?;
        let pdl_p_msg1 = decode_r5(&payload)?;

        let pdl_v_msg2 = verifier_step2::<C>(&pdl_v_state);

        let r6_payload = encode_r6(&pdl_v_msg2)?;
        self.outgoing.push(Outgoing {
            to: Recipient::Party(self.peer_id),
            msg: Lin17KeygenMsg::Round6(r6_payload),
        });

        self.state = Lin17KeygenState::P2WaitingForR7 {
            p2_state,
            p1_q1,
            ek,
            c_key,
            pdl_v_state,
            pdl_p_msg1,
        };
        self.round = 6;
        Ok(())
    }

    fn handle_p1_waiting_for_r6(
        &mut self,
        from: PartyId,
        payload: Vec<u8>,
        mut p1_state: KeyGenP1State<C>,
        dk: tecdsa_paillier::DecryptionKey,
        p2_q2: C::ProjectivePoint,
        pdl_v_msg1: PdlVerifierMsg1,
        pdl_p_state: PdlProverState<C>,
    ) -> tecdsa_core::Result<()> {
        self.validate_sender(from)?;
        let pdl_v_msg2 = decode_r6(&payload)?;

        let pdl_p_msg2 = prover_step2::<C>(&p1_state.x1, &pdl_p_state, &pdl_v_msg1, &pdl_v_msg2)
            .map_err(|e| {
                self.ia_report = Some(IaReport {
                    blamed: vec![from],
                    reason: AbortReason::InvalidProof {
                        round: 6,
                        party: from,
                    },
                });
                TecdsaError::InvalidProof(format!("P1 PDL prover step2 verification failed: {e}"))
            })?;

        let r7_payload = encode_r7::<C>(&pdl_p_msg2)?;
        self.outgoing.push(Outgoing {
            to: Recipient::Party(self.peer_id),
            msg: Lin17KeygenMsg::Round7(r7_payload),
        });

        let share = party1_finalize_keygen::<C>(&p1_state, &p2_q2, dk);
        p1_state.x1.zeroize();
        self.output = Some(Lin17KeyShare::Party1(share));
        self.state = Lin17KeygenState::Done;
        self.round = 7;
        Ok(())
    }

    fn handle_p2_waiting_for_r7(
        &mut self,
        from: PartyId,
        payload: Vec<u8>,
        mut p2_state: KeyGenP2State<C>,
        p1_q1: C::ProjectivePoint,
        ek: tecdsa_paillier::EncryptionKey,
        c_key: tecdsa_paillier::Ciphertext,
        pdl_v_state: PdlVerifierState<C>,
        pdl_p_msg1: PdlProverMsg1,
    ) -> tecdsa_core::Result<()> {
        self.validate_sender(from)?;
        let pdl_p_msg2: PdlProverMsg2<C> = decode_r7::<C>(&payload)?;

        if let Err(e) = verifier_finalize::<C>(&pdl_v_state, &pdl_p_msg1, &pdl_p_msg2) {
            self.ia_report = Some(IaReport {
                blamed: vec![from],
                reason: AbortReason::InvalidProof {
                    round: 7,
                    party: from,
                },
            });
            return Err(TecdsaError::InvalidProof(format!(
                "P2 PDL verifier finalize failed: {e}"
            )));
        }

        let share = party2_finalize_keygen::<C>(&p2_state, &p1_q1, c_key, ek);
        p2_state.x2.zeroize();
        self.output = Some(Lin17KeyShare::Party2(share));
        self.state = Lin17KeygenState::Done;
        self.round = 7;
        Ok(())
    }
}

impl<C: TecdsaCurve> StateMachine for Lin17KeygenMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    type Output = Lin17KeyShare<C>;
    type Inbound = Lin17KeygenMsg;
    type Outbound = Lin17KeygenMsg;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        let mut rng = rand_core::OsRng;

        let expected = match &self.state {
            Lin17KeygenState::P1WaitingForR2 { .. } => "Round2",
            Lin17KeygenState::P2WaitingForR1 { .. } => "Round1",
            Lin17KeygenState::P2WaitingForR3 { .. } => "Round3",
            Lin17KeygenState::P1WaitingForR4 { .. } => "Round4",
            Lin17KeygenState::P2WaitingForR5 { .. } => "Round5",
            Lin17KeygenState::P1WaitingForR6 { .. } => "Round6",
            Lin17KeygenState::P2WaitingForR7 { .. } => "Round7",
            Lin17KeygenState::Done => {
                return Err(TecdsaError::Other("keygen already completed".into()));
            }
        };

        let msg_matches = matches!(
            (&self.state, &msg),
            (
                Lin17KeygenState::P2WaitingForR1 { .. },
                Lin17KeygenMsg::Round1(_)
            ) | (
                Lin17KeygenState::P1WaitingForR2 { .. },
                Lin17KeygenMsg::Round2(_)
            ) | (
                Lin17KeygenState::P2WaitingForR3 { .. },
                Lin17KeygenMsg::Round3(_)
            ) | (
                Lin17KeygenState::P1WaitingForR4 { .. },
                Lin17KeygenMsg::Round4(_)
            ) | (
                Lin17KeygenState::P2WaitingForR5 { .. },
                Lin17KeygenMsg::Round5(_)
            ) | (
                Lin17KeygenState::P1WaitingForR6 { .. },
                Lin17KeygenMsg::Round6(_)
            ) | (
                Lin17KeygenState::P2WaitingForR7 { .. },
                Lin17KeygenMsg::Round7(_)
            )
        );

        if !msg_matches {
            let got = match &msg {
                Lin17KeygenMsg::Round1(_) => "Round1",
                Lin17KeygenMsg::Round2(_) => "Round2",
                Lin17KeygenMsg::Round3(_) => "Round3",
                Lin17KeygenMsg::Round4(_) => "Round4",
                Lin17KeygenMsg::Round5(_) => "Round5",
                Lin17KeygenMsg::Round6(_) => "Round6",
                Lin17KeygenMsg::Round7(_) => "Round7",
            };
            return Err(TecdsaError::Other(format!(
                "unexpected message {got} in state expecting {expected}"
            )));
        }

        let prev = std::mem::replace(&mut self.state, Lin17KeygenState::Done);

        match (prev, msg) {
            (
                Lin17KeygenState::P2WaitingForR1 {
                    p2_state,
                    p2_r2_msg,
                },
                Lin17KeygenMsg::Round1(payload),
            ) => self.handle_p2_waiting_for_r1(from, payload, p2_state, p2_r2_msg),

            (Lin17KeygenState::P1WaitingForR2 { p1_state }, Lin17KeygenMsg::Round2(payload)) => {
                self.handle_p1_waiting_for_r2(from, payload, p1_state, &mut rng)
            }

            (
                Lin17KeygenState::P2WaitingForR3 {
                    p2_state,
                    p1_r1_msg,
                },
                Lin17KeygenMsg::Round3(payload),
            ) => self.handle_p2_waiting_for_r3(from, payload, p2_state, p1_r1_msg, &mut rng),

            (
                Lin17KeygenState::P1WaitingForR4 {
                    p1_state,
                    dk,
                    ek,
                    c_key,
                    p2_q2,
                },
                Lin17KeygenMsg::Round4(payload),
            ) => self
                .handle_p1_waiting_for_r4(from, payload, p1_state, dk, ek, c_key, p2_q2, &mut rng),

            (
                Lin17KeygenState::P2WaitingForR5 {
                    p2_state,
                    p1_q1,
                    ek,
                    c_key,
                    pdl_v_state,
                },
                Lin17KeygenMsg::Round5(payload),
            ) => self.handle_p2_waiting_for_r5(
                from,
                payload,
                p2_state,
                p1_q1,
                ek,
                c_key,
                pdl_v_state,
            ),

            (
                Lin17KeygenState::P1WaitingForR6 {
                    p1_state,
                    dk,
                    p2_q2,
                    pdl_v_msg1,
                    pdl_p_state,
                },
                Lin17KeygenMsg::Round6(payload),
            ) => self.handle_p1_waiting_for_r6(
                from,
                payload,
                p1_state,
                dk,
                p2_q2,
                pdl_v_msg1,
                pdl_p_state,
            ),

            (
                Lin17KeygenState::P2WaitingForR7 {
                    p2_state,
                    p1_q1,
                    ek,
                    c_key,
                    pdl_v_state,
                    pdl_p_msg1,
                },
                Lin17KeygenMsg::Round7(payload),
            ) => self.handle_p2_waiting_for_r7(
                from,
                payload,
                p2_state,
                p1_q1,
                ek,
                c_key,
                pdl_v_state,
                pdl_p_msg1,
            ),

            _ => unreachable!(),
        }
    }

    fn drain_outgoing(&mut self) -> Vec<Outgoing<Self::Outbound>> {
        std::mem::take(&mut self.outgoing)
    }

    fn is_done(&self) -> bool {
        matches!(self.state, Lin17KeygenState::Done)
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
