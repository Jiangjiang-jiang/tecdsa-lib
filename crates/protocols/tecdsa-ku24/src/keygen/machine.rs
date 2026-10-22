// SPDX-License-Identifier: MIT OR Apache-2.0
//! State machine for the one-round PRSS key generation.

use std::collections::BTreeMap;

use elliptic_curve::{
    group::Group, sec1::ModulusSize, Field, FieldBytes, FieldBytesSize, PrimeField,
};
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{state_machine::Outgoing, IaReport, PartyId, Recipient, StateMachine};

use super::{msg::Ku24KeygenMsg, STREAM_KEYGEN};
use crate::{
    committee::Committee,
    error::{Ku24Error, Ku24Result},
    interp::Interp,
    key_share::Ku24KeyShare,
    prss::PrssKeys,
    wire,
};

enum KeygenRound<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Collecting `X_j` broadcasts.
    Round1(BTreeMap<u16, C::ProjectivePoint>),
    Done(Ku24KeyShare<C>),
    Poisoned,
}

/// KU24 key generation state machine (one broadcast round).
///
/// Requires the PRSS setup ([`crate::setup::Ku24SetupMachine`]) to have
/// completed.  `key_id` is the PRSS domain separator for this key: distinct
/// keys **must** use distinct identifiers, otherwise they would be the same key.
pub struct Ku24KeygenMachine<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    committee: Committee,
    interp: Interp<C>,
    secret_share: C::Scalar,
    round: KeygenRound<C>,
    outgoing: Vec<Outgoing<Ku24KeygenMsg>>,
}

impl<C: TecdsaCurve> Ku24KeygenMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// Derive the local key share and queue the `X_j` broadcast.
    ///
    /// # Errors
    /// Fails if the participant set disagrees with the PRSS setup, or if the
    /// derived share is degenerate (statistically impossible).
    pub fn new(
        my_id: PartyId,
        all_parties: Vec<PartyId>,
        prss: &PrssKeys<C>,
        key_id: &[u8; 32],
    ) -> Ku24Result<Self> {
        let committee = Committee::new(my_id, all_parties, prss.threshold())?;
        if committee.n() != prss.n() || committee.my_index() != prss.my_index() {
            return Err(Ku24Error::InvalidPartySet(
                "participant set does not match the PRSS setup".into(),
            ));
        }

        let secret_share = prss.rand(key_id, STREAM_KEYGEN, 1)[0];
        if secret_share == C::Scalar::ZERO {
            return Err(Ku24Error::Other("PRSS produced a zero key share".into()));
        }
        let my_point = C::generator() * secret_share;

        let mut received = BTreeMap::new();
        received.insert(committee.my_index(), my_point);

        let interp = Interp::<C>::new(&committee.indices(), usize::from(committee.degree()));
        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Ku24KeygenMsg::Round1(wire::encode_point::<C>(&my_point)?),
        }];

        let mut machine = Self {
            committee,
            interp,
            secret_share,
            round: KeygenRound::Round1(received),
            outgoing,
        };
        machine.try_finalize()?;
        Ok(machine)
    }

    fn try_finalize(&mut self) -> Ku24Result<()> {
        let KeygenRound::Round1(received) = &self.round else {
            return Ok(());
        };
        if received.len() != usize::from(self.committee.n()) {
            return Ok(());
        }

        let public_shares: Vec<C::ProjectivePoint> =
            (1..=self.committee.n()).map(|i| received[&i]).collect();
        // Interpolating "in the exponent" with a degree-t consistency check over
        // all n points: with an honest majority the t + 1 honest points pin down
        // the sharing polynomial, so any deviation is caught here.
        let public_key =
            self.interp
                .point(&public_shares)
                .ok_or(Ku24Error::InconsistentShares {
                    what: "key shares g^{x_j}",
                    degree: usize::from(self.committee.degree()),
                })?;
        if bool::from(public_key.is_identity()) {
            return Err(Ku24Error::Other(
                "derived public key is the identity".into(),
            ));
        }

        self.round = KeygenRound::Done(Ku24KeyShare {
            party_index: self.committee.my_index(),
            secret_share: self.secret_share,
            public_key,
            public_shares,
            threshold: self.committee.threshold(),
            total: self.committee.n(),
        });
        Ok(())
    }

    fn handle_inner(&mut self, from: PartyId, msg: Ku24KeygenMsg) -> Ku24Result<()> {
        let index = self.committee.sender_index(from)?;
        let KeygenRound::Round1(received) = &mut self.round else {
            return Err(Ku24Error::RoundMismatch {
                expected: 2,
                got: 1,
            });
        };
        let Ku24KeygenMsg::Round1(bytes) = msg;
        if received.contains_key(&index) {
            return Err(Ku24Error::DuplicateMessage {
                round: 1,
                party: from,
            });
        }
        received.insert(index, wire::decode_point::<C>(&bytes)?);
        self.try_finalize()
    }
}

impl<C: TecdsaCurve> StateMachine for Ku24KeygenMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    type Output = Ku24KeyShare<C>;
    type Inbound = Ku24KeygenMsg;
    type Outbound = Ku24KeygenMsg;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        if matches!(self.round, KeygenRound::Poisoned) {
            return Err(Ku24Error::Poisoned.into());
        }
        self.handle_inner(from, msg).map_err(|e| {
            self.round = KeygenRound::Poisoned;
            e.into()
        })
    }

    fn drain_outgoing(&mut self) -> Vec<Outgoing<Self::Outbound>> {
        core::mem::take(&mut self.outgoing)
    }

    fn is_done(&self) -> bool {
        matches!(self.round, KeygenRound::Done(_))
    }

    fn finish(self) -> tecdsa_core::Result<Self::Output> {
        match self.round {
            KeygenRound::Done(share) => Ok(share),
            _ => Err(Ku24Error::NotComplete("keygen").into()),
        }
    }

    fn current_round(&self) -> u16 {
        match self.round {
            KeygenRound::Round1(_) => 1,
            KeygenRound::Done(_) => 2,
            KeygenRound::Poisoned => 0,
        }
    }

    fn ia_report(&self) -> Option<&IaReport> {
        None
    }
}
