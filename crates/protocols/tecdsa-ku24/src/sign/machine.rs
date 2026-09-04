// SPDX-License-Identifier: MIT OR Apache-2.0
//! One-round state machine for KU24 online signing.

use std::collections::BTreeMap;

use elliptic_curve::{
    ops::LinearCombination, sec1::ModulusSize, Field, FieldBytes, FieldBytesSize, PrimeField,
};
use tecdsa_curve::{TecdsaCurve, conv::scalar_to_bytes};
use tecdsa_protocol::{
    ecdsa::{low_s_normalize, verify_ecdsa, DataToSign, Signature},
    state_machine::Outgoing,
    IaReport, PartyId, Recipient, StateMachine,
};

use super::{msg::Ku24SignMsg, partial_signature};
use crate::{
    committee::Committee,
    error::{Ku24Error, Ku24Result},
    interp::Interp,
    key_share::Ku24KeyShare,
    presign::Ku24Presignature,
    wire,
};

enum SignRound<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    Round1(BTreeMap<u16, C::Scalar>),
    Done(Signature<C>),
    Poisoned,
}

/// KU24 online signing state machine (one broadcast round).
///
/// Consumes one presignature; the caller is responsible for never reusing it.
pub struct Ku24SignMachine<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    committee: Committee,
    interp_2t: Interp<C>,
    r: C::Scalar,
    public_key: C::ProjectivePoint,
    digest: DataToSign<C>,
    round: SignRound<C>,
    outgoing: Vec<Outgoing<Ku24SignMsg>>,
}

impl<C: TecdsaCurve> Ku24SignMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
    C::ProjectivePoint: LinearCombination<[(C::ProjectivePoint, C::Scalar); 2]>,
{
    /// Compute the local partial signature and queue it for broadcast.
    ///
    /// The presignature is consumed by value to discourage reuse.
    ///
    /// # Errors
    /// Fails if the presignature and the key share disagree on the committee,
    /// or if the participant set is malformed.
    pub fn new(
        my_id: PartyId,
        all_parties: Vec<PartyId>,
        key_share: &Ku24KeyShare<C>,
        presignature: Ku24Presignature<C>,
        digest: DataToSign<C>,
    ) -> Ku24Result<Self> {
        let committee = Committee::new(my_id, all_parties, key_share.threshold)?;
        if key_share.total != committee.n() || key_share.party_index != committee.my_index() {
            return Err(Ku24Error::InvalidPartySet(
                "key share does not match the participant set".into(),
            ));
        }
        if presignature.total != key_share.total
            || presignature.threshold != key_share.threshold
            || presignature.party_index != key_share.party_index
        {
            return Err(Ku24Error::InvalidPartySet(
                "presignature does not match the key share".into(),
            ));
        }

        let s_share =
            partial_signature::<C>(&presignature, &key_share.secret_share, digest.digest());
        let r = presignature.r;

        // Reconstruction is over a degree-2t polynomial, so all n shares are
        // needed and there is no redundancy left for a consistency check.
        let interp_2t = Interp::<C>::new(&committee.indices(), 2 * usize::from(committee.degree()));

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Ku24SignMsg::Round1 {
                r: scalar_to_bytes(&r),
                s: scalar_to_bytes(&s_share),
            },
        }];
        let mut received = BTreeMap::new();
        received.insert(committee.my_index(), s_share);

        let mut machine = Self {
            committee,
            interp_2t,
            r,
            public_key: key_share.public_key,
            digest,
            round: SignRound::Round1(received),
            outgoing,
        };
        machine.try_finalize()?;
        Ok(machine)
    }

    fn try_finalize(&mut self) -> Ku24Result<()> {
        let SignRound::Round1(received) = &self.round else {
            return Ok(());
        };
        let n = self.committee.n();
        if received.len() != usize::from(n) {
            return Ok(());
        }

        let shares: Vec<C::Scalar> = (1..=n).map(|j| received[&j]).collect();
        let s = self
            .interp_2t
            .scalar(&shares)
            .ok_or(Ku24Error::InconsistentShares {
                what: "partial signatures",
                degree: self.interp_2t.degree(),
            })?;
        if s == C::Scalar::ZERO {
            return Err(Ku24Error::InvalidSignature);
        }
        let signature = Signature {
            r: self.r,
            s: low_s_normalize::<C>(s),
        };
        // The paper's coordinator verifies against the public key before
        // releasing the signature; a failure here means some party deviated.
        verify_ecdsa::<C>(&signature, &self.public_key, &self.digest)
            .map_err(|_| Ku24Error::InvalidSignature)?;

        self.round = SignRound::Done(signature);
        Ok(())
    }

    fn handle_inner(&mut self, from: PartyId, msg: Ku24SignMsg) -> Ku24Result<()> {
        let index = self.committee.sender_index(from)?;
        let Ku24SignMsg::Round1 { r, s } = msg;
        let r = wire::decode_scalar::<C>(&r)?;
        if r != self.r {
            return Err(Ku24Error::PresignatureMismatch(from));
        }
        let s = wire::decode_scalar::<C>(&s)?;

        let SignRound::Round1(received) = &mut self.round else {
            return Err(Ku24Error::RoundMismatch {
                expected: 2,
                got: 1,
            });
        };
        if received.contains_key(&index) {
            return Err(Ku24Error::DuplicateMessage {
                round: 1,
                party: from,
            });
        }
        received.insert(index, s);
        self.try_finalize()
    }
}

impl<C: TecdsaCurve> StateMachine for Ku24SignMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
    C::ProjectivePoint: LinearCombination<[(C::ProjectivePoint, C::Scalar); 2]>,
{
    type Output = Signature<C>;
    type Inbound = Ku24SignMsg;
    type Outbound = Ku24SignMsg;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        if matches!(self.round, SignRound::Poisoned) {
            return Err(Ku24Error::Poisoned.into());
        }
        self.handle_inner(from, msg).map_err(|e| {
            self.round = SignRound::Poisoned;
            e.into()
        })
    }

    fn drain_outgoing(&mut self) -> Vec<Outgoing<Self::Outbound>> {
        core::mem::take(&mut self.outgoing)
    }

    fn is_done(&self) -> bool {
        matches!(self.round, SignRound::Done(_))
    }

    fn finish(self) -> tecdsa_core::Result<Self::Output> {
        match self.round {
            SignRound::Done(sig) => Ok(sig),
            _ => Err(Ku24Error::NotComplete("signing").into()),
        }
    }

    fn current_round(&self) -> u16 {
        match self.round {
            SignRound::Poisoned => 0,
            SignRound::Round1(_) => 1,
            SignRound::Done(_) => 2,
        }
    }

    fn ia_report(&self) -> Option<&IaReport> {
        None
    }
}
