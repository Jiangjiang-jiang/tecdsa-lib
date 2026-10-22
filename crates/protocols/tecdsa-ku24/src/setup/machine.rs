// SPDX-License-Identifier: MIT OR Apache-2.0
//! State machine for the one-round, dealer-free PRSS setup.

use std::collections::BTreeMap;

use elliptic_curve::{sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField};
use rand::{rngs::OsRng, RngCore};
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{state_machine::Outgoing, IaReport, PartyId, Recipient, StateMachine};

use super::msg::{KeyEntry, Ku24SetupMsg};
use crate::{
    committee::Committee,
    error::{Ku24Error, Ku24Result},
    prss::{self, PrssKeys, SubsetMask, KEY_LEN},
};

/// KU24 PRSS setup ("aux info") state machine.
///
/// One round of point-to-point messages.  On construction the party samples
/// `k_A` for every subset `A` it is the designated dealer of (i.e. every `A` of
/// size `n - t` whose smallest member is this party) and queues one message per
/// recipient.  It completes once it has received every key `k_A` for the
/// subsets `A` that contain it but that it does not deal itself.
///
/// The output is the party's [`PrssKeys`], which is **key-independent**: a
/// single setup serves every ECDSA key and every presignature batch, as long as
/// distinct session identifiers are used per batch.
pub struct Ku24SetupMachine<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    committee: Committee,
    /// Keys held so far, indexed by subset mask.
    held: BTreeMap<SubsetMask, [u8; KEY_LEN]>,
    /// Subsets we still expect to receive, and the dealer responsible for each.
    expected: BTreeMap<SubsetMask, PartyId>,
    outgoing: Vec<Outgoing<Ku24SetupMsg>>,
    output: Option<PrssKeys<C>>,
    poisoned: bool,
    /// Round reported to the session layer.
    ///
    /// Deliberately *not* derived from `output`: a party that deals every
    /// subset it belongs to (party 1, always) has nothing to receive and is
    /// complete the moment it is constructed, yet its outgoing keys still
    /// belong to round 1. Advancing the counter eagerly would stamp them with
    /// round 2 and the wire layer would buffer them forever.
    round: u16,
}

impl<C: TecdsaCurve> Ku24SetupMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// Create the setup machine and queue this party's outgoing keys.
    ///
    /// `threshold` is the reconstruction threshold `t + 1`; an honest majority
    /// (`n >= 2t + 1`) is required.
    ///
    /// # Errors
    /// Fails if the participant set or the threshold is invalid.
    pub fn new(my_id: PartyId, all_parties: Vec<PartyId>, threshold: u16) -> Ku24Result<Self> {
        Self::new_with_rng(my_id, all_parties, threshold, &mut OsRng)
    }

    /// Same as [`Self::new`] but with a caller-supplied RNG.
    ///
    /// # Errors
    /// Fails if the participant set or the threshold is invalid.
    pub fn new_with_rng(
        my_id: PartyId,
        all_parties: Vec<PartyId>,
        threshold: u16,
        rng: &mut impl RngCore,
    ) -> Ku24Result<Self> {
        let committee = Committee::new(my_id, all_parties, threshold)?;
        let n = committee.n();
        let me = committee.my_index();
        let subset_size = n - committee.degree();

        let mut held = BTreeMap::new();
        let mut expected = BTreeMap::new();
        // recipient index -> keys destined for it
        let mut to_send: BTreeMap<u16, Vec<KeyEntry>> = BTreeMap::new();

        for mask in prss::subsets(n, subset_size) {
            let dealer = prss::dealer(mask);
            if dealer == me {
                let mut key = [0u8; KEY_LEN];
                rng.fill_bytes(&mut key);
                held.insert(mask, key);
                for member in prss::members(mask, n) {
                    if member != me {
                        to_send
                            .entry(member)
                            .or_default()
                            .push(KeyEntry { subset: mask, key });
                    }
                }
            } else if prss::contains(mask, me) {
                expected.insert(mask, committee.party_at(dealer));
            }
        }

        let outgoing = to_send
            .into_iter()
            .map(|(member, keys)| Outgoing {
                to: Recipient::Party(committee.party_at(member)),
                msg: Ku24SetupMsg::Keys(keys),
            })
            .collect();

        let mut machine = Self {
            committee,
            held,
            expected,
            outgoing,
            output: None,
            poisoned: false,
            round: 1,
        };
        machine.try_finalize()?;
        Ok(machine)
    }

    fn try_finalize(&mut self) -> Ku24Result<()> {
        if !self.expected.is_empty() {
            return Ok(());
        }
        self.output = Some(PrssKeys::from_keys(
            self.committee.my_index(),
            self.committee.n(),
            self.committee.threshold(),
            &self.held,
        )?);
        Ok(())
    }

    fn handle_inner(&mut self, from: PartyId, msg: Ku24SetupMsg) -> Ku24Result<()> {
        self.committee.sender_index(from)?;
        if self.output.is_some() {
            return Err(Ku24Error::DuplicateMessage {
                round: 1,
                party: from,
            });
        }
        let Ku24SetupMsg::Keys(entries) = msg;
        for entry in entries {
            match self.expected.get(&entry.subset) {
                Some(dealer) if *dealer == from => {}
                Some(_) => {
                    return Err(Ku24Error::Other(format!(
                        "{from} is not the designated dealer of subset {:#x}",
                        entry.subset
                    )))
                }
                None => {
                    return Err(Ku24Error::Other(format!(
                        "unexpected PRSS key for subset {:#x} from {from}",
                        entry.subset
                    )))
                }
            }
            self.expected.remove(&entry.subset);
            self.held.insert(entry.subset, entry.key);
        }
        self.try_finalize()?;
        if self.output.is_some() {
            self.round = 2;
        }
        Ok(())
    }
}

impl<C: TecdsaCurve> StateMachine for Ku24SetupMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    type Output = PrssKeys<C>;
    type Inbound = Ku24SetupMsg;
    type Outbound = Ku24SetupMsg;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        if self.poisoned {
            return Err(Ku24Error::Poisoned.into());
        }
        self.handle_inner(from, msg).map_err(|e| {
            self.poisoned = true;
            e.into()
        })
    }

    fn drain_outgoing(&mut self) -> Vec<Outgoing<Self::Outbound>> {
        core::mem::take(&mut self.outgoing)
    }

    fn is_done(&self) -> bool {
        self.output.is_some()
    }

    fn finish(mut self) -> tecdsa_core::Result<Self::Output> {
        self.output
            .take()
            .ok_or_else(|| Ku24Error::NotComplete("PRSS setup").into())
    }

    fn current_round(&self) -> u16 {
        if self.poisoned {
            0
        } else {
            self.round
        }
    }

    fn ia_report(&self) -> Option<&IaReport> {
        None
    }
}
