// SPDX-License-Identifier: MIT OR Apache-2.0
//! Four-round state machine for KU25 batch presigning.

use std::collections::BTreeMap;

use elliptic_curve::{
    group::{Curve as CurveGroup, Group},
    sec1::ModulusSize,
    Field, FieldBytes, FieldBytesSize, PrimeField,
};
use rand::{rngs::OsRng, RngCore};
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{state_machine::Outgoing, IaReport, PartyId, Recipient, StateMachine};

use super::{
    msg::{Ku25PresignMsg, PresignRound3, PresignRound4},
    open_points, open_scalar, open_scalars, streams, triple_check_share, wmult_contribution,
    Ku25PresignBatch, Ku25Presignature,
};
use crate::{
    committee::Committee,
    error::{Ku25Error, Ku25Result},
    interp::Interp,
    prss::PrssKeys,
    wire,
};

/// Decoded round-3 broadcast of one party.
struct R3<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    r: C::Scalar,
    beta: C::Scalar,
}

/// Decoded round-4 broadcast of one party.
struct R4<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    t: C::Scalar,
    w: Vec<C::Scalar>,
    big_r: Vec<C::ProjectivePoint>,
}

enum PresignRound<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    Round1(BTreeMap<u16, Vec<C::Scalar>>),
    Round2(BTreeMap<u16, Vec<C::Scalar>>),
    Round3(BTreeMap<u16, R3<C>>),
    Round4(BTreeMap<u16, R4<C>>),
    Done(Ku25PresignBatch<C>),
    Poisoned,
}

/// KU25 batch presigning state machine.
///
/// Produces `m` key-independent presignatures in four broadcast rounds.  The
/// round count is independent of `m`, which is where the amortization comes
/// from: the paper measures ~1.3 ms per presignature at `m = 10 000` under a
/// 50 ms link, against 680 ms at `m = 1`.
///
/// All `F_rss` material is derived locally in the constructor, so nothing but
/// the four broadcasts touches the network.
///
/// # Round ordering is security-critical
///
/// `r` and `beta` are available locally from the very first moment, but they
/// are deliberately not revealed until round 3 -- after **both** `F_wmult`
/// calls have closed.  Lemma 1 requires the adversary's additive shifts
/// `d_i, delta_i, delta'_i` to be independent of `r` and `beta`; a rushing
/// adversary that learned them earlier could pick `delta'_i = r * d_i` in the
/// second `F_wmult` and drive `T` to zero with a tampered triple.
pub struct Ku25PresignMachine<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    committee: Committee,
    /// Batch size `m`.
    m: usize,
    interp_t: Interp<C>,
    interp_2t: Interp<C>,

    // --- locally derived F_rss material -----------------------------------
    /// `a_{i,j}` for `i in [m]`.
    a: Vec<C::Scalar>,
    /// `k_{i,j}` for `i in [m]`.
    k: Vec<C::Scalar>,
    /// This party's degree-`t` share of the verification value `r`.
    r_share: C::Scalar,
    /// This party's degree-`t` share of the verification challenge `beta`.
    beta_share: C::Scalar,
    /// Degree-`t` masks of the first `F_wmult` call (`2m`).
    mask1: Vec<C::Scalar>,
    /// Degree-`t` masks of the second `F_wmult` call (`m`).
    mask2: Vec<C::Scalar>,
    /// Degree-`2t` zero shares of the second `F_wmult` call (`m`).
    zero2: Vec<C::Scalar>,
    /// Degree-`2t` zero shares handed to the online signing phase (`m`).
    sign_zero: Vec<C::Scalar>,

    // --- values derived as rounds complete --------------------------------
    /// `w_{i,j}`: degree-`t` share of `a_i k_i`.
    w: Vec<C::Scalar>,
    /// `mu_{i,j}`: degree-`t` share of `r a_i`.
    mu: Vec<C::Scalar>,
    /// `tau_{i,j}`: degree-`t` share of `mu_i k_i`.
    tau: Vec<C::Scalar>,

    round: PresignRound<C>,
    outgoing: Vec<Outgoing<Ku25PresignMsg>>,
}

impl<C: TecdsaCurve> Ku25PresignMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// Start a presigning batch of size `m` with a freshly sampled session id.
    ///
    /// Note that all parties must use the *same* session id; prefer
    /// [`Self::new_with_session`] with a coordinator-supplied value.  This
    /// constructor is provided for single-batch tests and benchmarks.
    ///
    /// # Errors
    /// Fails if `m == 0` or if the participant set disagrees with the PRSS setup.
    pub fn new(
        my_id: PartyId,
        all_parties: Vec<PartyId>,
        prss: &PrssKeys<C>,
        m: usize,
    ) -> Ku25Result<Self> {
        let mut session = [0u8; 32];
        OsRng.fill_bytes(&mut session);
        Self::new_with_session(my_id, all_parties, prss, m, &session)
    }

    /// Start a presigning batch of size `m` with an explicit session identifier.
    ///
    /// All parties **must** agree on `session`, and it **must never repeat**:
    /// it is the domain separator that keeps the `F_rss` outputs of different
    /// batches independent, which is what lets the PRSS setup be run once and
    /// for all (Section 3, "Running multiple executions").
    ///
    /// # Errors
    /// Fails if `m == 0` or if the participant set disagrees with the PRSS setup.
    pub fn new_with_session(
        my_id: PartyId,
        all_parties: Vec<PartyId>,
        prss: &PrssKeys<C>,
        m: usize,
        session: &[u8; 32],
    ) -> Ku25Result<Self> {
        if m == 0 {
            return Err(Ku25Error::Other("batch size must be at least 1".into()));
        }
        let committee = Committee::new(my_id, all_parties, prss.threshold())?;
        if committee.n() != prss.n() || committee.my_index() != prss.my_index() {
            return Err(Ku25Error::InvalidPartySet(
                "participant set does not match the PRSS setup".into(),
            ));
        }
        let degree = usize::from(committee.degree());
        let indices = committee.indices();
        let interp_t = Interp::<C>::new(&indices, degree);
        let interp_2t = Interp::<C>::new(&indices, 2 * degree);

        // Pi_triple step 2: 2m + 2 random values -- a_1..a_m, k_1..k_m, r, beta.
        let mut randoms = prss.rand(session, streams::TRIPLE_RANDOM, 2 * m + 2);
        let beta_share = randoms.pop().expect("2m + 2 values were requested");
        let r_share = randoms.pop().expect("2m + 2 values were requested");
        let k = randoms.split_off(m);
        let a = randoms;

        // All remaining F_rss material, derived non-interactively up front.
        let mask1 = prss.rand(session, streams::WMULT1_MASK, 2 * m);
        let zero1 = prss.zero(session, streams::WMULT1_ZERO, 2 * m);
        let mask2 = prss.rand(session, streams::WMULT2_MASK, m);
        let zero2 = prss.zero(session, streams::WMULT2_ZERO, m);
        let sign_zero = prss.zero(session, streams::SIGN_ZERO, m);

        // Pi_triple step 3: one batched F_wmult over {(k_i, a_i)} ++ {(r, a_i)}.
        let lhs: Vec<C::Scalar> = k
            .iter()
            .copied()
            .chain(core::iter::repeat_n(r_share, m))
            .collect();
        let rhs: Vec<C::Scalar> = a.iter().copied().chain(a.iter().copied()).collect();
        let e1 = wmult_contribution::<C>(&lhs, &rhs, &mask1, &zero1);

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Ku25PresignMsg::Round1(wire::encode_scalars::<C>(&e1)),
        }];

        let mut received = BTreeMap::new();
        received.insert(committee.my_index(), e1);

        Ok(Self {
            committee,
            m,
            interp_t,
            interp_2t,
            a,
            k,
            r_share,
            beta_share,
            mask1,
            mask2,
            zero2,
            sign_zero,
            w: Vec::new(),
            mu: Vec::new(),
            tau: Vec::new(),
            round: PresignRound::Round1(received),
            outgoing,
        })
    }

    /// Batch size `m`.
    #[must_use]
    pub fn batch_size(&self) -> usize {
        self.m
    }

    fn n(&self) -> u16 {
        self.committee.n()
    }

    /// Round 1 -> 2: open the first `F_wmult`, then run the second one.
    fn transition_r1_to_r2(&mut self, received: &BTreeMap<u16, Vec<C::Scalar>>) -> Ku25Result<()> {
        let n = self.n();
        let m = self.m;

        // Pi_wmult step 5. The opened value has degree 2t and, with n = 2t + 1,
        // is exactly determined -- hence no consistency check is possible here,
        // and F_wmult is only secure up to additive attacks. That is precisely
        // what the batch check in round 4 catches.
        let opened = open_scalars::<C>(&self.interp_2t, n, 2 * m, received, "F_wmult (1)")?;
        let products: Vec<C::Scalar> = opened
            .iter()
            .zip(&self.mask1)
            .map(|(e, mask)| *e - *mask)
            .collect();
        // First m: w_i = k_i a_i. Last m: mu_i = r a_i.
        self.mu = products[m..].to_vec();
        self.w = products[..m].to_vec();

        // Pi_triple step 4: F_wmult on {(mu_i, k_i)}.
        let e2 = wmult_contribution::<C>(&self.mu, &self.k, &self.mask2, &self.zero2);

        let mut next = BTreeMap::new();
        next.insert(self.committee.my_index(), e2.clone());
        self.outgoing.push(Outgoing {
            to: Recipient::Broadcast,
            msg: Ku25PresignMsg::Round2(wire::encode_scalars::<C>(&e2)),
        });
        self.round = PresignRound::Round2(next);
        Ok(())
    }

    /// Round 2 -> 3: recover `tau`, then open the challenge `r`, `beta`.
    fn transition_r2_to_r3(&mut self, received: &BTreeMap<u16, Vec<C::Scalar>>) -> Ku25Result<()> {
        let n = self.n();
        let m = self.m;
        let opened = open_scalars::<C>(&self.interp_2t, n, m, received, "F_wmult (2)")?;
        self.tau = opened
            .iter()
            .zip(&self.mask2)
            .map(|(e, mask)| *e - *mask)
            .collect();

        // Pi_triple step 5. Only now, with every additive shift already fixed by
        // rounds 1 and 2, is it safe to reveal the challenge.
        let mut next = BTreeMap::new();
        next.insert(
            self.committee.my_index(),
            R3 {
                r: self.r_share,
                beta: self.beta_share,
            },
        );
        self.outgoing.push(Outgoing {
            to: Recipient::Broadcast,
            msg: Ku25PresignMsg::Round3(PresignRound3 {
                r_share: wire::encode_scalar::<C>(&self.r_share),
                beta_share: wire::encode_scalar::<C>(&self.beta_share),
            }),
        });
        self.round = PresignRound::Round3(next);
        Ok(())
    }

    /// Round 3 -> 4: evaluate the batch check and open it together with
    /// `w_i` and `R_i = g^{k_i}`.
    fn transition_r3_to_r4(&mut self, received: &BTreeMap<u16, R3<C>>) -> Ku25Result<()> {
        let n = self.n();
        let r_shares: BTreeMap<u16, C::Scalar> =
            received.iter().map(|(index, p)| (*index, p.r)).collect();
        let beta_shares: BTreeMap<u16, C::Scalar> =
            received.iter().map(|(index, p)| (*index, p.beta)).collect();

        // r and beta are degree-t, so these openings *are* checked against the
        // t redundant points: a corrupted party cannot bias the challenge, it
        // can only cause an abort.
        let r = open_scalar::<C>(&self.interp_t, n, &r_shares, "r")?;
        let beta = open_scalar::<C>(&self.interp_t, n, &beta_shares, "beta")?;
        if beta == C::Scalar::ZERO {
            // T(beta) would be identically zero, voiding the check.
            return Err(Ku25Error::Degenerate {
                index: 0,
                what: "beta is zero",
            });
        }

        let t_share = triple_check_share::<C>(&self.tau, &self.w, &r, &beta);

        // Pi_ECDSA presigning step 4, merged into this round. Releasing w_i and
        // R_i alongside T_j is sound: if the check fails everyone aborts, and
        // Section 4 notes that the leaked (a_i, k_i) are just random values that
        // do not need to stay private once cheating has been detected.
        let big_r: Vec<C::ProjectivePoint> = self.k.iter().map(|k| C::generator() * *k).collect();
        let payload = PresignRound4 {
            t_share: wire::encode_scalar::<C>(&t_share),
            w: wire::encode_scalars::<C>(&self.w),
            big_r: wire::encode_points::<C>(&big_r)?,
        };

        let mut next = BTreeMap::new();
        next.insert(
            self.committee.my_index(),
            R4 {
                t: t_share,
                w: self.w.clone(),
                big_r,
            },
        );
        self.outgoing.push(Outgoing {
            to: Recipient::Broadcast,
            msg: Ku25PresignMsg::Round4(payload),
        });
        self.round = PresignRound::Round4(next);
        Ok(())
    }

    /// Round 4 -> done: verify `T = 0` and assemble the presignatures.
    fn finalize(&mut self, received: &BTreeMap<u16, R4<C>>) -> Ku25Result<()> {
        let n = self.n();
        let m = self.m;

        let t_shares: BTreeMap<u16, C::Scalar> =
            received.iter().map(|(index, p)| (*index, p.t)).collect();
        let t = open_scalar::<C>(&self.interp_t, n, &t_shares, "T")?;
        if t != C::Scalar::ZERO {
            // Lemma 1: an honest run always yields T = 0, and any additive shift
            // survives with probability at most (m + 1)/q.
            return Err(Ku25Error::TripleCheckFailed);
        }

        let w_shares: BTreeMap<u16, Vec<C::Scalar>> = received
            .iter()
            .map(|(index, p)| (*index, p.w.clone()))
            .collect();
        let r_shares: BTreeMap<u16, Vec<C::ProjectivePoint>> = received
            .iter()
            .map(|(index, p)| (*index, p.big_r.clone()))
            .collect();

        // Both openings are degree-t over n >= 2t + 1 points, so they are
        // checked: a corrupted party cannot substitute a different w_i or R_i.
        let w_open = open_scalars::<C>(&self.interp_t, n, m, &w_shares, "w_i")?;
        let r_open = open_points::<C>(&self.interp_t, n, m, &r_shares, "R_i")?;

        let mut presignatures = Vec::with_capacity(m);
        for i in 0..m {
            // w_i = a_i k_i must be invertible, else k'_{i,j} is undefined.
            let w_inv =
                Option::<C::Scalar>::from(w_open[i].invert()).ok_or(Ku25Error::Degenerate {
                    index: i,
                    what: "w_i is zero",
                })?;
            if bool::from(r_open[i].is_identity()) {
                return Err(Ku25Error::Degenerate {
                    index: i,
                    what: "R_i is the identity",
                });
            }
            let r = C::xcoord_mod_q(&r_open[i].to_affine());
            if r == C::Scalar::ZERO {
                return Err(Ku25Error::Degenerate {
                    index: i,
                    what: "r_i is zero",
                });
            }
            presignatures.push(Ku25Presignature {
                party_index: self.committee.my_index(),
                total: n,
                threshold: self.committee.threshold(),
                r,
                big_r: r_open[i],
                // k'_{i,j} = w_i^{-1} a_{i,j} is a degree-t sharing of k_i^{-1},
                // because w_i = a_i k_i.
                k_inv_share: w_inv * self.a[i],
                zero_share: self.sign_zero[i],
            });
        }
        self.round = PresignRound::Done(Ku25PresignBatch { presignatures });
        Ok(())
    }

    fn handle_inner(&mut self, from: PartyId, msg: Ku25PresignMsg) -> Ku25Result<()> {
        let index = self.committee.sender_index(from)?;
        let expected = usize::from(self.n());
        let m = self.m;

        match (&mut self.round, msg) {
            (PresignRound::Round1(received), Ku25PresignMsg::Round1(bytes)) => {
                if received.contains_key(&index) {
                    return Err(Ku25Error::DuplicateMessage {
                        round: 1,
                        party: from,
                    });
                }
                received.insert(index, wire::decode_scalars::<C>(&bytes, 2 * m)?);
                if received.len() == expected {
                    let PresignRound::Round1(received) =
                        core::mem::replace(&mut self.round, PresignRound::Poisoned)
                    else {
                        unreachable!("round was matched above")
                    };
                    self.transition_r1_to_r2(&received)?;
                }
                Ok(())
            }
            (PresignRound::Round2(received), Ku25PresignMsg::Round2(bytes)) => {
                if received.contains_key(&index) {
                    return Err(Ku25Error::DuplicateMessage {
                        round: 2,
                        party: from,
                    });
                }
                received.insert(index, wire::decode_scalars::<C>(&bytes, m)?);
                if received.len() == expected {
                    let PresignRound::Round2(received) =
                        core::mem::replace(&mut self.round, PresignRound::Poisoned)
                    else {
                        unreachable!("round was matched above")
                    };
                    self.transition_r2_to_r3(&received)?;
                }
                Ok(())
            }
            (PresignRound::Round3(received), Ku25PresignMsg::Round3(payload)) => {
                if received.contains_key(&index) {
                    return Err(Ku25Error::DuplicateMessage {
                        round: 3,
                        party: from,
                    });
                }
                received.insert(
                    index,
                    R3 {
                        r: wire::decode_scalar::<C>(&payload.r_share)?,
                        beta: wire::decode_scalar::<C>(&payload.beta_share)?,
                    },
                );
                if received.len() == expected {
                    let PresignRound::Round3(received) =
                        core::mem::replace(&mut self.round, PresignRound::Poisoned)
                    else {
                        unreachable!("round was matched above")
                    };
                    self.transition_r3_to_r4(&received)?;
                }
                Ok(())
            }
            (PresignRound::Round4(received), Ku25PresignMsg::Round4(payload)) => {
                if received.contains_key(&index) {
                    return Err(Ku25Error::DuplicateMessage {
                        round: 4,
                        party: from,
                    });
                }
                received.insert(
                    index,
                    R4 {
                        t: wire::decode_scalar::<C>(&payload.t_share)?,
                        w: wire::decode_scalars::<C>(&payload.w, m)?,
                        big_r: wire::decode_points::<C>(&payload.big_r, m)?,
                    },
                );
                if received.len() == expected {
                    let PresignRound::Round4(received) =
                        core::mem::replace(&mut self.round, PresignRound::Poisoned)
                    else {
                        unreachable!("round was matched above")
                    };
                    self.finalize(&received)?;
                }
                Ok(())
            }
            (round, msg) => Err(Ku25Error::RoundMismatch {
                expected: round_number(round),
                got: msg_round(&msg),
            }),
        }
    }
}

fn round_number<C: TecdsaCurve>(round: &PresignRound<C>) -> u16
where
    FieldBytesSize<C>: ModulusSize,
{
    match round {
        PresignRound::Poisoned => 0,
        PresignRound::Round1(_) => 1,
        PresignRound::Round2(_) => 2,
        PresignRound::Round3(_) => 3,
        PresignRound::Round4(_) => 4,
        PresignRound::Done(_) => 5,
    }
}

fn msg_round(msg: &Ku25PresignMsg) -> u16 {
    match msg {
        Ku25PresignMsg::Round1(_) => 1,
        Ku25PresignMsg::Round2(_) => 2,
        Ku25PresignMsg::Round3(_) => 3,
        Ku25PresignMsg::Round4(_) => 4,
    }
}

impl<C: TecdsaCurve> StateMachine for Ku25PresignMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    type Output = Ku25PresignBatch<C>;
    type Inbound = Ku25PresignMsg;
    type Outbound = Ku25PresignMsg;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        if matches!(self.round, PresignRound::Poisoned) {
            return Err(Ku25Error::Poisoned.into());
        }
        self.handle_inner(from, msg).map_err(|e| {
            self.round = PresignRound::Poisoned;
            e.into()
        })
    }

    fn drain_outgoing(&mut self) -> Vec<Outgoing<Self::Outbound>> {
        core::mem::take(&mut self.outgoing)
    }

    fn is_done(&self) -> bool {
        matches!(self.round, PresignRound::Done(_))
    }

    fn finish(self) -> tecdsa_core::Result<Self::Output> {
        match self.round {
            PresignRound::Done(batch) => Ok(batch),
            _ => Err(Ku25Error::NotComplete("presigning").into()),
        }
    }

    fn current_round(&self) -> u16 {
        round_number(&self.round)
    }

    fn ia_report(&self) -> Option<&IaReport> {
        None
    }
}
