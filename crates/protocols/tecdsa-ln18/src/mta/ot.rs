// SPDX-License-Identifier: MIT OR Apache-2.0
//! OT-based private multiplication backend (LN18 section 6.1 / 6.3).
//!
//! For each ordered pair $(P_i, P_j)$ with $i \neq j$, an OT-based multiplication
//! is executed using the [`MulSender`] / [`MulReceiver`] from `tecdsa-ot`.
//!
//! The underlying OT multiplication realizes random-input multiplication:
//! the sender inputs $a_i$ and the receiver gets a *random* value $b$ plus
//! additive shares $(\alpha, \beta)$ with $\alpha + \beta = a_i \cdot b$.
//!
//! To achieve multiplication with a *chosen* receiver input $b_j$, we apply
//! a standard correction:
//! 1. Run OT multiplication: sender inputs $a_i$, receiver gets random $b$
//!    and both get shares $\alpha + \beta = a_i \cdot b$.
//! 2. Receiver sends correction $\delta = b_j - b$ to sender.
//! 3. Sender adjusts: $\alpha' = \alpha + a_i \cdot \delta$.
//! 4. Now $\alpha' + \beta = a_i \cdot (b + \delta) = a_i \cdot b_j$.
//!
//! **Final output:** Each party computes
//! $$c_i = a_i b_i + \sum_{j \neq i} \alpha_{ij} + \sum_{j \neq i} \beta_{ji}$$

#![allow(non_snake_case)]

use std::collections::BTreeMap;

use elliptic_curve::{
    ops::Reduce, sec1::ModulusSize, Field, FieldBytes, FieldBytesSize, PrimeField,
};
use rand_core::CryptoRngCore;
use tecdsa_curve::TecdsaCurve;
use tecdsa_ot::{
    rvole::{MulDataToKeep, MulDataToReceiver, MulReceiver, MulSender},
    soft_spoken::OteInitSenderMsg,
};
use tecdsa_protocol::PartyId;

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// Round-0 P2P message: exchange OTE initialization data.
///
/// Each party initializes a [`MulSender`] for every peer and sends
/// the OTE init message. The peer uses it to initialize a [`MulReceiver`].
#[derive(Clone)]
pub struct OtMtaInitMsg {
    /// The sender (who will act as MulSender for this direction).
    pub from: PartyId,
    /// Nonce for the public gadget vector.
    pub nonce_bytes: Vec<u8>,
    /// OTE init message (for the MulSender -> MulReceiver direction).
    pub ote_init_msg: OteInitSenderMsg,
}

/// Round-1 P2P message: receiver sends OTE data + correction delta to sender.
#[derive(Clone)]
pub struct OtMtaRound1Msg {
    /// The sender of this message (i.e., the MulReceiver / Bob).
    pub from: PartyId,
    /// OTE data from the MulReceiver phase 1.
    pub ote_data: tecdsa_ot::soft_spoken::OteDataToSender,
    /// Correction value $\delta = b_j - b$ (serialized scalar).
    pub delta_bytes: Vec<u8>,
}

/// Round-2 P2P message: sender responds with MulDataToReceiver.
#[derive(Clone)]
pub struct OtMtaRound2Msg {
    /// The sender of this message (i.e., the MulSender / Alice).
    pub from: PartyId,
    /// Multiplication protocol data for the receiver.
    pub mul_data: MulDataToReceiver,
}

// ---------------------------------------------------------------------------
// Per-party state
// ---------------------------------------------------------------------------

/// Per-party state for the OT-based MtA protocol.
///
/// Each party acts as MulSender towards every peer (for its own input $a_i$)
/// and as MulReceiver from every peer (for its own input $b_i$).
pub struct OtMtaState<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// This party's ID.
    my_id: PartyId,
    /// All party IDs (sorted, including self).
    parties: Vec<PartyId>,
    /// Own additive share $a_i$.
    a_i: C::Scalar,
    /// Own additive share $b_i$.
    b_i: C::Scalar,
    /// MulSender instances: one per peer (keyed by peer ID).
    /// Used when this party acts as Alice (sender) with input $a_i$.
    mul_senders: BTreeMap<PartyId, MulSender>,
    /// MulReceiver instances: one per peer (keyed by peer ID).
    /// Used when this party acts as Bob (receiver) with input $b_i$.
    mul_receivers: BTreeMap<PartyId, MulReceiver>,
    /// Session ID used for OT sub-protocols.
    _session_id: Vec<u8>,
    /// Receiver-side kept data (from phase 1), keyed by peer.
    receiver_kept: BTreeMap<PartyId, MulDataToKeep>,
    /// Random `b` values from MulReceiver phase 1, keyed by peer.
    _receiver_b: BTreeMap<PartyId, C::Scalar>,
    /// Sender-side output shares (alpha), keyed by peer.
    /// $\alpha_{ij}$: share from acting as sender towards peer $j$.
    alpha_shares: BTreeMap<PartyId, C::Scalar>,
    /// Receiver-side output shares (beta), keyed by peer.
    /// $\beta_{ji}$: share from acting as receiver from peer $j$.
    beta_shares: BTreeMap<PartyId, C::Scalar>,
}

impl<C: TecdsaCurve> OtMtaState<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: Reduce<FieldBytes<C>> + PrimeField<Repr = FieldBytes<C>>,
{
    /// Create a new OT MtA state and produce init messages.
    ///
    /// Each party initializes a [`MulSender`] for every peer and sends
    /// the OTE init message. Returns the state and init messages to send.
    pub fn new(
        my_id: PartyId,
        parties: Vec<PartyId>,
        a_i: C::Scalar,
        b_i: C::Scalar,
        rng: &mut impl CryptoRngCore,
    ) -> (Self, Vec<(PartyId, OtMtaInitMsg)>) {
        assert!(parties.contains(&my_id), "parties must contain my_id");

        let session_id = format!("ot-mta/{}", my_id).into_bytes();

        let mut mul_senders = BTreeMap::new();
        let mut init_msgs = Vec::new();

        for &pid in &parties {
            if pid == my_id {
                continue;
            }
            // Create a unique sub-session for this (sender=me, receiver=pid) pair.
            let pair_sid = format!("ot-mta/s{}-r{}", my_id, pid);
            let nonce = C::random_scalar(rng);
            let repr = nonce.to_repr();
            let nonce_bytes: Vec<u8> = AsRef::<[u8]>::as_ref(&repr).to_vec();

            let (sender, ote_msg) = MulSender::init::<C>(pair_sid.as_bytes(), &nonce, rng);
            mul_senders.insert(pid, sender);

            init_msgs.push((
                pid,
                OtMtaInitMsg {
                    from: my_id,
                    nonce_bytes,
                    ote_init_msg: ote_msg,
                },
            ));
        }

        let state = Self {
            my_id,
            parties,
            a_i,
            b_i,
            mul_senders,
            mul_receivers: BTreeMap::new(),
            _session_id: session_id,
            receiver_kept: BTreeMap::new(),
            _receiver_b: BTreeMap::new(),
            alpha_shares: BTreeMap::new(),
            beta_shares: BTreeMap::new(),
        };

        (state, init_msgs)
    }

    /// Process received init messages and set up MulReceiver instances.
    ///
    /// For each peer who sent an init message, this party creates a
    /// [`MulReceiver`] instance (acting as Bob for that peer's input).
    pub fn handle_init(&mut self, msgs: &[OtMtaInitMsg]) -> Result<(), String> {
        for msg in msgs {
            if msg.from == self.my_id {
                continue;
            }
            if !self.parties.contains(&msg.from) {
                return Err(format!("unknown party {}", msg.from));
            }
            if self.mul_receivers.contains_key(&msg.from) {
                return Err(format!("duplicate init message from {}", msg.from));
            }

            // The pair session ID matches what the sender used.
            let pair_sid = format!("ot-mta/s{}-r{}", msg.from, self.my_id);

            // Reconstruct nonce from bytes.
            let fb = FieldBytes::<C>::try_from(msg.nonce_bytes.as_slice())
                .map_err(|_| format!("invalid nonce bytes from {}", msg.from))?;
            let nonce = <C::Scalar as PrimeField>::from_repr(fb)
                .into_option()
                .ok_or_else(|| format!("invalid nonce scalar from {}", msg.from))?;

            let receiver =
                MulReceiver::init::<C>(pair_sid.as_bytes(), &nonce, &msg.ote_init_msg)
                    .map_err(|e| format!("MulReceiver init failed for {}: {}", msg.from, e.0))?;

            self.mul_receivers.insert(msg.from, receiver);
        }
        Ok(())
    }

    /// Run MulReceiver phase 1 for all peers and produce Round-1 messages.
    ///
    /// For each peer $P_j$, this party (acting as Bob) runs phase 1 of the
    /// OT multiplication, obtaining random $b$ and OTE data to send.
    /// The correction $\delta = b_i - b$ is included so the sender can adjust.
    pub fn run_receiver_phase1(
        &mut self,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<(PartyId, OtMtaRound1Msg)>, String> {
        let mut msgs = Vec::new();

        let peer_ids: Vec<PartyId> = self.mul_receivers.keys().copied().collect();

        for pid in peer_ids {
            let pair_sid = format!("ot-mta/s{}-r{}", pid, self.my_id);

            let receiver = self
                .mul_receivers
                .get(&pid)
                .ok_or_else(|| format!("no MulReceiver for {}", pid))?;

            let (b, data_to_keep, data_to_sender) = receiver
                .run_phase1::<C>(pair_sid.as_bytes(), rng)
                .map_err(|e| format!("MulReceiver phase1 failed for {}: {}", pid, e.0))?;

            // Compute correction: delta = b_i - b
            let delta = self.b_i - b;
            let delta_repr = delta.to_repr();
            let delta_bytes: Vec<u8> = AsRef::<[u8]>::as_ref(&delta_repr).to_vec();

            self.receiver_kept.insert(pid, data_to_keep);
            self._receiver_b.insert(pid, b);

            msgs.push((
                pid,
                OtMtaRound1Msg {
                    from: self.my_id,
                    ote_data: data_to_sender,
                    delta_bytes,
                },
            ));
        }

        Ok(msgs)
    }

    /// Process Round-1 messages (acting as MulSender) and produce Round-2 messages.
    ///
    /// For each peer $P_j$ who sent OTE data and correction $\delta$:
    /// 1. Run MulSender with input $\[a_i\]$ (using slot 0 of the L=2 vector).
    /// 2. Compute $\alpha' = \alpha + a_i \cdot \delta$.
    /// 3. Store $\alpha'$ as our sender-side share.
    pub fn handle_round1(
        &mut self,
        msgs: &[OtMtaRound1Msg],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<(PartyId, OtMtaRound2Msg)>, String> {
        let mut round2_msgs = Vec::new();

        for msg in msgs {
            if msg.from == self.my_id {
                continue;
            }
            if !self.parties.contains(&msg.from) {
                return Err(format!("unknown party {}", msg.from));
            }
            if self.alpha_shares.contains_key(&msg.from) {
                return Err(format!("duplicate Round-1 message from {}", msg.from));
            }

            let pair_sid = format!("ot-mta/s{}-r{}", self.my_id, msg.from);

            let sender = self
                .mul_senders
                .get(&msg.from)
                .ok_or_else(|| format!("no MulSender for {}", msg.from))?;

            // The OT multiplication uses L=2 slots; we use slot 0 for our value.
            let input = vec![self.a_i, C::Scalar::ZERO];

            let (sender_output, data_to_receiver) = sender
                .run::<C>(pair_sid.as_bytes(), &input, &msg.ote_data, rng)
                .map_err(|e| format!("MulSender run failed for {}: {}", msg.from, e.0))?;

            // Parse correction delta.
            let fb = FieldBytes::<C>::try_from(msg.delta_bytes.as_slice())
                .map_err(|_| format!("invalid delta bytes from {}", msg.from))?;
            let delta = <C::Scalar as PrimeField>::from_repr(fb)
                .into_option()
                .ok_or_else(|| format!("invalid delta scalar from {}", msg.from))?;

            // Apply correction: alpha' = sender_output[0] + a_i * delta
            let alpha = sender_output[0] + self.a_i * delta;
            self.alpha_shares.insert(msg.from, alpha);

            round2_msgs.push((
                msg.from,
                OtMtaRound2Msg {
                    from: self.my_id,
                    mul_data: data_to_receiver,
                },
            ));
        }

        Ok(round2_msgs)
    }

    /// Process Round-2 messages (completing MulReceiver phase 2) and compute
    /// the final output share $c_i$.
    ///
    /// For each peer $P_j$ who responded:
    /// 1. Complete MulReceiver phase 2 to get receiver output.
    /// 2. Store $\beta_{ji}$ = receiver_output\[0\] (uncorrected receiver share).
    ///
    /// Then compute:
    /// $$c_i = a_i b_i + \sum_{j \neq i} \alpha_{ij} + \sum_{j \neq i} \beta_{ji}$$
    pub fn finish(&mut self, msgs: &[OtMtaRound2Msg]) -> Result<C::Scalar, String> {
        for msg in msgs {
            if msg.from == self.my_id {
                continue;
            }
            if !self.parties.contains(&msg.from) {
                return Err(format!("unknown party {}", msg.from));
            }
            if self.beta_shares.contains_key(&msg.from) {
                return Err(format!("duplicate Round-2 message from {}", msg.from));
            }

            let pair_sid = format!("ot-mta/s{}-r{}", msg.from, self.my_id);

            let receiver = self
                .mul_receivers
                .get(&msg.from)
                .ok_or_else(|| format!("no MulReceiver for {}", msg.from))?;
            let data_kept = self
                .receiver_kept
                .get(&msg.from)
                .ok_or_else(|| format!("no kept data for {}", msg.from))?;

            let receiver_output = receiver
                .run_phase2::<C>(pair_sid.as_bytes(), data_kept, &msg.mul_data)
                .map_err(|e| format!("MulReceiver phase2 failed for {}: {}", msg.from, e.0))?;

            // The receiver output (slot 0) is the uncorrected beta.
            // The correction was applied on the sender side, so:
            //   alpha'_{ji} + beta_{ij} = a_j * b  (from OT)
            //   alpha'_{ji} = alpha_{ji} + a_j * delta  (sender corrected)
            //   So alpha'_{ji} + beta_{ij} = a_j * (b + delta) = a_j * b_i
            // Therefore beta_{ij} is the receiver's uncorrected share.
            let beta = receiver_output[0];
            self.beta_shares.insert(msg.from, beta);
        }

        // Verify we have shares from all peers.
        let expected = self.parties.len() - 1;
        if self.alpha_shares.len() != expected {
            return Err(format!(
                "expected {} alpha shares, got {}",
                expected,
                self.alpha_shares.len()
            ));
        }
        if self.beta_shares.len() != expected {
            return Err(format!(
                "expected {} beta shares, got {}",
                expected,
                self.beta_shares.len()
            ));
        }

        // c_i = a_i * b_i + sum(alpha_ij) + sum(beta_ji)
        let alpha_sum: C::Scalar = self
            .alpha_shares
            .values()
            .copied()
            .fold(C::Scalar::ZERO, |acc, x| acc + x);
        let beta_sum: C::Scalar = self
            .beta_shares
            .values()
            .copied()
            .fold(C::Scalar::ZERO, |acc, x| acc + x);

        let c_i = self.a_i * self.b_i + alpha_sum + beta_sum;
        Ok(c_i)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "secp256k1")]
    type C = k256::Secp256k1;

    /// Run the OT MtA protocol for `n` parties and verify correctness.
    ///
    /// Each party receives random additive shares $(a_i, b_i)$. The protocol
    /// produces shares $c_i$ such that $\sum c_i = (\sum a_i)(\sum b_i) \bmod q$.
    #[cfg(feature = "secp256k1")]
    fn run_ot_mta(n: usize) {
        let mut rng = rand::thread_rng();
        let parties: Vec<PartyId> = (1..=n).map(|i| PartyId(i as u16)).collect();

        // Generate random shares
        let a_shares: Vec<<C as elliptic_curve::CurveArithmetic>::Scalar> =
            (0..n).map(|_| C::random_scalar(&mut rng)).collect();
        let b_shares: Vec<<C as elliptic_curve::CurveArithmetic>::Scalar> =
            (0..n).map(|_| C::random_scalar(&mut rng)).collect();

        // --- Init: each party creates state + sends init messages ---
        let mut states: Vec<OtMtaState<C>> = Vec::with_capacity(n);
        let mut all_init_msgs: Vec<Vec<(PartyId, OtMtaInitMsg)>> = Vec::with_capacity(n);

        for i in 0..n {
            let (state, init_msgs) = OtMtaState::<C>::new(
                parties[i],
                parties.clone(),
                a_shares[i],
                b_shares[i],
                &mut rng,
            );
            states.push(state);
            all_init_msgs.push(init_msgs);
        }

        // Deliver init messages
        for i in 0..n {
            let mut msgs_for_i: Vec<OtMtaInitMsg> = Vec::new();
            for j in 0..n {
                if i == j {
                    continue;
                }
                for (dest, msg) in &all_init_msgs[j] {
                    if *dest == parties[i] {
                        msgs_for_i.push(msg.clone());
                    }
                }
            }
            states[i]
                .handle_init(&msgs_for_i)
                .expect("init should succeed");
        }

        // --- Round 1: receiver phase 1 (OTE data + correction delta) ---
        let mut all_round1_msgs: Vec<Vec<(PartyId, OtMtaRound1Msg)>> = Vec::with_capacity(n);
        for i in 0..n {
            let r1_msgs = states[i]
                .run_receiver_phase1(&mut rng)
                .expect("receiver phase1 should succeed");
            all_round1_msgs.push(r1_msgs);
        }

        // --- Round 2: sender processes OTE data, sends MulDataToReceiver ---
        let mut all_round2_msgs: Vec<Vec<(PartyId, OtMtaRound2Msg)>> = Vec::with_capacity(n);
        for i in 0..n {
            let mut msgs_for_i: Vec<OtMtaRound1Msg> = Vec::new();
            for j in 0..n {
                if i == j {
                    continue;
                }
                for (dest, msg) in &all_round1_msgs[j] {
                    if *dest == parties[i] {
                        msgs_for_i.push(msg.clone());
                    }
                }
            }
            let r2_msgs = states[i]
                .handle_round1(&msgs_for_i, &mut rng)
                .expect("Round-1 should succeed");
            all_round2_msgs.push(r2_msgs);
        }

        // --- Finish: receiver completes phase 2, compute c_i ---
        let mut c_shares: Vec<<C as elliptic_curve::CurveArithmetic>::Scalar> =
            Vec::with_capacity(n);

        for i in 0..n {
            let mut msgs_for_i: Vec<OtMtaRound2Msg> = Vec::new();
            for j in 0..n {
                if i == j {
                    continue;
                }
                for (dest, msg) in &all_round2_msgs[j] {
                    if *dest == parties[i] {
                        msgs_for_i.push(msg.clone());
                    }
                }
            }
            let c_i = states[i]
                .finish(&msgs_for_i)
                .expect("finish should succeed");
            c_shares.push(c_i);
        }

        // --- Verify: sum(c_i) == (sum a_i) * (sum b_i) mod q ---
        let sum_a: <C as elliptic_curve::CurveArithmetic>::Scalar =
            a_shares.iter().copied().reduce(|acc, x| acc + x).unwrap();
        let sum_b: <C as elliptic_curve::CurveArithmetic>::Scalar =
            b_shares.iter().copied().reduce(|acc, x| acc + x).unwrap();
        let expected = sum_a * sum_b;

        let sum_c: <C as elliptic_curve::CurveArithmetic>::Scalar =
            c_shares.iter().copied().reduce(|acc, x| acc + x).unwrap();

        assert_eq!(
            sum_c, expected,
            "sum(c_i) must equal (sum a_i) * (sum b_i) mod q"
        );
    }

    #[test]
    #[cfg(feature = "secp256k1")]
    fn ot_mta_2of2() {
        run_ot_mta(2);
    }

    #[test]
    #[cfg(feature = "secp256k1")]
    fn ot_mta_3of3() {
        run_ot_mta(3);
    }
}
