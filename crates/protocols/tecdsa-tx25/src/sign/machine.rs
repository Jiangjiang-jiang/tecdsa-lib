// SPDX-License-Identifier: GPL-3.0-or-later
//! TX25 online sign state machine implementation.

use std::collections::BTreeMap;

use elliptic_curve::ops::LinearCombination;

use tecdsa_core::TecdsaError;
use tecdsa_curve::zk::ddh::{DdhProof, DdhStatement, DdhWitness};
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::ecdsa::{low_s_normalize, verify_ecdsa, DataToSign, Signature};
use tecdsa_protocol::{state_machine::Outgoing, IaReport, PartyId, Recipient, StateMachine};

use crate::presign::Tx25Presignature;

use super::msg::{deserialize_online_msg, serialize_online_msg, OnlineRoundMsg, Tx25OnlineSignMsg};
use super::rounds::{
    assemble_signature, hash_message_to_scalar, identify_cheaters, zero_poly_eval,
};

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

/// TX25 online signing state machine (1 round).
///
/// On construction, computes the masked delta/chi shares, the DDH proof,
/// and queues a broadcast.  Collects broadcasts from all other parties and
/// assembles the final signature.  If verification fails, performs cheater
/// identification using the public B/B_hat points and DDH proofs.
pub struct Tx25OnlineSignMachine {
    my_id: PartyId,
    all_parties: Vec<PartyId>,
    /// Party ids as u16 for arithmetic.
    party_ids: Vec<u16>,
    /// The presignature consumed by this signing session.
    presignature: Tx25Presignature,
    /// The message hash m = H(msg), kept for potential re-verification.
    _message_hash: k256::Scalar,
    /// The full DataToSign for verification.
    message: DataToSign<k256::Secp256k1>,
    /// The ECDSA public key X.
    public_key: k256::ProjectivePoint,
    /// The point A = mG + rX used in the DDH statement.
    a_point: k256::ProjectivePoint,
    /// Collected broadcasts, indexed by party id (u16).
    received: BTreeMap<u16, OnlineRoundMsg>,
    /// Outgoing messages to drain.
    outgoing: Vec<Outgoing<Tx25OnlineSignMsg>>,
    /// Final output.
    output: Option<Signature<k256::Secp256k1>>,
    /// Identifiable abort report (if cheater detected).
    ia_report: Option<IaReport>,
    done: bool,
}

impl Tx25OnlineSignMachine {
    /// Create a new TX25 online signing state machine.
    ///
    /// Immediately computes masked delta/chi shares, the DDH proof, and
    /// queues the broadcast for all other parties.
    ///
    /// # Arguments
    ///
    /// * `my_id` - This party's identifier.
    /// * `all_parties` - All signing party identifiers in consistent order.
    /// * `presignature` - This party's presignature output.
    /// * `message` - The raw message bytes to sign.
    /// * `public_key` - The joint ECDSA public key X.
    ///
    /// # Errors
    ///
    /// Returns an error if this party is not in `all_parties`.
    pub fn new(
        my_id: PartyId,
        all_parties: Vec<PartyId>,
        presignature: Tx25Presignature,
        message: &[u8],
        public_key: k256::ProjectivePoint,
    ) -> tecdsa_core::Result<Self> {
        let _my_idx = all_parties
            .iter()
            .position(|p| *p == my_id)
            .ok_or_else(|| TecdsaError::Other("my_id not found in all_parties".into()))?;

        let party_ids: Vec<u16> = all_parties.iter().map(|p| p.0).collect();
        let my_pid = my_id.0;
        let t = presignature.threshold;

        // Step 1: Hash message to scalar.
        let m = hash_message_to_scalar(message);
        let message_data = DataToSign::from_digest(m);

        let r_x = presignature.r_x;
        let gamma_i = presignature.gamma_i;
        let r_point = presignature.r_point;

        // Step 2: Generate two zero-sharing polynomials f, f' with f(0)=f'(0)=0.
        let mut rng = rand::thread_rng();
        let f_evals = zero_poly_eval(t, &party_ids, &mut rng);
        let f_prime_evals = zero_poly_eval(t, &party_ids, &mut rng);

        // Step 3: For each party j in S, compute masked delta and chi.
        let mut delta_shares = BTreeMap::new();
        let mut chi_shares = BTreeMap::new();

        for &pid in &party_ids {
            // Mask delta: delta_{i,j} = delta_{i,j} + f(j)
            let base_delta = presignature
                .delta_shares
                .get(&pid)
                .copied()
                .unwrap_or(k256::Scalar::ZERO);
            let masked_delta =
                base_delta + f_evals.get(&pid).copied().unwrap_or(k256::Scalar::ZERO);
            delta_shares.insert(pid, masked_delta);

            // Generate chi: chi_{i,j} = m*gamma_i + r*zeta_{i,j} + f'(j)
            let zeta_ij = presignature
                .zeta_shares
                .get(&pid)
                .copied()
                .unwrap_or(k256::Scalar::ZERO);
            let chi_ij = m * gamma_i
                + r_x * zeta_ij
                + f_prime_evals
                    .get(&pid)
                    .copied()
                    .unwrap_or(k256::Scalar::ZERO);
            chi_shares.insert(pid, chi_ij);
        }

        // Step 4: D_i = gamma_i * R
        let d_i = r_point * gamma_i;

        // Step 5: A = mG + rX, Gamma_i = gamma_i * A
        let g = k256::Secp256k1::generator();
        let a_point = <k256::ProjectivePoint as LinearCombination<
            [(k256::ProjectivePoint, k256::Scalar); 2],
        >>::lincomb(&[(g, m), (public_key, r_x)]);
        let gamma_i_point = a_point * gamma_i;

        // Step 6: DDH proof for (R, D_i, A, Gamma_i) with witness gamma_i.
        let stmt = DdhStatement::<k256::Secp256k1> {
            g: r_point,
            a: a_point,
            b: d_i,
            c: gamma_i_point,
        };
        let wit = DdhWitness::<k256::Secp256k1> { w: gamma_i };
        let ddh_proof = DdhProof::prove(&stmt, &wit, &mut rng);

        // Build the message to broadcast.
        let my_msg = OnlineRoundMsg {
            delta_shares: delta_shares.clone(),
            chi_shares: chi_shares.clone(),
            d_point: d_i,
            gamma_point: gamma_i_point,
            ddh_proof: ddh_proof.clone(),
        };

        let payload = serialize_online_msg(&my_msg);

        // Queue broadcast to all other parties.
        let mut outgoing = Vec::new();
        for party in &all_parties {
            if *party != my_id {
                outgoing.push(Outgoing {
                    to: Recipient::Party(*party),
                    msg: Tx25OnlineSignMsg::Online(payload.clone()),
                });
            }
        }

        // Store our own message in received.
        let mut received = BTreeMap::new();
        received.insert(my_pid, my_msg);

        Ok(Self {
            my_id,
            all_parties,
            party_ids,
            presignature,
            _message_hash: m,
            message: message_data,
            public_key,
            a_point,
            received,
            outgoing,
            output: None,
            ia_report: None,
            done: false,
        })
    }

    /// Check if all broadcasts have been collected.
    fn all_collected(&self) -> bool {
        self.received.len() == self.all_parties.len()
    }

    /// Attempt to assemble and verify the final signature.
    ///
    /// If verification fails, performs cheater identification.
    fn try_finalize(&mut self) -> tecdsa_core::Result<()> {
        // Collect all deltas and chis indexed by sender party id.
        let mut all_deltas: BTreeMap<u16, BTreeMap<u16, k256::Scalar>> = BTreeMap::new();
        let mut all_chis: BTreeMap<u16, BTreeMap<u16, k256::Scalar>> = BTreeMap::new();

        for (&pid, msg) in &self.received {
            all_deltas.insert(pid, msg.delta_shares.clone());
            all_chis.insert(pid, msg.chi_shares.clone());
        }

        // First attempt: assemble with all parties.
        let r_x = self.presignature.r_x;
        let party_ids = self.party_ids.clone();

        if let Some(s_raw) = assemble_signature(&party_ids, &all_deltas, &all_chis) {
            let s = low_s_normalize::<k256::Secp256k1>(s_raw);
            let sig = Signature { r: r_x, s };

            // Verify the signature.
            if verify_ecdsa::<k256::Secp256k1>(&sig, &self.public_key, &self.message).is_ok() {
                self.output = Some(sig);
                self.done = true;
                return Ok(());
            }
        }

        // Verification failed: perform cheater identification.
        let result = identify_cheaters(
            &party_ids,
            &self.presignature,
            self.a_point,
            self.public_key,
            &self.message,
            &self.received,
            &all_deltas,
            &all_chis,
        );

        match result {
            Ok((Some(sig), report)) => {
                self.output = Some(sig);
                self.ia_report = report;
                self.done = true;
                Ok(())
            }
            Ok((None, report)) => {
                self.ia_report = report;
                self.done = true;
                Err(TecdsaError::Other(
                    "signature verification failed but no cheaters identified".into(),
                ))
            }
            Err(e) => {
                self.done = true;
                Err(e)
            }
        }
    }
}

impl StateMachine for Tx25OnlineSignMachine {
    type Output = Signature<k256::Secp256k1>;
    type Inbound = Tx25OnlineSignMsg;
    type Outbound = Tx25OnlineSignMsg;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        if self.done {
            return Err(TecdsaError::Other("machine already done".into()));
        }

        // Reject messages from self.
        if from == self.my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }

        // Validate sender.
        if !self.all_parties.contains(&from) {
            return Err(TecdsaError::Other(format!("unknown party: {from}")));
        }

        let from_pid = from.0;

        // Reject duplicate.
        if self.received.contains_key(&from_pid) {
            return Err(TecdsaError::Other(format!(
                "duplicate message from party {from}"
            )));
        }

        match msg {
            Tx25OnlineSignMsg::Online(data) => {
                let online_msg = deserialize_online_msg(&data)?;

                // Basic validation: the sender should have shares for all parties.
                for &pid in &self.party_ids {
                    if !online_msg.delta_shares.contains_key(&pid) {
                        return Err(TecdsaError::Other(format!(
                            "missing delta share for party {pid} from {from}"
                        )));
                    }
                    if !online_msg.chi_shares.contains_key(&pid) {
                        return Err(TecdsaError::Other(format!(
                            "missing chi share for party {pid} from {from}"
                        )));
                    }
                }

                self.received.insert(from_pid, online_msg);

                if self.all_collected() {
                    self.try_finalize()?;
                }
            }
        }

        Ok(())
    }

    fn drain_outgoing(&mut self) -> Vec<Outgoing<Self::Outbound>> {
        std::mem::take(&mut self.outgoing)
    }

    fn is_done(&self) -> bool {
        self.done
    }

    fn finish(self) -> tecdsa_core::Result<Self::Output> {
        self.output
            .ok_or_else(|| TecdsaError::Other("online sign not complete".into()))
    }

    fn current_round(&self) -> u16 {
        if self.done {
            4 // presign 2 rounds + online 1 round + done
        } else {
            3 // presign 2 rounds + online round
        }
    }

    fn ia_report(&self) -> Option<&IaReport> {
        self.ia_report.as_ref()
    }
}
