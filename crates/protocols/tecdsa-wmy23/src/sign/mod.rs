// SPDX-License-Identifier: GPL-3.0-or-later
//! WMY23 online signing protocol (Round 5, 1 round).
//!
//! Consumes a [`Wmy23Presignature`] and a message digest to produce a
//! threshold ECDSA signature in a single round of interaction.
//!
//! Each party computes its partial signature $s_i$ and broadcasts it.
//! After collecting all partial signatures, the final signature is
//! assembled: $s = \sum s_i \bmod q$.
//!
//! ## StateMachine implementation
//!
//! With bicycl-rs v0.2.1, `Wmy23Presignature` is `Send` (it contains
//! only scalars and EC points), so the `StateMachine: Send + 'static`
//! bound is satisfied.
//!
//! The machine immediately computes the partial signature on construction
//! and queues it for broadcast.  As partial signatures arrive from other
//! parties, they are collected.  Once all `n_signers` partials are
//! available, the final signature is assembled and verified.
//!
//! Reference: Wang, Mei, Yu. "Real Threshold ECDSA." NDSS 2023, Section 3.4.

pub mod msg;
pub mod rounds;

use elliptic_curve::PrimeField;
use tecdsa_core::TecdsaError;
use tecdsa_protocol::{
    state_machine::Outgoing, DataToSign, IaReport, PartyId, Signature, StateMachine,
};

use crate::presign::Wmy23Presignature;
use msg::Wmy23SignMsg;
use rounds::{combine_signatures, compute_partial_signature, PartialSignature};

/// WMY23 online signing state machine (1 round).
///
/// On construction, computes the local partial signature and queues it
/// for broadcast.  Collects partial signatures from other parties and
/// assembles the final signature once all are received.
pub struct Wmy23OnlineSignMachine {
    my_id: PartyId,
    all_parties: Vec<PartyId>,
    /// The presignature consumed by this signing session.
    presignature: Wmy23Presignature,
    /// The message being signed.
    message: DataToSign<k256::Secp256k1>,
    /// The ECDSA public key (for final verification).
    public_key: k256::ProjectivePoint,
    /// Collected partial signatures, indexed by party order.
    partials: Vec<Option<PartialSignature>>,
    /// Outgoing messages to drain.
    outgoing: Vec<Outgoing<Wmy23SignMsg>>,
    /// Final output.
    output: Option<Signature<k256::Secp256k1>>,
    done: bool,
}

impl Wmy23OnlineSignMachine {
    /// Create a new WMY23 online signing state machine.
    ///
    /// Immediately computes this party's partial signature and queues it
    /// for broadcast to all other parties.
    ///
    /// # Arguments
    ///
    /// * `my_id` - This party's identifier.
    /// * `all_parties` - All signing party identifiers in consistent order.
    /// * `presignature` - This party's presignature output.
    /// * `message` - The message digest to sign.
    /// * `public_key` - The joint ECDSA public key (for verification).
    ///
    /// # Errors
    ///
    /// Returns an error if this party is not in `all_parties`.
    pub fn new(
        my_id: PartyId,
        all_parties: Vec<PartyId>,
        presignature: Wmy23Presignature,
        message: DataToSign<k256::Secp256k1>,
        public_key: k256::ProjectivePoint,
    ) -> tecdsa_core::Result<Self> {
        let n = all_parties.len();
        let my_idx = all_parties
            .iter()
            .position(|p| *p == my_id)
            .ok_or_else(|| TecdsaError::Other("my_id not found in all_parties".into()))?;

        // Compute our partial signature
        let my_partial = compute_partial_signature(&presignature, &message);

        // Store it
        let mut partials: Vec<Option<PartialSignature>> = vec![None; n];
        partials[my_idx] = Some(my_partial.clone());

        // Serialize as raw 32-byte scalar
        let payload = my_partial.s_i.to_repr().to_vec();

        let mut outgoing = Vec::new();
        for party in &all_parties {
            if *party != my_id {
                outgoing.push(Outgoing {
                    to: tecdsa_protocol::Recipient::Party(*party),
                    msg: Wmy23SignMsg::Round5(payload.clone()),
                });
            }
        }

        Ok(Self {
            my_id,
            all_parties,
            presignature,
            message,
            public_key,
            partials,
            outgoing,
            output: None,
            done: false,
        })
    }

    /// Returns the index of a given party.
    fn party_idx(&self, party: PartyId) -> Option<usize> {
        self.all_parties.iter().position(|p| *p == party)
    }

    /// Check if all partials have been collected.
    fn all_collected(&self) -> bool {
        self.partials.iter().all(|p| p.is_some())
    }

    /// Assemble the final signature.
    fn assemble_signature(&mut self) -> tecdsa_core::Result<()> {
        let partials: Vec<PartialSignature> = self
            .partials
            .iter()
            .map(|p| p.clone().expect("all partials should be present"))
            .collect();

        let sig = combine_signatures(
            &partials,
            &self.presignature,
            &self.message,
            &self.public_key,
        )
        .map_err(|e| TecdsaError::Other(format!("combine_signatures failed: {e}")))?;

        self.output = Some(sig);
        self.done = true;
        Ok(())
    }
}

impl StateMachine for Wmy23OnlineSignMachine {
    type Output = Signature<k256::Secp256k1>;
    type Inbound = Wmy23SignMsg;
    type Outbound = Wmy23SignMsg;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        // Reject messages from self.
        if from == self.my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }

        let from_idx = self
            .party_idx(from)
            .ok_or_else(|| TecdsaError::Other(format!("unknown party: {from}")))?;

        match msg {
            Wmy23SignMsg::Round5(data) => {
                if data.len() != 32 {
                    return Err(TecdsaError::Other(
                        "invalid partial signature length".into(),
                    ));
                }

                // Reject duplicate messages.
                if self.partials[from_idx].is_some() {
                    return Err(TecdsaError::Other(format!(
                        "duplicate message from party {from}"
                    )));
                }

                let mut repr = k256::FieldBytes::default();
                repr.copy_from_slice(&data);
                let s_i = k256::Scalar::from_repr(repr)
                    .into_option()
                    .ok_or_else(|| TecdsaError::Other("invalid scalar in partial sig".into()))?;

                self.partials[from_idx] = Some(PartialSignature { s_i });

                if self.all_collected() {
                    self.assemble_signature()?;
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
            6
        } else {
            5
        }
    }

    fn ia_report(&self) -> Option<&IaReport> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use elliptic_curve::CurveArithmetic;
    use tecdsa_curve::TecdsaCurve;

    /// Create a minimal WMY23 sign machine for validation tests.
    ///
    /// The presignature is synthetic (random scalars), so it will not
    /// produce a valid ECDSA signature. This is sufficient for testing
    /// message-validation guards (self, duplicate, unknown).
    fn make_test_machine(my_pid: u16, party_pids: &[u16]) -> Wmy23OnlineSignMachine {
        let mut rng = rand::thread_rng();
        let all_parties: Vec<PartyId> = party_pids.iter().map(|&p| PartyId(p)).collect();

        let g = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR;
        let r_scalar = k256::Secp256k1::random_scalar(&mut rng);
        let r_point = g * r_scalar;
        let r_affine = r_point.to_affine();
        let r_x = <k256::Secp256k1 as TecdsaCurve>::xcoord_mod_q(&r_affine);

        let presig = Wmy23Presignature {
            k_i: k256::Secp256k1::random_scalar(&mut rng),
            big_r: r_point,
            r_x,
            sigma_i: k256::Secp256k1::random_scalar(&mut rng),
            n_signers: party_pids.len(),
        };

        let m = k256::Secp256k1::random_scalar(&mut rng);
        let message = DataToSign::from_digest(m);
        let public_key = g * k256::Secp256k1::random_scalar(&mut rng);

        Wmy23OnlineSignMachine::new(PartyId(my_pid), all_parties, presig, message, public_key)
            .expect("machine creation should succeed")
    }

    #[test]
    fn sign_rejects_self_message() {
        let mut machine = make_test_machine(1, &[1, 2, 3]);
        let _out = machine.drain_outgoing();

        let dummy_scalar = k256::Scalar::ONE.to_repr().to_vec();
        let result = machine.handle(PartyId(1), Wmy23SignMsg::Round5(dummy_scalar));
        let err = result.expect_err("should reject self-message");
        let msg = format!("{err}");
        assert!(
            msg.contains("from self"),
            "error should mention from self, got: {msg}"
        );
    }

    #[test]
    fn sign_rejects_duplicate_message() {
        let mut machine = make_test_machine(1, &[1, 2, 3]);
        let _out = machine.drain_outgoing();

        let dummy_scalar = k256::Scalar::ONE.to_repr().to_vec();

        // First message from party 2 should succeed.
        machine
            .handle(PartyId(2), Wmy23SignMsg::Round5(dummy_scalar.clone()))
            .expect("first message should succeed");

        // Second message from party 2 should fail as duplicate.
        let result = machine.handle(PartyId(2), Wmy23SignMsg::Round5(dummy_scalar));
        let err = result.expect_err("should reject duplicate message");
        let msg = format!("{err}");
        assert!(
            msg.contains("duplicate"),
            "error should mention duplicate, got: {msg}"
        );
    }

    #[test]
    fn sign_rejects_unknown_party() {
        let mut machine = make_test_machine(1, &[1, 2, 3]);
        let _out = machine.drain_outgoing();

        let dummy_scalar = k256::Scalar::ONE.to_repr().to_vec();
        let result = machine.handle(PartyId(99), Wmy23SignMsg::Round5(dummy_scalar));
        let err = result.expect_err("should reject unknown party");
        let msg = format!("{err}");
        assert!(
            msg.contains("unknown party"),
            "error should mention unknown party, got: {msg}"
        );
    }
}
