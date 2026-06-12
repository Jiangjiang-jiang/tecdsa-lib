// SPDX-License-Identifier: MIT OR Apache-2.0
//! WMY23 *identifiable* online signing protocol (1 broadcast round).
//!
//! Consumes a [`Wmy23Presignature`] and a message digest to produce a
//! threshold ECDSA signature, faithfully following WMY23 Figures 7-9.
//!
//! Each party broadcasts its additive partial signature
//! `s_i = m * hat_k_i + r * sigma_i` together with, for every counterparty,
//! the MtAwc shares-in-exponent `M_{ij}`, `N_{ij}` and a NIZKDL-2PC proof
//! (`R_DL-2PC`, Fig. 13). After collecting all broadcasts, every party
//! verifies each peer's proofs and the share-consistency equation
//! (WMY23 Equation (3)); only then is `s = sum_i s_i` assembled. A peer
//! whose proofs or equation fail is reported as a cheater via [`IaReport`],
//! so the online phase achieves identifiable abort instead of a silent
//! failure (the previous implementation summed shares with no verification).
//!
//! Reference: Wong, Ma, Yin, Chow. "Real Threshold ECDSA." NDSS 2023,
//! Section V (Figures 7-9) and Section V-D (cheater identification).

pub mod msg;
pub mod rounds;

use msg::Wmy23SignMsg;
use rounds::{
    combine_signatures, compute_contribution, verify_contribution_equation,
    verify_contribution_proofs, SignContribution,
};
use tecdsa_core::TecdsaError;
use tecdsa_protocol::{
    state_machine::Outgoing, AbortReason, DataToSign, IaReport, PartyId, Recipient, Signature,
    StateMachine,
};

use crate::presign::Wmy23Presignature;

/// WMY23 identifiable online signing state machine (1 broadcast round).
pub struct Wmy23OnlineSignMachine {
    my_id: PartyId,
    all_parties: Vec<PartyId>,
    presignature: Wmy23Presignature,
    message: DataToSign<k256::Secp256k1>,
    public_key: k256::ProjectivePoint,
    /// Collected contributions, indexed by quorum-local position.
    contribs: Vec<Option<SignContribution>>,
    outgoing: Vec<Outgoing<Wmy23SignMsg>>,
    output: Option<Signature<k256::Secp256k1>>,
    ia_report: Option<IaReport>,
    done: bool,
}

impl Wmy23OnlineSignMachine {
    /// Create a new WMY23 identifiable online signing state machine.
    ///
    /// Immediately computes this party's contribution (partial signature +
    /// MtAwc shares-in-exponent + NIZKDL-2PC proofs) and queues it for
    /// broadcast.
    ///
    /// # Errors
    ///
    /// Returns an error if this party is not in `all_parties`, or if the
    /// presignature's recorded index does not match this party's position
    /// in `all_parties` (the presign and sign quorums must be identical and
    /// in the same order).
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
        if presignature.index != my_idx {
            return Err(TecdsaError::Other(format!(
                "presignature index {} != quorum position {my_idx}",
                presignature.index
            )));
        }
        if presignature.n_signers != n {
            return Err(TecdsaError::Other(format!(
                "presignature n_signers {} != quorum size {n}",
                presignature.n_signers
            )));
        }

        let mut rng = rand::thread_rng();
        let my_contribution = compute_contribution(&presignature, &message, &mut rng);

        let mut contribs: Vec<Option<SignContribution>> = vec![None; n];
        contribs[my_idx] = Some(my_contribution.clone());

        let payload = msg::serialize_contribution(&my_contribution).map_err(TecdsaError::Other)?;
        let outgoing = all_parties
            .iter()
            .filter(|p| **p != my_id)
            .map(|p| Outgoing {
                to: Recipient::Party(*p),
                msg: Wmy23SignMsg::Round5(payload.clone()),
            })
            .collect();

        Ok(Self {
            my_id,
            all_parties,
            presignature,
            message,
            public_key,
            contribs,
            outgoing,
            output: None,
            ia_report: None,
            done: false,
        })
    }

    fn party_idx(&self, party: PartyId) -> Option<usize> {
        self.all_parties.iter().position(|p| *p == party)
    }

    fn all_collected(&self) -> bool {
        self.contribs.iter().all(Option::is_some)
    }

    /// Verify every party's contribution and either assemble the signature
    /// or record an [`IaReport`] blaming the parties that failed.
    fn verify_and_finish(&mut self) -> tecdsa_core::Result<()> {
        let n = self.all_parties.len();
        let contribs: Vec<SignContribution> = self
            .contribs
            .iter()
            .map(|c| c.clone().expect("all contributions present"))
            .collect();

        // WMY23 Fig. 8 cheater identification, two-phase for correct
        // attribution:
        //   (1) Each M_{ij} is bound to party i by its NIZKDL-2PC proof, so a
        //       proof failure is unambiguously party i's fault. A bad M_{ij}
        //       would also poison party j's equation, so if any proof fails we
        //       blame only the proof owners and stop.
        //   (2) With every M well-formed, an equation failure can only be due
        //       to an inconsistent partial signature s_i (party i's fault).
        let mut blamed: Vec<PartyId> = Vec::new();
        for i in 0..n {
            if !verify_contribution_proofs(&self.presignature, &contribs, i) {
                blamed.push(self.all_parties[i]);
            }
        }
        if blamed.is_empty() {
            for i in 0..n {
                if !verify_contribution_equation(&self.presignature, &self.message, &contribs, i) {
                    blamed.push(self.all_parties[i]);
                }
            }
        }

        if !blamed.is_empty() {
            self.ia_report = Some(IaReport {
                blamed,
                reason: AbortReason::ProtocolSpecific(
                    "WMY23 online signing: NIZKDL-2PC proof or Equation (3) verification failed"
                        .into(),
                ),
            });
            self.done = true;
            return Err(TecdsaError::Other(
                "WMY23 online signing aborted: cheater(s) identified".into(),
            ));
        }

        // WMY23 Fig. 9: s = sum_i s_i, then standard ECDSA verification.
        let sig = combine_signatures(
            &self.presignature,
            &contribs,
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
        if from == self.my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }
        let from_idx = self
            .party_idx(from)
            .ok_or_else(|| TecdsaError::Other(format!("unknown party: {from}")))?;

        match msg {
            Wmy23SignMsg::Round5(data) => {
                if self.contribs[from_idx].is_some() {
                    return Err(TecdsaError::Other(format!(
                        "duplicate message from party {from}"
                    )));
                }
                let n = self.all_parties.len();
                let contribution =
                    msg::deserialize_contribution(&data, n).map_err(TecdsaError::Other)?;
                if contribution.index != from_idx {
                    return Err(TecdsaError::Other(format!(
                        "party {from} claims index {} != {from_idx}",
                        contribution.index
                    )));
                }
                self.contribs[from_idx] = Some(contribution);

                if self.all_collected() {
                    self.verify_and_finish()?;
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
            .ok_or_else(|| TecdsaError::Other("online sign not complete or aborted".into()))
    }

    fn current_round(&self) -> u16 {
        if self.done {
            6
        } else {
            5
        }
    }

    fn ia_report(&self) -> Option<&IaReport> {
        self.ia_report.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use elliptic_curve::CurveArithmetic;
    use tecdsa_curve::TecdsaCurve;

    use super::*;

    /// Create a minimal WMY23 sign machine for message-guard tests.
    ///
    /// The presignature is synthetic, so it will not assemble a valid
    /// signature; the machine never reaches verification in these tests
    /// (which only exercise self/duplicate/unknown message rejection).
    fn make_test_machine(my_pid: u16, party_pids: &[u16]) -> Wmy23OnlineSignMachine {
        let mut rng = rand::thread_rng();
        let all_parties: Vec<PartyId> = party_pids.iter().map(|&p| PartyId(p)).collect();
        let my_idx = party_pids.iter().position(|&p| p == my_pid).unwrap();

        let g = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR;
        let r_scalar = k256::Secp256k1::random_scalar(&mut rng);
        let r_point = g * r_scalar;
        let r_x = <k256::Secp256k1 as TecdsaCurve>::xcoord_mod_q(&r_point.to_affine());
        let n = party_pids.len();

        let presig = Wmy23Presignature {
            k_i: k256::Secp256k1::random_scalar(&mut rng),
            big_r: r_point,
            r_x,
            sigma_i: k256::Secp256k1::random_scalar(&mut rng),
            n_signers: n,
            index: my_idx,
            hat_k_randomness: k256::Scalar::ZERO,
            hat_x_i: k256::Scalar::ZERO,
            mu_shares: vec![None; n],
            nu_points: vec![None; n],
            pc_hat_k: vec![k256::ProjectivePoint::IDENTITY; n],
            big_r_shares: vec![k256::ProjectivePoint::IDENTITY; n],
            xhat_points: vec![k256::ProjectivePoint::IDENTITY; n],
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
        let result = machine.handle(PartyId(1), Wmy23SignMsg::Round5(vec![0u8; 4]));
        let err = result.expect_err("should reject self-message");
        assert!(format!("{err}").contains("from self"));
    }

    #[test]
    fn sign_rejects_unknown_party() {
        let mut machine = make_test_machine(1, &[1, 2, 3]);
        let _out = machine.drain_outgoing();
        let result = machine.handle(PartyId(99), Wmy23SignMsg::Round5(vec![0u8; 4]));
        let err = result.expect_err("should reject unknown party");
        assert!(format!("{err}").contains("unknown party"));
    }
}
