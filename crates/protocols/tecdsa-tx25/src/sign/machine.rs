use std::collections::BTreeMap;

use elliptic_curve::ops::LinearCombination;
use tecdsa_core::TecdsaError;
use tecdsa_curve::{
    zk::ddh::{DdhProof, DdhStatement, DdhWitness},
    TecdsaCurve,
};
use tecdsa_protocol::{
    ecdsa::{low_s_normalize, verify_ecdsa, DataToSign, Signature},
    state_machine::Outgoing,
    IaReport, PartyId, Recipient, StateMachine,
};

use super::{
    msg::{deserialize_online_msg, serialize_online_msg, OnlineRoundMsg, Tx25OnlineSignMsg},
    rounds::{assemble_signature, hash_message_to_scalar, identify_cheaters, zero_poly_eval},
};
use crate::presign::Tx25Presignature;

pub struct Tx25OnlineSignMachine {
    my_id: PartyId,
    all_parties: Vec<PartyId>,
    party_ids: Vec<u16>,
    presignature: Tx25Presignature,
    _message_hash: k256::Scalar,
    message: DataToSign<k256::Secp256k1>,
    public_key: k256::ProjectivePoint,
    a_point: k256::ProjectivePoint,
    received: BTreeMap<u16, OnlineRoundMsg>,
    outgoing: Vec<Outgoing<Tx25OnlineSignMsg>>,
    output: Option<Signature<k256::Secp256k1>>,
    ia_report: Option<IaReport>,
    done: bool,
}

impl Tx25OnlineSignMachine {
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

        let m = hash_message_to_scalar(message);
        let message_data = DataToSign::from_digest(m);

        let r_x = presignature.r_x;
        let gamma_i = presignature.gamma_i;
        let r_point = presignature.r_point;

        let mut rng = rand::thread_rng();
        let f_evals = zero_poly_eval(t, &party_ids, &mut rng);
        let f_prime_evals = zero_poly_eval(t, &party_ids, &mut rng);

        let mut delta_shares = BTreeMap::new();
        let mut chi_shares = BTreeMap::new();

        for &pid in &party_ids {
            let base_delta = presignature
                .delta_shares
                .get(&pid)
                .copied()
                .unwrap_or(k256::Scalar::ZERO);
            let masked_delta =
                base_delta + f_evals.get(&pid).copied().unwrap_or(k256::Scalar::ZERO);
            delta_shares.insert(pid, masked_delta);

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

        let d_i = r_point * gamma_i;

        let g = k256::Secp256k1::generator();
        let a_point = <k256::ProjectivePoint as LinearCombination<
            [(k256::ProjectivePoint, k256::Scalar); 2],
        >>::lincomb(&[(g, m), (public_key, r_x)]);
        let gamma_i_point = a_point * gamma_i;

        let stmt = DdhStatement::<k256::Secp256k1> {
            g: r_point,
            a: a_point,
            b: d_i,
            c: gamma_i_point,
        };
        let wit = DdhWitness::<k256::Secp256k1> { w: gamma_i };
        let ddh_proof = DdhProof::prove(&stmt, &wit, &mut rng);

        let my_msg = OnlineRoundMsg {
            delta_shares: delta_shares.clone(),
            chi_shares: chi_shares.clone(),
            d_point: d_i,
            gamma_point: gamma_i_point,
            ddh_proof: ddh_proof.clone(),
        };

        let payload = serialize_online_msg(&my_msg);

        let mut outgoing = Vec::new();
        for party in &all_parties {
            if *party != my_id {
                outgoing.push(Outgoing {
                    to: Recipient::Party(*party),
                    msg: Tx25OnlineSignMsg::Online(payload.clone()),
                });
            }
        }

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

    fn all_collected(&self) -> bool {
        self.received.len() == self.all_parties.len()
    }

    fn try_finalize(&mut self) -> tecdsa_core::Result<()> {
        let mut all_deltas: BTreeMap<u16, BTreeMap<u16, k256::Scalar>> = BTreeMap::new();
        let mut all_chis: BTreeMap<u16, BTreeMap<u16, k256::Scalar>> = BTreeMap::new();

        for (&pid, msg) in &self.received {
            all_deltas.insert(pid, msg.delta_shares.clone());
            all_chis.insert(pid, msg.chi_shares.clone());
        }

        let r_x = self.presignature.r_x;
        let party_ids = self.party_ids.clone();

        if let Some(s_raw) = assemble_signature(&party_ids, &all_deltas, &all_chis) {
            let s = low_s_normalize::<k256::Secp256k1>(s_raw);
            let sig = Signature { r: r_x, s };

            if verify_ecdsa::<k256::Secp256k1>(&sig, &self.public_key, &self.message).is_ok() {
                self.output = Some(sig);
                self.done = true;
                return Ok(());
            }
        }

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

        if from == self.my_id {
            return Err(TecdsaError::Other("received message from self".into()));
        }

        if !self.all_parties.contains(&from) {
            return Err(TecdsaError::Other(format!("unknown party: {from}")));
        }

        let from_pid = from.0;

        if self.received.contains_key(&from_pid) {
            return Err(TecdsaError::Other(format!(
                "duplicate message from party {from}"
            )));
        }

        match msg {
            Tx25OnlineSignMsg::Online(data) => {
                let online_msg = deserialize_online_msg(&data)?;

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
            4
        } else {
            3
        }
    }

    fn ia_report(&self) -> Option<&IaReport> {
        self.ia_report.as_ref()
    }
}
