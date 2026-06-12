use elliptic_curve::{
    group::GroupEncoding, sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField,
};
use rand_core::CryptoRngCore;
use tecdsa_commit::HashCommitment;
use tecdsa_curve::{
    elgamal_exp::{self, EgexpCiphertext},
    zk::egexp::{EgexpProof, EgexpStatement, EgexpWitness},
    TecdsaCurve,
};
use tecdsa_protocol::PartyId;

#[derive(Clone)]
pub struct InputRound1Msg {
    pub from: PartyId,
    pub commitment: HashCommitment,
}

pub struct InputRound2Msg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub from: PartyId,
    pub ciphertext: EgexpCiphertext<C>,
    pub proof: EgexpProof<C>,
    pub nonce: [u8; 32],
}

impl<C: TecdsaCurve> Clone for InputRound2Msg<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn clone(&self) -> Self {
        Self {
            from: self.from,
            ciphertext: self.ciphertext.clone(),
            proof: self.proof.clone(),
            nonce: self.nonce,
        }
    }
}

pub struct InputState<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    my_id: PartyId,
    parties: Vec<PartyId>,
    elgamal_pk: C::ProjectivePoint,
    a_i: C::Scalar,
    s_i: C::Scalar,
    own_ct: EgexpCiphertext<C>,
    own_proof: EgexpProof<C>,
    decommit_nonce: [u8; 32],
    round1_commitments: Vec<Option<HashCommitment>>,
}

pub struct InputOutput<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub ciphertext: EgexpCiphertext<C>,
    pub a_i: C::Scalar,
    pub s_i: C::Scalar,
    pub per_party_cts: Vec<(PartyId, EgexpCiphertext<C>)>,
}

impl<C: TecdsaCurve> Clone for InputOutput<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn clone(&self) -> Self {
        Self {
            ciphertext: self.ciphertext.clone(),
            a_i: self.a_i,
            s_i: self.s_i,
            per_party_cts: self.per_party_cts.clone(),
        }
    }
}

fn serialize_input_commitment_payload<C: TecdsaCurve>(
    ct: &EgexpCiphertext<C>,
    proof: &EgexpProof<C>,
) -> Vec<u8>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let mut payload = Vec::new();
    payload.extend_from_slice(ct.a.to_bytes().as_ref());
    payload.extend_from_slice(ct.b.to_bytes().as_ref());
    payload.extend_from_slice(proof.commit_x.to_bytes().as_ref());
    payload.extend_from_slice(proof.commit_y.to_bytes().as_ref());
    let z1_repr = proof.z1.to_repr();
    payload.extend_from_slice(AsRef::<[u8]>::as_ref(&z1_repr));
    let z2_repr = proof.z2.to_repr();
    payload.extend_from_slice(AsRef::<[u8]>::as_ref(&z2_repr));
    payload
}

impl<C: TecdsaCurve> InputState<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    pub fn new(
        my_id: PartyId,
        parties: Vec<PartyId>,
        elgamal_pk: C::ProjectivePoint,
        a_i: C::Scalar,
        rng: &mut impl CryptoRngCore,
    ) -> (Self, InputRound1Msg) {
        assert!(parties.contains(&my_id), "parties list must contain my_id");

        let (ct, s_i) = elgamal_exp::encrypt_random::<C>(&elgamal_pk, &a_i, rng);

        let stmt = EgexpStatement::<C> {
            p: elgamal_pk,
            a: ct.a,
            b: ct.b,
        };
        let witness = EgexpWitness::<C> { x: a_i, r: s_i };
        let proof = EgexpProof::prove(&stmt, &witness, rng);

        let payload = serialize_input_commitment_payload::<C>(&ct, &proof);
        let (commitment, nonce) = HashCommitment::commit(&payload, rng);

        let n = parties.len();
        let my_index = parties.iter().position(|p| *p == my_id).unwrap();
        let mut round1_commitments = vec![None; n];
        round1_commitments[my_index] = Some(commitment.clone());

        let round1_msg = InputRound1Msg {
            from: my_id,
            commitment,
        };

        let state = Self {
            my_id,
            parties,
            elgamal_pk,
            a_i,
            s_i,
            own_ct: ct,
            own_proof: proof,
            decommit_nonce: nonce,
            round1_commitments,
        };

        (state, round1_msg)
    }

    pub fn handle_round1(&mut self, msgs: &[InputRound1Msg]) -> Result<InputRound2Msg<C>, String> {
        for msg in msgs {
            if msg.from == self.my_id {
                continue;
            }
            let idx = self
                .parties
                .iter()
                .position(|p| *p == msg.from)
                .ok_or_else(|| format!("unknown party {}", msg.from))?;
            if self.round1_commitments[idx].is_some() {
                return Err(format!("duplicate Round-1 message from {}", msg.from));
            }
            self.round1_commitments[idx] = Some(msg.commitment.clone());
        }

        for (i, slot) in self.round1_commitments.iter().enumerate() {
            if slot.is_none() {
                return Err(format!("missing Round-1 message from {}", self.parties[i]));
            }
        }

        Ok(InputRound2Msg {
            from: self.my_id,
            ciphertext: self.own_ct.clone(),
            proof: self.own_proof.clone(),
            nonce: self.decommit_nonce,
        })
    }

    pub fn finish_round2(&self, msgs: &[InputRound2Msg<C>]) -> Result<InputOutput<C>, String> {
        let n = self.parties.len();
        let mut per_party_cts: Vec<Option<(PartyId, EgexpCiphertext<C>)>> = vec![None; n];

        let my_index = self.parties.iter().position(|p| *p == self.my_id).unwrap();
        per_party_cts[my_index] = Some((self.my_id, self.own_ct.clone()));

        for msg in msgs {
            if msg.from == self.my_id {
                continue;
            }
            let idx = self
                .parties
                .iter()
                .position(|p| *p == msg.from)
                .ok_or_else(|| format!("unknown party {}", msg.from))?;
            if per_party_cts[idx].is_some() {
                return Err(format!("duplicate Round-2 message from {}", msg.from));
            }

            let payload = serialize_input_commitment_payload::<C>(&msg.ciphertext, &msg.proof);
            let commitment = self.round1_commitments[idx]
                .as_ref()
                .expect("round1 commitments must be filled");
            if !commitment.verify(&payload, &msg.nonce) {
                return Err(format!(
                    "input commitment verification failed for {}",
                    msg.from
                ));
            }

            let stmt = EgexpStatement::<C> {
                p: self.elgamal_pk,
                a: msg.ciphertext.a,
                b: msg.ciphertext.b,
            };
            if !msg.proof.verify(&stmt) {
                return Err(format!("R_EG proof verification failed for {}", msg.from));
            }

            per_party_cts[idx] = Some((msg.from, msg.ciphertext.clone()));
        }

        for (i, slot) in per_party_cts.iter().enumerate() {
            if slot.is_none() {
                return Err(format!("missing Round-2 message from {}", self.parties[i]));
            }
        }

        let per_party: Vec<(PartyId, EgexpCiphertext<C>)> =
            per_party_cts.into_iter().map(|s| s.unwrap()).collect();

        let aggregate = per_party
            .iter()
            .map(|(_, ct)| ct.clone())
            .reduce(|acc, ct| acc.add(&ct))
            .expect("at least one party");

        Ok(InputOutput {
            ciphertext: aggregate,
            a_i: self.a_i,
            s_i: self.s_i,
            per_party_cts: per_party,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "secp256k1")]
    type C = k256::Secp256k1;

    #[cfg(feature = "secp256k1")]
    fn run_input(n: usize) {
        use crate::f_mult::init::InitState;

        let mut rng = rand::thread_rng();
        let parties: Vec<PartyId> = (0..n).map(|i| PartyId(i as u16)).collect();

        let mut init_states: Vec<InitState<C>> = Vec::with_capacity(n);
        let mut r1_msgs = Vec::with_capacity(n);
        for i in 0..n {
            let (state, msg) = InitState::<C>::new(parties[i], parties.clone(), &mut rng);
            init_states.push(state);
            r1_msgs.push(msg);
        }

        let mut r2_msgs = Vec::with_capacity(n);
        for i in 0..n {
            let others: Vec<_> = r1_msgs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, m)| m.clone())
                .collect();
            let r2 = init_states[i]
                .handle_round1(&others)
                .expect("init Round-1 should succeed");
            r2_msgs.push(r2);
        }

        let mut init_outputs = Vec::with_capacity(n);
        for i in 0..n {
            let others: Vec<_> = r2_msgs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, m)| m.clone())
                .collect();
            let output = init_states[i]
                .finish_round2(&others)
                .expect("init Round-2 should succeed");
            init_outputs.push(output);
        }

        let elgamal_pk = init_outputs[0].elgamal_pk;

        let shares: Vec<<C as elliptic_curve::CurveArithmetic>::Scalar> =
            (0..n).map(|_| C::random_scalar(&mut rng)).collect();

        let mut input_states: Vec<InputState<C>> = Vec::with_capacity(n);
        let mut input_r1_msgs: Vec<InputRound1Msg> = Vec::with_capacity(n);
        for i in 0..n {
            let (state, msg) =
                InputState::<C>::new(parties[i], parties.clone(), elgamal_pk, shares[i], &mut rng);
            input_states.push(state);
            input_r1_msgs.push(msg);
        }

        let mut input_r2_msgs: Vec<InputRound2Msg<C>> = Vec::with_capacity(n);
        for i in 0..n {
            let others: Vec<_> = input_r1_msgs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, m)| m.clone())
                .collect();
            let r2 = input_states[i]
                .handle_round1(&others)
                .expect("input Round-1 should succeed");
            input_r2_msgs.push(r2);
        }

        let mut input_outputs: Vec<InputOutput<C>> = Vec::with_capacity(n);
        for i in 0..n {
            let others: Vec<_> = input_r2_msgs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, m)| m.clone())
                .collect();
            let output = input_states[i]
                .finish_round2(&others)
                .expect("input Round-2 should succeed");
            input_outputs.push(output);
        }

        let ct0 = &input_outputs[0].ciphertext;
        for output in &input_outputs[1..] {
            assert_eq!(
                output.ciphertext, *ct0,
                "all parties must agree on the aggregate ciphertext"
            );
        }

        let d: <C as elliptic_curve::CurveArithmetic>::Scalar = init_outputs
            .iter()
            .map(|o| o.d_i)
            .reduce(|acc, d| acc + d)
            .unwrap();

        let decrypted = ct0.decrypt_to_point(&d);
        let expected_sum: <C as elliptic_curve::CurveArithmetic>::Scalar =
            shares.iter().copied().reduce(|acc, s| acc + s).unwrap();
        let expected_point = C::generator() * expected_sum;
        assert_eq!(
            decrypted, expected_point,
            "aggregate ciphertext must decrypt to (sum a_i) * G"
        );

        for output in &input_outputs {
            assert_eq!(
                output.per_party_cts.len(),
                n,
                "should have n per-party ciphertexts"
            );
        }

        for (i, output) in input_outputs.iter().enumerate() {
            assert_eq!(output.a_i, shares[i], "own share must be preserved");
        }
    }

    #[test]
    #[cfg(feature = "secp256k1")]
    fn input_2of2() {
        run_input(2);
    }

    #[test]
    #[cfg(feature = "secp256k1")]
    fn input_3of3() {
        run_input(3);
    }
}
