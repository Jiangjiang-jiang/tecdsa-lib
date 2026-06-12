use elliptic_curve::{sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField};
use rand_core::CryptoRngCore;
use tecdsa_curve::{
    elgamal_exp::EgexpCiphertext,
    zk::ddh::{DdhProof, DdhStatement, DdhWitness},
    TecdsaCurve,
};
use tecdsa_protocol::PartyId;

pub struct ElementOutMsg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub from: PartyId,
    pub a_i_point: C::ProjectivePoint,
    pub proof: DdhProof<C>,
}

impl<C: TecdsaCurve> Clone for ElementOutMsg<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn clone(&self) -> Self {
        Self {
            from: self.from,
            a_i_point: self.a_i_point,
            proof: self.proof.clone(),
        }
    }
}

pub struct ElementOutOutput<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub element: C::ProjectivePoint,
}

pub struct ElementOutState<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    my_id: PartyId,
    parties: Vec<PartyId>,
    a_i: C::Scalar,
    #[allow(dead_code)]
    s_i: C::Scalar,
    per_party_cts: Vec<(PartyId, EgexpCiphertext<C>)>,
    elgamal_pk: C::ProjectivePoint,
}

impl<C: TecdsaCurve> ElementOutState<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    pub fn new(
        my_id: PartyId,
        parties: Vec<PartyId>,
        a_i: C::Scalar,
        s_i: C::Scalar,
        per_party_cts: Vec<(PartyId, EgexpCiphertext<C>)>,
        elgamal_pk: C::ProjectivePoint,
        rng: &mut impl CryptoRngCore,
    ) -> (Self, ElementOutMsg<C>) {
        assert!(parties.contains(&my_id), "parties list must contain my_id");

        let a_i_point = C::generator() * a_i;

        let own_ct = per_party_cts
            .iter()
            .find(|(pid, _)| *pid == my_id)
            .expect("per_party_cts must contain own ciphertext")
            .1
            .clone();

        let stmt = DdhStatement::<C> {
            g: C::generator(),
            a: elgamal_pk,
            b: own_ct.a,
            c: own_ct.b - a_i_point,
        };
        let wit = DdhWitness::<C> { w: s_i };
        let proof = DdhProof::prove(&stmt, &wit, rng);

        let msg = ElementOutMsg {
            from: my_id,
            a_i_point,
            proof,
        };

        let state = Self {
            my_id,
            parties,
            a_i,
            s_i,
            per_party_cts,
            elgamal_pk,
        };

        (state, msg)
    }

    pub fn finish(&self, msgs: &[ElementOutMsg<C>]) -> Result<ElementOutOutput<C>, String> {
        let n = self.parties.len();
        let mut a_points: Vec<Option<C::ProjectivePoint>> = vec![None; n];

        let my_index = self.parties.iter().position(|p| *p == self.my_id).unwrap();
        let own_a_point = C::generator() * self.a_i;
        a_points[my_index] = Some(own_a_point);

        for msg in msgs {
            if msg.from == self.my_id {
                continue;
            }
            let idx = self
                .parties
                .iter()
                .position(|p| *p == msg.from)
                .ok_or_else(|| format!("unknown party {}", msg.from))?;
            if a_points[idx].is_some() {
                return Err(format!("duplicate message from {}", msg.from));
            }

            let ct_j = self
                .per_party_cts
                .iter()
                .find(|(pid, _)| *pid == msg.from)
                .ok_or_else(|| format!("no ciphertext for party {}", msg.from))?
                .1
                .clone();

            let stmt = DdhStatement::<C> {
                g: C::generator(),
                a: self.elgamal_pk,
                b: ct_j.a,
                c: ct_j.b - msg.a_i_point,
            };
            if !msg.proof.verify(&stmt) {
                return Err(format!("R_DH proof verification failed for {}", msg.from));
            }

            a_points[idx] = Some(msg.a_i_point);
        }

        for (i, slot) in a_points.iter().enumerate() {
            if slot.is_none() {
                return Err(format!("missing message from {}", self.parties[i]));
            }
        }

        let element = a_points
            .into_iter()
            .map(|s| s.unwrap())
            .reduce(|acc, p| acc + p)
            .expect("at least one party");

        Ok(ElementOutOutput { element })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "secp256k1")]
    type C = k256::Secp256k1;

    #[cfg(feature = "secp256k1")]
    fn run_element_out(n: usize) {
        use crate::f_mult::{init::InitState, input::InputState};

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
        let mut input_r1_msgs = Vec::with_capacity(n);
        for i in 0..n {
            let (state, msg) =
                InputState::<C>::new(parties[i], parties.clone(), elgamal_pk, shares[i], &mut rng);
            input_states.push(state);
            input_r1_msgs.push(msg);
        }

        let mut input_r2_msgs = Vec::with_capacity(n);
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

        let mut input_outputs = Vec::with_capacity(n);
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

        let mut eo_states: Vec<ElementOutState<C>> = Vec::with_capacity(n);
        let mut eo_msgs: Vec<ElementOutMsg<C>> = Vec::with_capacity(n);
        for i in 0..n {
            let (state, msg) = ElementOutState::<C>::new(
                parties[i],
                parties.clone(),
                input_outputs[i].a_i,
                input_outputs[i].s_i,
                input_outputs[i].per_party_cts.clone(),
                elgamal_pk,
                &mut rng,
            );
            eo_states.push(state);
            eo_msgs.push(msg);
        }

        let mut eo_outputs: Vec<ElementOutOutput<C>> = Vec::with_capacity(n);
        for i in 0..n {
            let others: Vec<_> = eo_msgs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, m)| m.clone())
                .collect();
            let output = eo_states[i]
                .finish(&others)
                .expect("element-out should succeed");
            eo_outputs.push(output);
        }

        let a0 = eo_outputs[0].element;
        for output in &eo_outputs[1..] {
            assert_eq!(
                output.element, a0,
                "all parties must agree on the revealed element A"
            );
        }

        let expected_sum: <C as elliptic_curve::CurveArithmetic>::Scalar =
            shares.iter().copied().reduce(|acc, s| acc + s).unwrap();
        let expected_point = C::generator() * expected_sum;
        assert_eq!(
            a0, expected_point,
            "element-out result must equal sum(a_i) * G"
        );
    }

    #[test]
    #[cfg(feature = "secp256k1")]
    fn element_out_2of2() {
        run_element_out(2);
    }

    #[test]
    #[cfg(feature = "secp256k1")]
    fn element_out_3of3() {
        run_element_out(3);
    }
}
