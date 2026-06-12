use elliptic_curve::{sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField};
use rand_core::CryptoRngCore;
use tecdsa_curve::{
    zk::{
        ddh::{DdhProof, DdhStatement, DdhWitness},
        rerandom::{ReProof, ReStatement, ReWitness},
    },
    TecdsaCurve,
};
use tecdsa_protocol::PartyId;

pub struct CheckDhRound1Msg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub from: PartyId,
    pub u_prime_i: C::ProjectivePoint,
    pub v_prime_i: C::ProjectivePoint,
    pub re_proof: ReProof<C>,
}

impl<C: TecdsaCurve> Clone for CheckDhRound1Msg<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn clone(&self) -> Self {
        Self {
            from: self.from,
            u_prime_i: self.u_prime_i,
            v_prime_i: self.v_prime_i,
            re_proof: self.re_proof.clone(),
        }
    }
}

pub struct CheckDhRound2Msg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub from: PartyId,
    pub w_i: C::ProjectivePoint,
    pub ddh_proof: DdhProof<C>,
}

impl<C: TecdsaCurve> Clone for CheckDhRound2Msg<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn clone(&self) -> Self {
        Self {
            from: self.from,
            w_i: self.w_i,
            ddh_proof: self.ddh_proof.clone(),
        }
    }
}

pub struct CheckDhState<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    my_id: PartyId,
    parties: Vec<PartyId>,
    d_i: C::Scalar,
    p_i: C::ProjectivePoint,
    elgamal_pk: C::ProjectivePoint,
    elgamal_pk_shares: Vec<C::ProjectivePoint>,
    u: C::ProjectivePoint,
    v: C::ProjectivePoint,
    own_u_prime_i: C::ProjectivePoint,
    own_v_prime_i: C::ProjectivePoint,
}

impl<C: TecdsaCurve> CheckDhState<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    pub fn new(
        my_id: PartyId,
        parties: Vec<PartyId>,
        d_i: C::Scalar,
        elgamal_pk: C::ProjectivePoint,
        elgamal_pk_shares: Vec<C::ProjectivePoint>,
        u: C::ProjectivePoint,
        v: C::ProjectivePoint,
        rng: &mut impl CryptoRngCore,
    ) -> (Self, CheckDhRound1Msg<C>) {
        assert!(parties.contains(&my_id), "parties list must contain my_id");
        assert_eq!(
            elgamal_pk_shares.len(),
            parties.len(),
            "must have one pk share per party"
        );

        let g = C::generator();
        let p_i = g * d_i;

        let r_i = C::random_scalar(rng);
        let s_i = C::random_scalar(rng);

        let u_prime_i = g * r_i + u * s_i;
        let v_prime_i = elgamal_pk * r_i + v * s_i;

        let re_stmt = ReStatement::<C> {
            g,
            p: elgamal_pk,
            a: u,
            b: v,
            a_prime: u_prime_i,
            b_prime: v_prime_i,
        };
        let re_wit = ReWitness::<C> { r: r_i, s: s_i };
        let sigma = C::random_scalar(rng);
        let tau = C::random_scalar(rng);
        let re_proof = ReProof::prove(&re_stmt, &re_wit, &sigma, &tau);

        let round1_msg = CheckDhRound1Msg {
            from: my_id,
            u_prime_i,
            v_prime_i,
            re_proof,
        };

        let state = Self {
            my_id,
            parties,
            d_i,
            p_i,
            elgamal_pk,
            elgamal_pk_shares,
            u,
            v,
            own_u_prime_i: u_prime_i,
            own_v_prime_i: v_prime_i,
        };

        (state, round1_msg)
    }

    pub fn handle_round1(
        &self,
        msgs: &[CheckDhRound1Msg<C>],
        rng: &mut impl CryptoRngCore,
    ) -> Result<(CheckDhRound2Msg<C>, AggregatedRerand<C>), String> {
        let n = self.parties.len();
        let g = C::generator();

        let mut u_primes: Vec<Option<C::ProjectivePoint>> = vec![None; n];
        let mut v_primes: Vec<Option<C::ProjectivePoint>> = vec![None; n];

        let my_index = self.parties.iter().position(|p| *p == self.my_id).unwrap();
        u_primes[my_index] = Some(self.own_u_prime_i);
        v_primes[my_index] = Some(self.own_v_prime_i);

        for msg in msgs {
            if msg.from == self.my_id {
                continue;
            }
            let idx = self
                .parties
                .iter()
                .position(|p| *p == msg.from)
                .ok_or_else(|| format!("unknown party {}", msg.from))?;
            if u_primes[idx].is_some() {
                return Err(format!("duplicate Round-1 message from {}", msg.from));
            }

            let re_stmt = ReStatement::<C> {
                g,
                p: self.elgamal_pk,
                a: self.u,
                b: self.v,
                a_prime: msg.u_prime_i,
                b_prime: msg.v_prime_i,
            };
            if !msg.re_proof.verify(&re_stmt) {
                return Err(format!(
                    "R_RE proof verification failed for party {}",
                    msg.from
                ));
            }

            u_primes[idx] = Some(msg.u_prime_i);
            v_primes[idx] = Some(msg.v_prime_i);
        }

        for (i, slot) in u_primes.iter().enumerate() {
            if slot.is_none() {
                return Err(format!(
                    "missing Round-1 message from party {}",
                    self.parties[i]
                ));
            }
        }

        let u_prime: C::ProjectivePoint = u_primes
            .iter()
            .map(|s| s.unwrap())
            .reduce(|acc, p| acc + p)
            .expect("at least one party");
        let v_prime: C::ProjectivePoint = v_primes
            .iter()
            .map(|s| s.unwrap())
            .reduce(|acc, p| acc + p)
            .expect("at least one party");

        let w_i = u_prime * self.d_i;

        let ddh_stmt = DdhStatement::<C> {
            g,
            a: u_prime,
            b: self.p_i,
            c: w_i,
        };
        let ddh_wit = DdhWitness::<C> { w: self.d_i };
        let ddh_proof = DdhProof::prove(&ddh_stmt, &ddh_wit, rng);

        let round2_msg = CheckDhRound2Msg {
            from: self.my_id,
            w_i,
            ddh_proof,
        };

        let aggregated = AggregatedRerand { u_prime, v_prime };

        Ok((round2_msg, aggregated))
    }

    pub fn finish_round2(
        &self,
        msgs: &[CheckDhRound2Msg<C>],
        aggregated: &AggregatedRerand<C>,
    ) -> Result<bool, String> {
        let n = self.parties.len();
        let g = C::generator();

        let mut w_shares: Vec<Option<C::ProjectivePoint>> = vec![None; n];

        let my_index = self.parties.iter().position(|p| *p == self.my_id).unwrap();
        let own_w_i = aggregated.u_prime * self.d_i;
        w_shares[my_index] = Some(own_w_i);

        for msg in msgs {
            if msg.from == self.my_id {
                continue;
            }
            let idx = self
                .parties
                .iter()
                .position(|p| *p == msg.from)
                .ok_or_else(|| format!("unknown party {}", msg.from))?;
            if w_shares[idx].is_some() {
                return Err(format!("duplicate Round-2 message from {}", msg.from));
            }

            let ddh_stmt = DdhStatement::<C> {
                g,
                a: aggregated.u_prime,
                b: self.elgamal_pk_shares[idx],
                c: msg.w_i,
            };
            if !msg.ddh_proof.verify(&ddh_stmt) {
                return Err(format!(
                    "R_DH proof verification failed for party {}",
                    msg.from
                ));
            }

            w_shares[idx] = Some(msg.w_i);
        }

        for (i, slot) in w_shares.iter().enumerate() {
            if slot.is_none() {
                return Err(format!(
                    "missing Round-2 message from party {}",
                    self.parties[i]
                ));
            }
        }

        let sum_w: C::ProjectivePoint = w_shares
            .iter()
            .map(|s| s.unwrap())
            .reduce(|acc, p| acc + p)
            .expect("at least one party");

        Ok(sum_w == aggregated.v_prime)
    }
}

pub struct AggregatedRerand<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub u_prime: C::ProjectivePoint,
    pub v_prime: C::ProjectivePoint,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "secp256k1")]
    type C = k256::Secp256k1;

    #[cfg(feature = "secp256k1")]
    fn run_init(n: usize) -> (Vec<PartyId>, Vec<crate::f_mult::init::InitOutput<C>>) {
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

        (parties, init_outputs)
    }

    #[cfg(feature = "secp256k1")]
    fn run_check_dh(
        parties: &[PartyId],
        init_outputs: &[crate::f_mult::init::InitOutput<C>],
        u: <C as elliptic_curve::CurveArithmetic>::ProjectivePoint,
        v: <C as elliptic_curve::CurveArithmetic>::ProjectivePoint,
    ) -> Vec<bool> {
        let n = parties.len();
        let mut rng = rand::thread_rng();

        let elgamal_pk = init_outputs[0].elgamal_pk;
        let pk_shares = &init_outputs[0].elgamal_pk_shares;

        let mut states: Vec<CheckDhState<C>> = Vec::with_capacity(n);
        let mut r1_msgs: Vec<CheckDhRound1Msg<C>> = Vec::with_capacity(n);
        for i in 0..n {
            let (state, msg) = CheckDhState::<C>::new(
                parties[i],
                parties.to_vec(),
                init_outputs[i].d_i,
                elgamal_pk,
                pk_shares.clone(),
                u,
                v,
                &mut rng,
            );
            states.push(state);
            r1_msgs.push(msg);
        }

        let mut r2_msgs: Vec<CheckDhRound2Msg<C>> = Vec::with_capacity(n);
        let mut aggregateds: Vec<AggregatedRerand<C>> = Vec::with_capacity(n);
        for i in 0..n {
            let others: Vec<_> = r1_msgs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, m)| m.clone())
                .collect();
            let (r2, agg) = states[i]
                .handle_round1(&others, &mut rng)
                .expect("Round-1 should succeed");
            r2_msgs.push(r2);
            aggregateds.push(agg);
        }

        for i in 1..n {
            assert_eq!(
                aggregateds[0].u_prime, aggregateds[i].u_prime,
                "all parties must agree on U'"
            );
            assert_eq!(
                aggregateds[0].v_prime, aggregateds[i].v_prime,
                "all parties must agree on V'"
            );
        }

        let mut results: Vec<bool> = Vec::with_capacity(n);
        for i in 0..n {
            let others: Vec<_> = r2_msgs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, m)| m.clone())
                .collect();
            let result = states[i]
                .finish_round2(&others, &aggregateds[i])
                .expect("Round-2 should succeed");
            results.push(result);
        }

        results
    }

    #[test]
    #[cfg(feature = "secp256k1")]
    fn check_dh_valid_tuple_2of2() {
        let (parties, init_outputs) = run_init(2);

        let mut rng = rand::thread_rng();
        let g = C::generator();

        let d: <C as elliptic_curve::CurveArithmetic>::Scalar = init_outputs
            .iter()
            .map(|o| o.d_i)
            .reduce(|acc, x| acc + x)
            .unwrap();

        let u_scalar = C::random_scalar(&mut rng);
        let u = g * u_scalar;
        let v = u * d;

        let results = run_check_dh(&parties, &init_outputs, u, v);
        for (i, result) in results.iter().enumerate() {
            assert!(result, "party {} should accept a valid DH tuple", i);
        }
    }

    #[test]
    #[cfg(feature = "secp256k1")]
    fn check_dh_valid_tuple_3of3() {
        let (parties, init_outputs) = run_init(3);

        let mut rng = rand::thread_rng();
        let g = C::generator();

        let d: <C as elliptic_curve::CurveArithmetic>::Scalar = init_outputs
            .iter()
            .map(|o| o.d_i)
            .reduce(|acc, x| acc + x)
            .unwrap();

        let u_scalar = C::random_scalar(&mut rng);
        let u = g * u_scalar;
        let v = u * d;

        let results = run_check_dh(&parties, &init_outputs, u, v);
        for (i, result) in results.iter().enumerate() {
            assert!(result, "party {} should accept a valid DH tuple", i);
        }
    }

    #[test]
    #[cfg(feature = "secp256k1")]
    fn check_dh_invalid_tuple_2of2() {
        let (parties, init_outputs) = run_init(2);

        let mut rng = rand::thread_rng();
        let g = C::generator();

        let u_scalar = C::random_scalar(&mut rng);
        let u = g * u_scalar;
        let v_scalar = C::random_scalar(&mut rng);
        let v = g * v_scalar;

        let results = run_check_dh(&parties, &init_outputs, u, v);
        for (i, result) in results.iter().enumerate() {
            assert!(!result, "party {} should reject an invalid DH tuple", i);
        }
    }

    #[test]
    #[cfg(feature = "secp256k1")]
    fn check_dh_invalid_tuple_3of3() {
        let (parties, init_outputs) = run_init(3);

        let mut rng = rand::thread_rng();
        let g = C::generator();

        let u_scalar = C::random_scalar(&mut rng);
        let u = g * u_scalar;
        let v_scalar = C::random_scalar(&mut rng);
        let v = g * v_scalar;

        let results = run_check_dh(&parties, &init_outputs, u, v);
        for (i, result) in results.iter().enumerate() {
            assert!(!result, "party {} should reject an invalid DH tuple", i);
        }
    }
}
