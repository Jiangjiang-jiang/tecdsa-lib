#![allow(non_snake_case)]

use std::collections::BTreeMap;

use elliptic_curve::{
    group::GroupEncoding, sec1::ModulusSize, Field, FieldBytes, FieldBytesSize, PrimeField,
};
use rand_core::CryptoRngCore;
use tecdsa_curve::TecdsaCurve;
use tecdsa_paillier::{
    backend::Integer,
    conv::{integer_to_scalar, scalar_to_integer},
    zk::mta_range::{AliceProof, BobProofExt, NTildeParams},
    DecryptionKey, EncryptionKey,
};
use tecdsa_protocol::PartyId;

#[derive(Clone)]
pub struct MtaRound1Msg {
    pub from: PartyId,
    pub c_a: Integer,
    pub alice_proof: AliceProof,
}

pub struct MtaRound2Msg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub from: PartyId,
    pub c_b: Integer,
    pub bob_proof: BobProofExt<C>,
    pub b_point: C::ProjectivePoint,
}

impl<C: TecdsaCurve> Clone for MtaRound2Msg<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::ProjectivePoint: GroupEncoding,
{
    fn clone(&self) -> Self {
        Self {
            from: self.from,
            c_b: self.c_b.clone(),
            bob_proof: self.bob_proof.clone(),
            b_point: self.b_point,
        }
    }
}

pub struct PaillierMtaState<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    my_id: PartyId,
    parties: Vec<PartyId>,
    dk: DecryptionKey,
    eks: BTreeMap<PartyId, EncryptionKey>,
    ntilde_params: BTreeMap<PartyId, NTildeParams>,
    a_i: C::Scalar,
    b_i: C::Scalar,
    c_a: Integer,
    beta_shares: BTreeMap<PartyId, C::Scalar>,
}

impl<C: TecdsaCurve> PaillierMtaState<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
    C::ProjectivePoint: GroupEncoding,
{
    pub fn new(
        my_id: PartyId,
        parties: Vec<PartyId>,
        dk: DecryptionKey,
        eks: BTreeMap<PartyId, EncryptionKey>,
        ntilde_params: BTreeMap<PartyId, NTildeParams>,
        a_i: C::Scalar,
        b_i: C::Scalar,
        rng: &mut impl CryptoRngCore,
    ) -> (Self, Vec<(PartyId, MtaRound1Msg)>) {
        assert!(parties.contains(&my_id), "parties must contain my_id");
        assert!(
            eks.contains_key(&my_id),
            "eks must contain my own encryption key"
        );

        let a_i_int = scalar_to_integer::<C>(&a_i);
        let my_ek = &eks[&my_id];
        let (c_a, r_a) = my_ek
            .encrypt_with_random(rng, &a_i_int)
            .expect("Paillier encrypt must succeed");

        let mut round1_msgs = Vec::new();
        for &pid in &parties {
            if pid == my_id {
                continue;
            }
            let receiver_ntilde = &ntilde_params[&pid];
            let alice_proof = AliceProof::prove::<C>(
                &a_i_int,
                &c_a,
                my_ek.n(),
                my_ek.nn(),
                receiver_ntilde,
                &r_a,
                rng,
            );
            round1_msgs.push((
                pid,
                MtaRound1Msg {
                    from: my_id,
                    c_a: c_a.clone(),
                    alice_proof,
                },
            ));
        }

        let state = Self {
            my_id,
            parties,
            dk,
            eks,
            ntilde_params,
            a_i,
            b_i,
            c_a,
            beta_shares: BTreeMap::new(),
        };

        (state, round1_msgs)
    }

    pub fn handle_round1(
        &mut self,
        msgs: &[MtaRound1Msg],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<(PartyId, MtaRound2Msg<C>)>, String> {
        let mut round2_msgs = Vec::new();

        for msg in msgs {
            if msg.from == self.my_id {
                continue;
            }
            if !self.parties.contains(&msg.from) {
                return Err(format!("unknown party {}", msg.from));
            }
            if self.beta_shares.contains_key(&msg.from) {
                return Err(format!("duplicate Round-1 message from {}", msg.from));
            }

            let alice_ek = self
                .eks
                .get(&msg.from)
                .ok_or_else(|| format!("missing encryption key for party {}", msg.from))?;

            let my_ntilde = self
                .ntilde_params
                .get(&self.my_id)
                .ok_or_else(|| format!("missing N_tilde params for self {}", self.my_id))?;
            msg.alice_proof
                .verify::<C>(&msg.c_a, alice_ek.n(), alice_ek.nn(), my_ntilde)
                .map_err(|e| {
                    format!(
                        "party {} Alice range proof verification failed: {}",
                        msg.from, e
                    )
                })?;

            let c_a_j = &msg.c_a;
            let b_i_int = scalar_to_integer::<C>(&self.b_i);

            let beta_prime = alice_ek.half_n().random_below_ref(rng);

            let r_bob = Integer::sample_in_mult_group_of(rng, alice_ek.n());
            let enc_beta = alice_ek
                .encrypt_with(&beta_prime, &r_bob)
                .expect("Paillier encrypt beta");
            let c_b = if b_i_int.cmp0().is_eq() {
                enc_beta
            } else {
                let b_times_ca = alice_ek.omul(&b_i_int, c_a_j).expect("Paillier scalar mul");
                alice_ek.oadd(&b_times_ca, &enc_beta).expect("Paillier add")
            };

            let alice_ntilde = self
                .ntilde_params
                .get(&msg.from)
                .ok_or_else(|| format!("missing N_tilde params for party {}", msg.from))?;

            let bob_proof = BobProofExt::<C>::prove(
                c_a_j,
                &c_b,
                &b_i_int,
                &beta_prime,
                alice_ek.n(),
                alice_ek.nn(),
                alice_ntilde,
                &r_bob,
                rng,
            );

            let b_scalar = integer_to_scalar::<C>(&b_i_int);
            let b_point = C::generator() * b_scalar;

            let neg_beta = -integer_to_scalar::<C>(&beta_prime);
            self.beta_shares.insert(msg.from, neg_beta);

            round2_msgs.push((
                msg.from,
                MtaRound2Msg {
                    from: self.my_id,
                    c_b,
                    bob_proof,
                    b_point,
                },
            ));
        }

        Ok(round2_msgs)
    }

    pub fn finish(&self, msgs: &[MtaRound2Msg<C>]) -> Result<C::Scalar, String> {
        let mut alpha_sum = C::Scalar::ZERO;

        let my_ek = self
            .eks
            .get(&self.my_id)
            .expect("must have own encryption key");
        let my_ntilde = self
            .ntilde_params
            .get(&self.my_id)
            .expect("must have own N_tilde params");

        let mut seen = std::collections::HashSet::new();
        for msg in msgs {
            if msg.from == self.my_id {
                continue;
            }
            if !self.parties.contains(&msg.from) {
                return Err(format!("unknown party {}", msg.from));
            }
            if !seen.insert(msg.from) {
                return Err(format!("duplicate Round-2 message from {}", msg.from));
            }

            msg.bob_proof
                .verify(
                    &self.c_a,
                    &msg.c_b,
                    my_ek.n(),
                    my_ek.nn(),
                    my_ntilde,
                    &msg.b_point,
                )
                .map_err(|e| {
                    format!(
                        "party {} Bob range proof verification failed: {}",
                        msg.from, e
                    )
                })?;

            let alpha_int = self
                .dk
                .decrypt(&msg.c_b)
                .map_err(|e| format!("decrypt failed for party {}: {}", msg.from, e))?;
            let alpha = signed_integer_to_scalar::<C>(&alpha_int);
            alpha_sum += alpha;
        }

        let expected = self.parties.len() - 1;
        if seen.len() != expected {
            return Err(format!(
                "expected {} Round-2 messages, got {}",
                expected,
                seen.len()
            ));
        }

        let mut beta_sum = C::Scalar::ZERO;
        for &pid in &self.parties {
            if pid == self.my_id {
                continue;
            }
            let beta = self
                .beta_shares
                .get(&pid)
                .ok_or_else(|| format!("missing beta share for party {}", pid))?;
            beta_sum += beta;
        }

        let c_i = self.a_i * self.b_i + alpha_sum + beta_sum;

        Ok(c_i)
    }
}

fn signed_integer_to_scalar<C: TecdsaCurve>(
    i: &Integer,
) -> <C as elliptic_curve::CurveArithmetic>::Scalar
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    if i.cmp0().is_lt() {
        let abs_val = -i.clone();
        let pos_scalar = integer_to_scalar::<C>(&abs_val);
        -pos_scalar
    } else {
        integer_to_scalar::<C>(i)
    }
}

#[cfg(test)]
mod tests {
    use tecdsa_paillier::zk::mta_range::NTildeParams;

    use super::*;

    #[cfg(feature = "secp256k1")]
    type C = k256::Secp256k1;

    #[cfg(feature = "secp256k1")]
    fn test_paillier_dk(rng: &mut impl CryptoRngCore) -> DecryptionKey {
        let p = Integer::generate_safe_prime(rng, 512);
        let q = Integer::generate_safe_prime(rng, 512);
        DecryptionKey::from_primes(p, q).expect("valid primes")
    }

    #[cfg(feature = "secp256k1")]
    fn test_ntilde(rng: &mut impl CryptoRngCore) -> NTildeParams {
        let p = Integer::generate_safe_prime(rng, 256);
        let q = Integer::generate_safe_prime(rng, 256);
        let n_tilde = &p * &q;

        let h1 = Integer::sample_in_mult_group_of(rng, &n_tilde);
        let phi_n = (&p - Integer::one()) * (&q - Integer::one());
        let lambda = phi_n.random_below_ref(rng);
        let h2 = h1.pow_mod_ref(&lambda, &n_tilde).expect("pow_mod defined");

        NTildeParams {
            N_tilde: n_tilde,
            h1,
            h2,
        }
    }

    #[cfg(feature = "secp256k1")]
    fn run_paillier_mta(n: usize) {
        let mut rng = rand::thread_rng();
        let parties: Vec<PartyId> = (1..=n).map(|i| PartyId(i as u16)).collect();

        let mut dks: Vec<DecryptionKey> = Vec::with_capacity(n);
        let mut eks: BTreeMap<PartyId, EncryptionKey> = BTreeMap::new();
        let mut ntilde_map: BTreeMap<PartyId, NTildeParams> = BTreeMap::new();
        for &pid in &parties {
            let dk = test_paillier_dk(&mut rng);
            eks.insert(pid, dk.encryption_key().clone());
            dks.push(dk);
            ntilde_map.insert(pid, test_ntilde(&mut rng));
        }

        let a_shares: Vec<<C as elliptic_curve::CurveArithmetic>::Scalar> =
            (0..n).map(|_| C::random_scalar(&mut rng)).collect();
        let b_shares: Vec<<C as elliptic_curve::CurveArithmetic>::Scalar> =
            (0..n).map(|_| C::random_scalar(&mut rng)).collect();

        let mut states: Vec<PaillierMtaState<C>> = Vec::with_capacity(n);
        let mut all_round1_msgs: Vec<Vec<(PartyId, MtaRound1Msg)>> = Vec::with_capacity(n);

        for i in 0..n {
            let (state, r1_msgs) = PaillierMtaState::<C>::new(
                parties[i],
                parties.clone(),
                dks[i].clone(),
                eks.clone(),
                ntilde_map.clone(),
                a_shares[i],
                b_shares[i],
                &mut rng,
            );
            states.push(state);
            all_round1_msgs.push(r1_msgs);
        }

        let mut all_round2_msgs: Vec<Vec<(PartyId, MtaRound2Msg<C>)>> = Vec::with_capacity(n);

        for i in 0..n {
            let mut msgs_for_i: Vec<MtaRound1Msg> = Vec::new();
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

        let mut c_shares: Vec<<C as elliptic_curve::CurveArithmetic>::Scalar> =
            Vec::with_capacity(n);

        for i in 0..n {
            let mut msgs_for_i: Vec<MtaRound2Msg<C>> = Vec::new();
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
    fn paillier_mta_2of2() {
        run_paillier_mta(2);
    }

    #[test]
    #[cfg(feature = "secp256k1")]
    fn paillier_mta_3of3() {
        run_paillier_mta(3);
    }

    #[test]
    #[cfg(feature = "secp256k1")]
    fn paillier_mta_zero_shares() {
        let mut rng = rand::thread_rng();
        let n = 2;
        let parties: Vec<PartyId> = (1..=n).map(|i| PartyId(i as u16)).collect();

        let mut dks = Vec::with_capacity(n as usize);
        let mut eks: BTreeMap<PartyId, EncryptionKey> = BTreeMap::new();
        let mut ntilde_map: BTreeMap<PartyId, NTildeParams> = BTreeMap::new();
        for &pid in &parties {
            let dk = test_paillier_dk(&mut rng);
            eks.insert(pid, dk.encryption_key().clone());
            dks.push(dk);
            ntilde_map.insert(pid, test_ntilde(&mut rng));
        }

        let zero = <C as elliptic_curve::CurveArithmetic>::Scalar::ZERO;

        let mut states: Vec<PaillierMtaState<C>> = Vec::with_capacity(n as usize);
        let mut all_round1_msgs = Vec::new();

        for i in 0..n as usize {
            let (state, r1_msgs) = PaillierMtaState::<C>::new(
                parties[i],
                parties.clone(),
                dks[i].clone(),
                eks.clone(),
                ntilde_map.clone(),
                zero,
                zero,
                &mut rng,
            );
            states.push(state);
            all_round1_msgs.push(r1_msgs);
        }

        let mut all_round2_msgs = Vec::new();
        for i in 0..n as usize {
            let mut msgs_for_i: Vec<MtaRound1Msg> = Vec::new();
            for j in 0..n as usize {
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
                .expect("round1 should succeed");
            all_round2_msgs.push(r2_msgs);
        }

        let mut c_shares = Vec::new();
        for i in 0..n as usize {
            let mut msgs_for_i: Vec<MtaRound2Msg<C>> = Vec::new();
            for j in 0..n as usize {
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

        let sum_c: <C as elliptic_curve::CurveArithmetic>::Scalar =
            c_shares.iter().copied().reduce(|acc, x| acc + x).unwrap();

        assert_eq!(sum_c, zero, "0 * 0 must equal 0");
    }

    #[test]
    #[cfg(feature = "secp256k1")]
    fn paillier_mta_one_hot() {
        let mut rng = rand::thread_rng();
        let n = 3usize;
        let parties: Vec<PartyId> = (1..=n).map(|i| PartyId(i as u16)).collect();

        let mut dks = Vec::with_capacity(n);
        let mut eks: BTreeMap<PartyId, EncryptionKey> = BTreeMap::new();
        let mut ntilde_map: BTreeMap<PartyId, NTildeParams> = BTreeMap::new();
        for &pid in &parties {
            let dk = test_paillier_dk(&mut rng);
            eks.insert(pid, dk.encryption_key().clone());
            dks.push(dk);
            ntilde_map.insert(pid, test_ntilde(&mut rng));
        }

        let zero = <C as elliptic_curve::CurveArithmetic>::Scalar::ZERO;
        let a_val = C::random_scalar(&mut rng);
        let b_val = C::random_scalar(&mut rng);

        let a_shares = [a_val, zero, zero];
        let b_shares = [zero, b_val, zero];

        let mut states: Vec<PaillierMtaState<C>> = Vec::with_capacity(n);
        let mut all_round1_msgs = Vec::new();
        for i in 0..n {
            let (state, r1_msgs) = PaillierMtaState::<C>::new(
                parties[i],
                parties.clone(),
                dks[i].clone(),
                eks.clone(),
                ntilde_map.clone(),
                a_shares[i],
                b_shares[i],
                &mut rng,
            );
            states.push(state);
            all_round1_msgs.push(r1_msgs);
        }

        let mut all_round2_msgs = Vec::new();
        for i in 0..n {
            let mut msgs_for_i: Vec<MtaRound1Msg> = Vec::new();
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
                .expect("round1 should succeed");
            all_round2_msgs.push(r2_msgs);
        }

        let mut c_shares = Vec::new();
        for i in 0..n {
            let mut msgs_for_i: Vec<MtaRound2Msg<C>> = Vec::new();
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

        let expected = a_val * b_val;
        let sum_c: <C as elliptic_curve::CurveArithmetic>::Scalar =
            c_shares.iter().copied().reduce(|acc, x| acc + x).unwrap();

        assert_eq!(sum_c, expected, "one-hot: sum(c_i) must equal a * b");
    }
}
