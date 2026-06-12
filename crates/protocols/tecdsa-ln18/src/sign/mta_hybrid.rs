use std::{collections::BTreeMap, sync::Mutex};

use elliptic_curve::{
    group::GroupEncoding, sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField,
};
use rand_core::CryptoRngCore;
use tecdsa_curve::TecdsaCurve;
use tecdsa_paillier::{zk::mta_range::NTildeParams, DecryptionKey, EncryptionKey};
use tecdsa_protocol::PartyId;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Ln18MtaOp {
    Tau,
    Beta,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ln18MtaBackend {
    Paillier,
    #[cfg(feature = "mta-ot")]
    Ot,
}

pub struct Ln18MtaLocalParams<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub paillier_dk: DecryptionKey,
    pub paillier_eks: BTreeMap<PartyId, EncryptionKey>,
    pub ntilde_params: BTreeMap<PartyId, NTildeParams>,
    pub _marker: core::marker::PhantomData<C>,
}

type MtaSubmission<C> = (
    <C as elliptic_curve::CurveArithmetic>::Scalar,
    <C as elliptic_curve::CurveArithmetic>::Scalar,
    Ln18MtaLocalParams<C>,
);

enum PaillierPartyPhase<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    WaitingForAllSubmissions {
        state: crate::mta::paillier::PaillierMtaState<C>,
    },
    WaitingForAllR2 {
        state: crate::mta::paillier::PaillierMtaState<C>,
    },
    Done,
}

struct PaillierOpState<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    submissions: BTreeMap<PartyId, MtaSubmission<C>>,
    phases: BTreeMap<PartyId, PaillierPartyPhase<C>>,
    r1_msgs: BTreeMap<PartyId, Vec<(PartyId, crate::mta::paillier::MtaRound1Msg)>>,
    r2_msgs: BTreeMap<PartyId, Vec<(PartyId, crate::mta::paillier::MtaRound2Msg<C>)>>,
    results: BTreeMap<PartyId, C::Scalar>,
}

#[cfg(feature = "mta-ot")]
struct OtOpState<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    submissions: BTreeMap<PartyId, MtaSubmission<C>>,
    results: Option<BTreeMap<PartyId, C::Scalar>>,
}

enum OpState<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    Paillier(PaillierOpState<C>),
    #[cfg(feature = "mta-ot")]
    Ot(OtOpState<C>),
}

struct Inner<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    ops: BTreeMap<Ln18MtaOp, OpState<C>>,
}

pub struct Ln18MtaHybrid<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    parties: Vec<PartyId>,
    backend: Ln18MtaBackend,
    inner: Mutex<Inner<C>>,
}

impl<C: TecdsaCurve> Ln18MtaHybrid<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    pub fn new(parties: Vec<PartyId>, backend: Ln18MtaBackend) -> Self {
        Self {
            parties,
            backend,
            inner: Mutex::new(Inner {
                ops: BTreeMap::new(),
            }),
        }
    }

    pub(crate) fn submit_and_try_get(
        &self,
        op: Ln18MtaOp,
        my_id: PartyId,
        params: Ln18MtaLocalParams<C>,
        a_i: C::Scalar,
        b_i: C::Scalar,
        rng: &mut impl CryptoRngCore,
    ) -> tecdsa_core::Result<Option<C::Scalar>>
    where
        C::ProjectivePoint: GroupEncoding,
    {
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| tecdsa_core::TecdsaError::Other(format!("MtA lock poisoned: {e}")))?;

        let n = self.parties.len();

        let op_state = guard.ops.entry(op).or_insert_with(|| match self.backend {
            Ln18MtaBackend::Paillier => OpState::Paillier(PaillierOpState {
                submissions: BTreeMap::new(),
                phases: BTreeMap::new(),
                r1_msgs: BTreeMap::new(),
                r2_msgs: BTreeMap::new(),
                results: BTreeMap::new(),
            }),
            #[cfg(feature = "mta-ot")]
            Ln18MtaBackend::Ot => OpState::Ot(OtOpState {
                submissions: BTreeMap::new(),
                results: None,
            }),
        });

        match op_state {
            OpState::Paillier(pstate) => {
                if let Some(&c_i) = pstate.results.get(&my_id) {
                    return Ok(Some(c_i));
                }

                if let std::collections::btree_map::Entry::Vacant(entry) =
                    pstate.submissions.entry(my_id)
                {
                    let (state, r1_msgs) = crate::mta::paillier::PaillierMtaState::<C>::new(
                        my_id,
                        self.parties.clone(),
                        params.paillier_dk.clone(),
                        params.paillier_eks.clone(),
                        params.ntilde_params.clone(),
                        a_i,
                        b_i,
                        rng,
                    );
                    entry.insert((a_i, b_i, params));
                    pstate.r1_msgs.insert(my_id, r1_msgs);
                    pstate.phases.insert(
                        my_id,
                        PaillierPartyPhase::WaitingForAllSubmissions { state },
                    );
                    return Ok(None);
                }

                if pstate.submissions.len() < n {
                    return Ok(None);
                }

                if matches!(
                    pstate.phases.get(&my_id),
                    Some(PaillierPartyPhase::WaitingForAllSubmissions { .. })
                ) {
                    let old_phase = pstate.phases.remove(&my_id).unwrap();
                    let mut state = match old_phase {
                        PaillierPartyPhase::WaitingForAllSubmissions { state } => state,
                        _ => unreachable!(),
                    };

                    let mut msgs_for_me = Vec::new();
                    for (&sender, r1_list) in &pstate.r1_msgs {
                        if sender == my_id {
                            continue;
                        }
                        for (dest, msg) in r1_list {
                            if *dest == my_id {
                                msgs_for_me.push(msg.clone());
                            }
                        }
                    }

                    let r2_msgs = state.handle_round1(&msgs_for_me, rng).map_err(|e| {
                        tecdsa_core::TecdsaError::Other(format!("MtA R1 for party {my_id}: {e}"))
                    })?;
                    pstate.r2_msgs.insert(my_id, r2_msgs);
                    pstate
                        .phases
                        .insert(my_id, PaillierPartyPhase::WaitingForAllR2 { state });
                }

                if pstate.r2_msgs.len() < n {
                    return Ok(None);
                }

                if matches!(
                    pstate.phases.get(&my_id),
                    Some(PaillierPartyPhase::WaitingForAllR2 { .. })
                ) {
                    let old_phase = pstate.phases.remove(&my_id).unwrap();
                    let state = match old_phase {
                        PaillierPartyPhase::WaitingForAllR2 { state } => state,
                        _ => unreachable!(),
                    };

                    let mut msgs_for_me = Vec::new();
                    for (&sender, r2_list) in &pstate.r2_msgs {
                        if sender == my_id {
                            continue;
                        }
                        for (dest, msg) in r2_list {
                            if *dest == my_id {
                                msgs_for_me.push(msg.clone());
                            }
                        }
                    }

                    let c_i = state.finish(&msgs_for_me).map_err(|e| {
                        tecdsa_core::TecdsaError::Other(format!(
                            "MtA finish for party {my_id}: {e}"
                        ))
                    })?;
                    pstate.results.insert(my_id, c_i);
                    pstate.phases.insert(my_id, PaillierPartyPhase::Done);
                    return Ok(Some(c_i));
                }

                Ok(pstate.results.get(&my_id).copied())
            }
            #[cfg(feature = "mta-ot")]
            OpState::Ot(ostate) => {
                if let Some(ref results) = ostate.results {
                    let c_i = results.get(&my_id).ok_or_else(|| {
                        tecdsa_core::TecdsaError::Other(format!(
                            "MtA result not found for party {my_id}"
                        ))
                    })?;
                    return Ok(Some(*c_i));
                }

                ostate
                    .submissions
                    .entry(my_id)
                    .or_insert((a_i, b_i, params));

                if ostate.submissions.len() < n {
                    return Ok(None);
                }

                let results = self.run_ot_mta(&self.parties, &ostate.submissions, rng)?;
                let c_i = *results.get(&my_id).ok_or_else(|| {
                    tecdsa_core::TecdsaError::Other(format!(
                        "MtA result not found for party {my_id} after computation"
                    ))
                })?;
                ostate.results = Some(results);
                Ok(Some(c_i))
            }
        }
    }

    #[cfg(feature = "mta-ot")]
    fn run_ot_mta(
        &self,
        parties: &[PartyId],
        submissions: &BTreeMap<PartyId, MtaSubmission<C>>,
        rng: &mut impl CryptoRngCore,
    ) -> tecdsa_core::Result<BTreeMap<PartyId, C::Scalar>>
    where
        C::Scalar: elliptic_curve::ops::Reduce<FieldBytes<C>>,
    {
        use crate::mta::ot::OtMtaState;

        let n = parties.len();

        let mut a_shares = Vec::with_capacity(n);
        let mut b_shares = Vec::with_capacity(n);
        for pid in parties {
            let (a, b, _) = submissions.get(pid).ok_or_else(|| {
                tecdsa_core::TecdsaError::Other(format!("missing submission for {pid}"))
            })?;
            a_shares.push(*a);
            b_shares.push(*b);
        }

        let mut states = Vec::with_capacity(n);
        let mut all_init_msgs = Vec::with_capacity(n);
        for i in 0..n {
            let (state, init_msgs) =
                OtMtaState::<C>::new(parties[i], parties.to_vec(), a_shares[i], b_shares[i], rng);
            states.push(state);
            all_init_msgs.push(init_msgs);
        }

        for i in 0..n {
            let mut msgs_for_i = Vec::new();
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
                .map_err(|e| tecdsa_core::TecdsaError::Other(format!("OT init: {e}")))?;
        }

        let mut all_r1_msgs = Vec::with_capacity(n);
        for i in 0..n {
            let r1 = states[i]
                .run_receiver_phase1(rng)
                .map_err(|e| tecdsa_core::TecdsaError::Other(format!("OT R1: {e}")))?;
            all_r1_msgs.push(r1);
        }

        let mut all_r2_msgs = Vec::with_capacity(n);
        for i in 0..n {
            let mut msgs_for_i = Vec::new();
            for j in 0..n {
                if i == j {
                    continue;
                }
                for (dest, msg) in &all_r1_msgs[j] {
                    if *dest == parties[i] {
                        msgs_for_i.push(msg.clone());
                    }
                }
            }
            let r2 = states[i]
                .handle_round1(&msgs_for_i, rng)
                .map_err(|e| tecdsa_core::TecdsaError::Other(format!("OT R2: {e}")))?;
            all_r2_msgs.push(r2);
        }

        let mut results = BTreeMap::new();
        for i in 0..n {
            let mut msgs_for_i = Vec::new();
            for j in 0..n {
                if i == j {
                    continue;
                }
                for (dest, msg) in &all_r2_msgs[j] {
                    if *dest == parties[i] {
                        msgs_for_i.push(msg.clone());
                    }
                }
            }
            let c_i = states[i]
                .finish(&msgs_for_i)
                .map_err(|e| tecdsa_core::TecdsaError::Other(format!("OT finish: {e}")))?;
            results.insert(parties[i], c_i);
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[cfg(feature = "secp256k1")]
    type C = k256::Secp256k1;

    #[cfg(feature = "secp256k1")]
    fn test_paillier_dk(rng: &mut impl CryptoRngCore) -> DecryptionKey {
        use tecdsa_paillier::backend::Integer;
        let p = Integer::generate_safe_prime(rng, 512);
        let q = Integer::generate_safe_prime(rng, 512);
        DecryptionKey::from_primes(p, q).expect("valid primes")
    }

    #[cfg(feature = "secp256k1")]
    fn test_ntilde(rng: &mut impl CryptoRngCore) -> NTildeParams {
        use tecdsa_paillier::backend::Integer;
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

    #[test]
    #[cfg(feature = "secp256k1")]
    fn paillier_mta_two_parties() {
        let mut rng = rand::thread_rng();
        let parties = vec![PartyId(0), PartyId(1)];
        let mta = Arc::new(Ln18MtaHybrid::<C>::new(
            parties.clone(),
            Ln18MtaBackend::Paillier,
        ));

        let k_0 = <C as TecdsaCurve>::random_scalar(&mut rng);
        let k_1 = <C as TecdsaCurve>::random_scalar(&mut rng);
        let rho_0 = <C as TecdsaCurve>::random_scalar(&mut rng);
        let rho_1 = <C as TecdsaCurve>::random_scalar(&mut rng);

        let dk0 = test_paillier_dk(&mut rng);
        let dk1 = test_paillier_dk(&mut rng);
        let mut eks = BTreeMap::new();
        eks.insert(PartyId(0), dk0.encryption_key().clone());
        eks.insert(PartyId(1), dk1.encryption_key().clone());

        let mut ntilde_map = BTreeMap::new();
        ntilde_map.insert(PartyId(0), test_ntilde(&mut rng));
        ntilde_map.insert(PartyId(1), test_ntilde(&mut rng));

        let params0 = Ln18MtaLocalParams::<C> {
            paillier_dk: dk0.clone(),
            paillier_eks: eks.clone(),
            ntilde_params: ntilde_map.clone(),
            _marker: core::marker::PhantomData,
        };
        let r0 = mta
            .submit_and_try_get(Ln18MtaOp::Tau, PartyId(0), params0, k_0, rho_0, &mut rng)
            .expect("submit should succeed");
        assert!(r0.is_none(), "not all parties submitted yet");

        let params1 = Ln18MtaLocalParams::<C> {
            paillier_dk: dk1.clone(),
            paillier_eks: eks.clone(),
            ntilde_params: ntilde_map.clone(),
            _marker: core::marker::PhantomData,
        };
        let r1 = mta
            .submit_and_try_get(Ln18MtaOp::Tau, PartyId(1), params1, k_1, rho_1, &mut rng)
            .expect("submit should succeed");

        let make_dummy_params = |dk: &DecryptionKey| Ln18MtaLocalParams::<C> {
            paillier_dk: dk.clone(),
            paillier_eks: eks.clone(),
            ntilde_params: ntilde_map.clone(),
            _marker: core::marker::PhantomData,
        };

        let mut result_0 = None;
        let mut result_1 = r1;

        for _ in 0..5 {
            if result_0.is_none() {
                result_0 = mta
                    .submit_and_try_get(
                        Ln18MtaOp::Tau,
                        PartyId(0),
                        make_dummy_params(&dk0),
                        k_0,
                        rho_0,
                        &mut rng,
                    )
                    .expect("try_get should succeed");
            }
            if result_1.is_none() {
                result_1 = mta
                    .submit_and_try_get(
                        Ln18MtaOp::Tau,
                        PartyId(1),
                        make_dummy_params(&dk1),
                        k_1,
                        rho_1,
                        &mut rng,
                    )
                    .expect("try_get should succeed");
            }
            if result_0.is_some() && result_1.is_some() {
                break;
            }
        }

        assert!(result_0.is_some(), "party 0 should have result");
        assert!(result_1.is_some(), "party 1 should have result");

        let tau = result_0.unwrap() + result_1.unwrap();
        let expected = (k_0 + k_1) * (rho_0 + rho_1);
        assert_eq!(tau, expected, "sum of MtA shares must equal k * rho");
    }

    #[test]
    #[cfg(feature = "secp256k1")]
    fn paillier_mta_three_parties_distributed() {
        let mut rng = rand::thread_rng();
        let parties = vec![PartyId(0), PartyId(1), PartyId(2)];
        let mta = Arc::new(Ln18MtaHybrid::<C>::new(
            parties.clone(),
            Ln18MtaBackend::Paillier,
        ));

        let a: Vec<_> = (0..3)
            .map(|_| <C as TecdsaCurve>::random_scalar(&mut rng))
            .collect();
        let b: Vec<_> = (0..3)
            .map(|_| <C as TecdsaCurve>::random_scalar(&mut rng))
            .collect();

        let dks: Vec<_> = (0..3).map(|_| test_paillier_dk(&mut rng)).collect();
        let mut eks = BTreeMap::new();
        let mut ntilde_map = BTreeMap::new();
        for (i, pid) in parties.iter().enumerate() {
            eks.insert(*pid, dks[i].encryption_key().clone());
            ntilde_map.insert(*pid, test_ntilde(&mut rng));
        }

        for i in 0..3 {
            let params = Ln18MtaLocalParams::<C> {
                paillier_dk: dks[i].clone(),
                paillier_eks: eks.clone(),
                ntilde_params: ntilde_map.clone(),
                _marker: core::marker::PhantomData,
            };
            let r = mta
                .submit_and_try_get(Ln18MtaOp::Tau, parties[i], params, a[i], b[i], &mut rng)
                .expect("submit should succeed");
            assert!(r.is_none(), "submit phase should return None");
        }

        let mut results: [Option<<C as elliptic_curve::CurveArithmetic>::Scalar>; 3] =
            [None, None, None];

        for _ in 0..5 {
            for i in 0..3 {
                if results[i].is_none() {
                    let params = Ln18MtaLocalParams::<C> {
                        paillier_dk: dks[i].clone(),
                        paillier_eks: eks.clone(),
                        ntilde_params: ntilde_map.clone(),
                        _marker: core::marker::PhantomData,
                    };
                    results[i] = mta
                        .submit_and_try_get(
                            Ln18MtaOp::Tau,
                            parties[i],
                            params,
                            a[i],
                            b[i],
                            &mut rng,
                        )
                        .expect("try_get should succeed");
                }
            }
            if results.iter().all(|r| r.is_some()) {
                break;
            }
        }

        for (i, r) in results.iter().enumerate() {
            assert!(r.is_some(), "party {i} should have result");
        }

        let sum_c: <C as elliptic_curve::CurveArithmetic>::Scalar =
            results.iter().map(|r| r.unwrap()).fold(
                <C as elliptic_curve::CurveArithmetic>::Scalar::ZERO,
                |acc, x| acc + x,
            );
        let sum_a: <C as elliptic_curve::CurveArithmetic>::Scalar = a.iter().copied().fold(
            <C as elliptic_curve::CurveArithmetic>::Scalar::ZERO,
            |acc, x| acc + x,
        );
        let sum_b: <C as elliptic_curve::CurveArithmetic>::Scalar = b.iter().copied().fold(
            <C as elliptic_curve::CurveArithmetic>::Scalar::ZERO,
            |acc, x| acc + x,
        );
        let expected = sum_a * sum_b;
        assert_eq!(sum_c, expected, "sum of MtA shares must equal a * b");
    }
}
