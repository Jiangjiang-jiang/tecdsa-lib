// SPDX-License-Identifier: MIT OR Apache-2.0
//! Protocol 4.7 (Rounds 3-4) / Section 7 -- $\mathcal{F}_\text{checkDH}$:
//! securely check whether $(G, \mathcal{P}, U, V)$ is a Diffie-Hellman tuple
//! (i.e., $V = d \cdot U$ where $\mathcal{P} = d \cdot G$) without revealing
//! anything else. 3 rounds.
//!
//! Each party holds:
//! - $d_i$: their ElGamal secret share ($d = \sum d_i$, $\mathcal{P} = d \cdot G$)
//! - $\mathcal{P}_i = d_i \cdot G$: their public share
//! - $(G, \mathcal{P}, U, V)$: the tuple to check
//!
//! **Round 1:** Each $P_i$ samples $r_i, s_i$, computes rerandomization:
//!   $U'_i = r_i G + s_i U$, $V'_i = r_i \mathcal{P} + s_i V$.
//!   Sends $(U'_i, V'_i)$ with $R_{RE}$ proof.
//!
//! **Round 2:** Verify all $R_{RE}$ proofs. Compute $(U', V') = \sum (U'_j, V'_j)$.
//!   Each $P_i$ computes $W_i = d_i \cdot U'$ and sends $W_i$ with $R_{DH}$ proof
//!   that $(G, U', \mathcal{P}_i, W_i)$ is a DH tuple (witness $d_i$).
//!
//! **Round 3:** Verify all $R_{DH}$ proofs. Check $\sum W_j = V'$.
//!   If equal -> accept (it's a DH tuple). If not -> reject.

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

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// Round-1 broadcast: rerandomization shares $(U'_i, V'_i)$ and $R_{RE}$ proof.
pub struct CheckDhRound1Msg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Sender party ID.
    pub from: PartyId,
    /// Rerandomized U-share: $U'_i = r_i G + s_i U$.
    pub u_prime_i: C::ProjectivePoint,
    /// Rerandomized V-share: $V'_i = r_i \mathcal{P} + s_i V$.
    pub v_prime_i: C::ProjectivePoint,
    /// $R_{RE}$ proof that $(U'_i, V'_i)$ is a valid rerandomization.
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

/// Round-2 broadcast: partial decryption $W_i = d_i \cdot U'$ and $R_{DH}$ proof.
pub struct CheckDhRound2Msg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Sender party ID.
    pub from: PartyId,
    /// Partial decryption: $W_i = d_i \cdot U'$.
    pub w_i: C::ProjectivePoint,
    /// $R_{DH}$ proof that $(G, U', \mathcal{P}_i, W_i)$ is a DH tuple with witness $d_i$.
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

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// Internal state for the $\mathcal{F}_\text{checkDH}$ sub-protocol.
pub struct CheckDhState<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// This party's ID.
    my_id: PartyId,
    /// All party IDs (sorted, including self).
    parties: Vec<PartyId>,
    /// Own ElGamal secret share $d_i$.
    d_i: C::Scalar,
    /// Own ElGamal public-key share $\mathcal{P}_i = d_i \cdot G$.
    p_i: C::ProjectivePoint,
    /// Joint ElGamal public key $\mathcal{P} = d \cdot G$.
    elgamal_pk: C::ProjectivePoint,
    /// Per-party ElGamal public-key shares $\{\mathcal{P}_j\}$, ordered by party index.
    elgamal_pk_shares: Vec<C::ProjectivePoint>,
    /// Point $U$ from the tuple to check.
    u: C::ProjectivePoint,
    /// Point $V$ from the tuple to check.
    v: C::ProjectivePoint,
    /// Own rerandomization share $U'_i$ (kept for aggregation in Round 2).
    own_u_prime_i: C::ProjectivePoint,
    /// Own rerandomization share $V'_i$ (kept for aggregation in Round 2).
    own_v_prime_i: C::ProjectivePoint,
}

impl<C: TecdsaCurve> CheckDhState<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// Create a new checkDH state and produce the Round-1 broadcast message.
    ///
    /// # Arguments
    /// - `my_id`: this party's ID
    /// - `parties`: all party IDs (sorted, including self)
    /// - `d_i`: own ElGamal decryption-key share
    /// - `elgamal_pk`: joint ElGamal public key $\mathcal{P}$
    /// - `elgamal_pk_shares`: per-party ElGamal public-key shares (ordered by party index)
    /// - `u`: point $U$ of the tuple to check
    /// - `v`: point $V$ of the tuple to check
    /// - `rng`: cryptographic RNG
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

        // Sample rerandomization scalars
        let r_i = C::random_scalar(rng);
        let s_i = C::random_scalar(rng);

        // Compute rerandomization shares
        let u_prime_i = g * r_i + u * s_i;
        let v_prime_i = elgamal_pk * r_i + v * s_i;

        // Build R_RE proof
        // Statement: (G, P, U, V, U'_i, V'_i) with witness (r_i, s_i)
        // such that U'_i = r_i*G + s_i*U and V'_i = r_i*P + s_i*V
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

    /// Process all Round-1 messages, verify $R_{RE}$ proofs, aggregate
    /// rerandomization shares, and produce the Round-2 broadcast message.
    ///
    /// `msgs` should contain all Round-1 messages from *other* parties.
    pub fn handle_round1(
        &self,
        msgs: &[CheckDhRound1Msg<C>],
        rng: &mut impl CryptoRngCore,
    ) -> Result<(CheckDhRound2Msg<C>, AggregatedRerand<C>), String> {
        let n = self.parties.len();
        let g = C::generator();

        // Collect all rerandomization shares (including own)
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

            // Verify R_RE proof
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

        // Ensure all parties sent Round-1 messages
        for (i, slot) in u_primes.iter().enumerate() {
            if slot.is_none() {
                return Err(format!(
                    "missing Round-1 message from party {}",
                    self.parties[i]
                ));
            }
        }

        // Aggregate: (U', V') = sum of (U'_j, V'_j)
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

        // Compute W_i = d_i * U'
        let w_i = u_prime * self.d_i;

        // Build R_DH proof: prove (G, U', P_i, W_i) is a DH tuple with witness d_i
        // i.e., P_i = d_i * G and W_i = d_i * U'
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

    /// Process all Round-2 messages and determine whether $(G, \mathcal{P}, U, V)$
    /// is a Diffie-Hellman tuple.
    ///
    /// Verifies all $R_{DH}$ proofs and checks $\sum W_j = V'$.
    ///
    /// Returns `Ok(true)` if the tuple is valid (DH), `Ok(false)` if not.
    pub fn finish_round2(
        &self,
        msgs: &[CheckDhRound2Msg<C>],
        aggregated: &AggregatedRerand<C>,
    ) -> Result<bool, String> {
        let n = self.parties.len();
        let g = C::generator();

        let mut w_shares: Vec<Option<C::ProjectivePoint>> = vec![None; n];

        // Compute own W_i (recompute to avoid storing extra state)
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

            // Verify R_DH proof: (G, U', P_j, W_j) is DH tuple
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

        // Ensure all parties sent Round-2 messages
        for (i, slot) in w_shares.iter().enumerate() {
            if slot.is_none() {
                return Err(format!(
                    "missing Round-2 message from party {}",
                    self.parties[i]
                ));
            }
        }

        // Check: sum(W_j) == V'
        let sum_w: C::ProjectivePoint = w_shares
            .iter()
            .map(|s| s.unwrap())
            .reduce(|acc, p| acc + p)
            .expect("at least one party");

        Ok(sum_w == aggregated.v_prime)
    }
}

/// Aggregated rerandomization values computed at the end of Round 1.
///
/// Both parties must agree on $(U', V')$; this struct is passed from
/// `handle_round1` to `finish_round2`.
pub struct AggregatedRerand<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Aggregated rerandomized $U' = \sum U'_j$.
    pub u_prime: C::ProjectivePoint,
    /// Aggregated rerandomized $V' = \sum V'_j$.
    pub v_prime: C::ProjectivePoint,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "secp256k1")]
    type C = k256::Secp256k1;

    /// Run the init sub-protocol and return the outputs needed for checkDH.
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

    /// Run the full checkDH protocol for `n` parties on the given tuple (U, V).
    /// Returns the accept/reject result from each party.
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

        // --- Round 1: each party creates state + Round-1 message ---
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

        // --- Round 2: each party processes Round-1 messages ---
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

        // Verify all parties computed the same aggregated (U', V')
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

        // --- Round 3: each party processes Round-2 messages ---
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

        // Reconstruct the full secret key d = sum(d_i)
        let d: <C as elliptic_curve::CurveArithmetic>::Scalar = init_outputs
            .iter()
            .map(|o| o.d_i)
            .reduce(|acc, x| acc + x)
            .unwrap();

        // Create a valid DH tuple: (G, P, U, V) where V = d*U
        let u_scalar = C::random_scalar(&mut rng);
        let u = g * u_scalar;
        let v = u * d; // V = d*U, so this is a valid DH tuple

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

        // Create an INVALID DH tuple: V is random, not d*U
        let u_scalar = C::random_scalar(&mut rng);
        let u = g * u_scalar;
        let v_scalar = C::random_scalar(&mut rng);
        let v = g * v_scalar; // V is random, NOT d*U

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
