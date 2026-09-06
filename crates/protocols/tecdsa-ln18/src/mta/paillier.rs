// SPDX-License-Identifier: MIT OR Apache-2.0
//! Paillier-based private multiplication backend (LN18 section 6.2).
//!
//! For each ordered pair $(P_i, P_j)$ with $i \neq j$, a 2-party Paillier MtA
//! is executed:
//!
//! 1. **Alice ($P_i$):** encrypts $a_i$ under her own Paillier key:
//!    $c_{a,i} = \text{Enc}_{N_i}(a_i; r_i)$. Sends $c_{a,i}$ to $P_j$ along
//!    with an `AliceProof` proving $|a_i| < q^3$ under each receiver's Ring-Pedersen
//!    parameters $(N', h_1, h_2)$.
//!
//! 2. **Bob ($P_j$):** verifies Alice's range proof, then computes
//!    $c_{b,ij} = b_j \odot c_{a,i} \oplus \text{Enc}_{N_i}(\beta'_{ij})$.
//!    Sends $c_{b,ij}$ back to $P_i$ along with a `BobProofExt` proving
//!    knowledge of $(b_j, \beta'_{ij}, r_j)$ with $|b_j| < q^3$ and $B_j = b_j G$.
//!
//! 3. **Alice ($P_i$):** verifies Bob's extended range proof, then decrypts
//!    $c_{b,ij}$ to get $\alpha_{ij} = a_i b_j + \beta'_{ij}$.
//!    Bob sets $\beta_{ij} = -\beta'_{ij}$.
//!
//! **Final output:** Each party computes
//! $$c_i = a_i b_i + \sum_{j \neq i} \alpha_{ij} + \sum_{j \neq i} \beta_{ji}$$
//!
//! ## Range Proofs
//!
//! Range proofs use the `AliceProof` and `BobProofExt` from `tecdsa_paillier::zk::mta_range`,
//! following GG18 Appendix A. They require Ring-Pedersen auxiliary parameters
//! $(N', h_1, h_2)$ per party, passed via `NTildeParams`.

#![allow(non_snake_case)]

use std::collections::BTreeMap;

use elliptic_curve::{
    group::GroupEncoding, sec1::ModulusSize, Field, FieldBytes, FieldBytesSize, PrimeField,
};
use rand_core::CryptoRngCore;
use rug::Integer;
use tecdsa_curve::{
    conv::{integer_to_scalar, scalar_to_integer},
    TecdsaCurve,
};
use tecdsa_paillier::{
    zk::mta_range::{AliceProof, BobProofExt, NTildeParams},
    BigIntExt, DecryptionKey, EncryptionKey,
};
use tecdsa_protocol::PartyId;

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// Round-1 P2P message: Alice sends $\text{Enc}_{N_i}(a_i)$ to each Bob.
#[derive(Clone)]
pub struct MtaRound1Msg {
    /// The sender (Alice).
    pub from: PartyId,
    /// Paillier ciphertext $c_{a,i} = \text{Enc}_{N_i}(a_i; r_i)$.
    pub c_a: Integer,
    /// Alice's range proof: proves $|a_i| < q^3$ under the receiver's
    /// Ring-Pedersen parameters.
    pub alice_proof: AliceProof,
}

/// Round-2 P2P message: Bob responds with $c_{b,ij}$ back to Alice.
pub struct MtaRound2Msg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// The sender (Bob).
    pub from: PartyId,
    /// Paillier ciphertext $c_{b,ij} = b_j \odot c_{a,i} \oplus \text{Enc}_{N_i}(\beta'_{ij})$.
    pub c_b: Integer,
    /// Bob's extended range proof: proves knowledge of $(b_j, \beta'_{ij}, r_j)$
    /// with $|b_j| < q^3$ and $B_j = b_j G$.
    pub bob_proof: BobProofExt<C>,
    /// The claimed public point $B_j = b_j G$ (verified by the BobProofExt).
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

// ---------------------------------------------------------------------------
// Per-party state
// ---------------------------------------------------------------------------

/// Per-party state for the Paillier MtA protocol.
///
/// Each party holds its own Paillier decryption key and the encryption keys
/// of all other parties.
pub struct PaillierMtaState<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// This party's ID.
    my_id: PartyId,
    /// All party IDs (sorted, including self).
    parties: Vec<PartyId>,
    /// Own Paillier decryption key.
    dk: DecryptionKey,
    /// Paillier encryption keys for all parties, keyed by party ID.
    eks: BTreeMap<PartyId, EncryptionKey>,
    /// Ring-Pedersen auxiliary parameters for all parties, keyed by party ID.
    ntilde_params: BTreeMap<PartyId, NTildeParams>,
    /// Own additive share $a_i$.
    a_i: C::Scalar,
    /// Own additive share $b_i$.
    b_i: C::Scalar,
    /// Own ciphertext $c_{a,i}$ (stored for Bob proof verification in `finish`).
    c_a: Integer,
    /// Bob's shares: for each peer $P_j$, $\beta_{ji} = -\beta'_{ji}$.
    /// These are the shares that Bob ($P_i$, acting as Bob for peer $P_j$)
    /// accumulates from round-2 processing.
    beta_shares: BTreeMap<PartyId, C::Scalar>,
}

impl<C: TecdsaCurve> PaillierMtaState<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
    C::ProjectivePoint: GroupEncoding,
{
    /// Create a new MtA state and produce Round-1 messages.
    ///
    /// Each party encrypts $a_i$ under its own Paillier key and sends the
    /// ciphertext to every other party, along with an `AliceProof` range
    /// proof for each receiver (generated under the receiver's `NTildeParams`).
    ///
    /// # Arguments
    ///
    /// - `my_id`: this party's ID
    /// - `parties`: all party IDs (sorted, including self)
    /// - `dk`: this party's Paillier decryption key
    /// - `eks`: Paillier encryption keys for all parties (keyed by party ID)
    /// - `ntilde_params`: Ring-Pedersen auxiliary parameters for all parties
    /// - `a_i`: this party's additive share $a_i$
    /// - `b_i`: this party's additive share $b_i$
    /// - `rng`: cryptographic RNG
    ///
    /// Returns the state and the Round-1 messages to send to each peer.
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

        // Encrypt a_i under our own key
        let a_i_int = scalar_to_integer::<C>(&a_i);
        let my_ek = &eks[&my_id];
        let (c_a, r_a) = my_ek
            .encrypt_with_random(rng, &a_i_int)
            .expect("Paillier encrypt must succeed");

        // Build Round-1 messages: send c_a + AliceProof to each peer
        // Each proof is generated under the RECEIVER's N_tilde params
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

    /// Process received Round-1 messages (acting as Bob) and produce Round-2 responses.
    ///
    /// For each Alice $P_j$ who sent $c_{a,j}$, Bob ($P_i$):
    /// 1. Verifies Alice's `AliceProof` range proof under our own `NTildeParams`.
    /// 2. Computes $c_{b,ji} = b_i \odot c_{a,j} \oplus \text{Enc}_{N_j}(\beta'_{ji})$.
    /// 3. Generates a `BobProofExt` for the response under Alice's `NTildeParams`.
    /// 4. Stores $\beta_{ji} = -\beta'_{ji}$.
    ///
    /// Returns Round-2 messages to send back to each Alice.
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

            // Alice's encryption key (we need to encrypt under Alice's key)
            let alice_ek = self
                .eks
                .get(&msg.from)
                .ok_or_else(|| format!("missing encryption key for party {}", msg.from))?;

            // ---- Verify Alice's range proof ----
            // Use OUR N_tilde params (we are the receiver/verifier)
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

            // Sample beta_prime uniformly from [0, N/2)
            let beta_prime = alice_ek.half_n().sample_below_ref(rng);

            // Compute c_b = b_i * c_a_j + Enc(beta_prime)
            // This encrypts (a_j * b_i + beta_prime) under Alice's key.
            //
            // When b_i = 0, omul would fail because 0 is not in Z*_N.
            // In that case b_i * c_a = Enc(0), so c_b = Enc(beta_prime).
            let r_bob = Integer::sample_in_mult_group_of(rng, alice_ek.n());
            let enc_beta = alice_ek
                .encrypt_with(&beta_prime, &r_bob)
                .expect("Paillier encrypt beta");
            let c_b = if b_i_int.cmp0().is_eq() {
                // b_i = 0 => b_i * a_j = 0 => c_b = Enc(0 + beta_prime) = enc_beta
                enc_beta
            } else {
                let b_times_ca = alice_ek.omul(&b_i_int, c_a_j).expect("Paillier scalar mul");
                alice_ek.oadd(&b_times_ca, &enc_beta).expect("Paillier add")
            };

            // ---- Generate BobProofExt ----
            // Use ALICE's N_tilde params (the sender is the verifier for Bob's proof)
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

            // B = b_i * G (the claimed public point for BobProofExt verification)
            let b_scalar = integer_to_scalar::<C>(&b_i_int);
            let b_point = C::generator() * b_scalar;

            // Bob's share: beta = -beta_prime (mod q)
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

    /// Process received Round-2 messages (acting as Alice) and compute the final
    /// output share $c_i$.
    ///
    /// For each Bob $P_j$ who responded with $c_{b,ij}$, Alice ($P_i$):
    /// 1. Verifies Bob's `BobProofExt` range proof under our own `NTildeParams`.
    /// 2. Decrypts $c_{b,ij}$ to get $\alpha_{ij} = a_i b_j + \beta'_{ij}$.
    ///
    /// Final: $c_i = a_i b_i + \sum_{j \neq i} \alpha_{ij} + \sum_{j \neq i} \beta_{ji}$
    pub fn finish(&self, msgs: &[MtaRound2Msg<C>]) -> Result<C::Scalar, String> {
        // Accumulate alpha shares from decrypting Bob's responses
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

            // ---- Verify Bob's extended range proof ----
            // Use OUR N_tilde params (we are Alice, the verifier)
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

            // Alice decrypts c_b to get alpha_ij
            let alpha_int = self
                .dk
                .decrypt(&msg.c_b)
                .map_err(|e| format!("decrypt failed for party {}: {}", msg.from, e))?;
            let alpha = integer_to_scalar::<C>(&alpha_int);
            alpha_sum += alpha;
        }

        // Verify we received from all peers
        let expected = self.parties.len() - 1;
        if seen.len() != expected {
            return Err(format!(
                "expected {} Round-2 messages, got {}",
                expected,
                seen.len()
            ));
        }

        // Accumulate beta shares (Bob's role for each peer)
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

        // c_i = a_i * b_i + sum(alpha_ij) + sum(beta_ji)
        let c_i = self.a_i * self.b_i + alpha_sum + beta_sum;

        Ok(c_i)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use tecdsa_paillier::zk::mta_range::NTildeParams;

    use super::*;

    #[cfg(feature = "secp256k1")]
    type C = k256::Secp256k1;

    /// Generate a test Paillier decryption key with 512-bit primes.
    ///
    /// 512-bit primes produce N ~ 1024 bits, which is large enough that the
    /// product a_i * b_j (~ 512 bits for secp256k1 scalars) does not wrap
    /// modulo N in the Paillier plaintext space.
    #[cfg(feature = "secp256k1")]
    fn test_paillier_dk(rng: &mut impl CryptoRngCore) -> DecryptionKey {
        let p = Integer::generate_safe_prime(rng, 512);
        let q = Integer::generate_safe_prime(rng, 512);
        DecryptionKey::from_primes(p, q).expect("valid primes")
    }

    /// Generate Ring-Pedersen auxiliary parameters $(N', h_1, h_2)$ for testing.
    #[cfg(feature = "secp256k1")]
    fn test_ntilde(rng: &mut impl CryptoRngCore) -> NTildeParams {
        let (params, _) = tecdsa_pedersen_mod::PedersenModParams::generate(256, rng);
        let (n_tilde, h1, h2) = (params.n, params.t, params.s);
        NTildeParams {
            N_tilde: n_tilde,
            h1,
            h2,
        }
    }

    /// Run the Paillier MtA protocol for `n` parties and verify correctness.
    ///
    /// Each party receives random additive shares $(a_i, b_i)$. The protocol
    /// produces shares $c_i$ such that $\sum c_i = (\sum a_i)(\sum b_i) \bmod q$.
    #[cfg(feature = "secp256k1")]
    fn run_paillier_mta(n: usize) {
        let mut rng = rand::thread_rng();
        let parties: Vec<PartyId> = (1..=n).map(|i| PartyId(i as u16)).collect();

        // Generate Paillier keys and N_tilde params for each party
        let mut dks: Vec<DecryptionKey> = Vec::with_capacity(n);
        let mut eks: BTreeMap<PartyId, EncryptionKey> = BTreeMap::new();
        let mut ntilde_map: BTreeMap<PartyId, NTildeParams> = BTreeMap::new();
        for &pid in &parties {
            let dk = test_paillier_dk(&mut rng);
            eks.insert(pid, dk.encryption_key().clone());
            dks.push(dk);
            ntilde_map.insert(pid, test_ntilde(&mut rng));
        }

        // Generate random shares
        let a_shares: Vec<<C as elliptic_curve::CurveArithmetic>::Scalar> =
            (0..n).map(|_| C::random_scalar(&mut rng)).collect();
        let b_shares: Vec<<C as elliptic_curve::CurveArithmetic>::Scalar> =
            (0..n).map(|_| C::random_scalar(&mut rng)).collect();

        // --- Round 1: each party creates state + sends c_a to peers ---
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

        // --- Round 2: each party processes received Round-1 messages ---
        // Deliver Round-1 messages: party i receives messages addressed to it
        let mut all_round2_msgs: Vec<Vec<(PartyId, MtaRound2Msg<C>)>> = Vec::with_capacity(n);

        for i in 0..n {
            // Collect messages addressed to party i
            let mut msgs_for_i: Vec<MtaRound1Msg> = Vec::new();
            for j in 0..n {
                if i == j {
                    continue;
                }
                // Find the message from party j addressed to party i
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

        // --- Finish: each party processes received Round-2 messages ---
        let mut c_shares: Vec<<C as elliptic_curve::CurveArithmetic>::Scalar> =
            Vec::with_capacity(n);

        for i in 0..n {
            // Collect messages addressed to party i
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

        // --- Verify: sum(c_i) == (sum a_i) * (sum b_i) mod q ---
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

    /// Verify that zero shares produce zero output.
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

        // All zero shares: a_i = 0, b_i = 0
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

    /// Verify correctness with one-hot shares: only one party has non-zero a, one has non-zero b.
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

        // Only party 0 has a, only party 1 has b
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
