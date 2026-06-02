// SPDX-License-Identifier: MIT OR Apache-2.0
//! Protocol 4.4 — $\mathcal{F}_\text{mult}$.input: additive share input via EGexp encryption.
//!
//! Implemented in the $\mathcal{F}_{com\text{-}zk}$ hybrid model with 2 interaction rounds:
//!
//! **Round 1 (commit):** Each $P_i$ samples $s_i \xleftarrow{\$} \mathbb{Z}_q$, computes
//! $(U_i, V_i) = \text{EGexpEnc}_\mathcal{P}(a_i; s_i)$ and an $R_{EG}$ proof.
//! Broadcasts a hash commitment to the ciphertext and proof.
//!
//! **Round 2 (decommit + verify):** Each party decommits $(U_i, V_i)$ and the
//! $R_{EG}$ proof. All parties verify commitments and proofs. Computes
//! $(U, V) = \sum_j (U_j, V_j)$.
//!
//! **Output:** Each party stores $(\text{sid}, (U, V), a_i, s_i, \{(U_j, V_j)\})$.

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

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// Round-1 broadcast message: commitment to the ciphertext and proof.
#[derive(Clone)]
pub struct InputRound1Msg {
    /// Sender party ID.
    pub from: PartyId,
    /// Hash commitment over $(U_i, V_i, \text{proof}_i)$.
    pub commitment: HashCommitment,
}

/// Round-2 broadcast message: decommitment revealing ciphertext and $R_{EG}$ proof.
pub struct InputRound2Msg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Sender party ID.
    pub from: PartyId,
    /// EGexp ciphertext $(U_i, V_i) = \text{EGexpEnc}_\mathcal{P}(a_i; s_i)$.
    pub ciphertext: EgexpCiphertext<C>,
    /// $R_{EG}$ proof of knowledge of $(a_i, s_i)$.
    pub proof: EgexpProof<C>,
    /// Opening nonce for the Round-1 hash commitment.
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

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// Internal state for the input sub-protocol.
pub struct InputState<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// This party's ID.
    my_id: PartyId,
    /// All party IDs (sorted, including self).
    parties: Vec<PartyId>,
    /// Joint ElGamal public key $\mathcal{P}$ from the init sub-protocol.
    elgamal_pk: C::ProjectivePoint,
    /// Party's additive share $a_i$.
    a_i: C::Scalar,
    /// Encryption randomness $s_i$.
    s_i: C::Scalar,
    /// Own ciphertext $(U_i, V_i)$.
    own_ct: EgexpCiphertext<C>,
    /// Own proof.
    own_proof: EgexpProof<C>,
    /// Own commitment opening nonce.
    decommit_nonce: [u8; 32],
    /// Received Round-1 commitments, indexed by party index.
    round1_commitments: Vec<Option<HashCommitment>>,
}

/// Output of the input sub-protocol.
///
/// This output is stored and reused across protocol phases (e.g., x input
/// from KeyGen is reused via `affine` during signing, per Protocol 5.1).
pub struct InputOutput<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Aggregate ciphertext $(U, V) = \sum_j (U_j, V_j)$, an encryption of $\sum_j a_j$.
    pub ciphertext: EgexpCiphertext<C>,
    /// Own additive share $a_i$.
    pub a_i: C::Scalar,
    /// Own encryption randomness $s_i$.
    pub s_i: C::Scalar,
    /// Per-party ciphertexts.
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

/// Serialize a ciphertext and proof into a byte vector for commitment.
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
    /// Create a new input state and produce the Round-1 broadcast message.
    ///
    /// - `my_id`: this party's ID
    /// - `parties`: all party IDs (sorted, including self)
    /// - `elgamal_pk`: joint ElGamal public key from init
    /// - `a_i`: this party's additive share to input
    /// - `rng`: cryptographic RNG
    pub fn new(
        my_id: PartyId,
        parties: Vec<PartyId>,
        elgamal_pk: C::ProjectivePoint,
        a_i: C::Scalar,
        rng: &mut impl CryptoRngCore,
    ) -> (Self, InputRound1Msg) {
        assert!(parties.contains(&my_id), "parties list must contain my_id");

        // Sample encryption randomness and encrypt
        let (ct, s_i) = elgamal_exp::encrypt_random::<C>(&elgamal_pk, &a_i, rng);

        // Create R_EG proof of knowledge
        let stmt = EgexpStatement::<C> {
            p: elgamal_pk,
            a: ct.a,
            b: ct.b,
        };
        let witness = EgexpWitness::<C> { x: a_i, r: s_i };
        let proof = EgexpProof::prove(&stmt, &witness, rng);

        // Commit to (ciphertext, proof)
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

    /// Process all Round-1 messages (commitments) and produce the Round-2 decommitment.
    ///
    /// `msgs` should contain all Round-1 messages from *other* parties.
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

        // Ensure all parties sent Round-1 messages
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

    /// Process all Round-2 messages and finalize the input sub-protocol.
    ///
    /// Verifies each party's commitment opening and $R_{EG}$ proof, then
    /// computes the aggregate ciphertext.
    ///
    /// `msgs` should contain all Round-2 messages from *other* parties.
    pub fn finish_round2(&self, msgs: &[InputRound2Msg<C>]) -> Result<InputOutput<C>, String> {
        let n = self.parties.len();
        let mut per_party_cts: Vec<Option<(PartyId, EgexpCiphertext<C>)>> = vec![None; n];

        // Store own ciphertext
        let my_index = self.parties.iter().position(|p| *p == self.my_id).unwrap();
        per_party_cts[my_index] = Some((self.my_id, self.own_ct.clone()));

        for msg in msgs {
            if msg.from == self.my_id {
                continue; // skip self
            }
            let idx = self
                .parties
                .iter()
                .position(|p| *p == msg.from)
                .ok_or_else(|| format!("unknown party {}", msg.from))?;
            if per_party_cts[idx].is_some() {
                return Err(format!("duplicate Round-2 message from {}", msg.from));
            }

            // Verify commitment opening
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

            // Verify R_EG proof
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

        // Ensure all parties sent messages
        for (i, slot) in per_party_cts.iter().enumerate() {
            if slot.is_none() {
                return Err(format!("missing Round-2 message from {}", self.parties[i]));
            }
        }

        let per_party: Vec<(PartyId, EgexpCiphertext<C>)> =
            per_party_cts.into_iter().map(|s| s.unwrap()).collect();

        // Compute aggregate ciphertext: (U, V) = sum of all (U_j, V_j)
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

    /// Run the full input sub-protocol (2 rounds: commit, decommit+verify)
    /// for `n` parties and verify that the aggregate ciphertext decrypts to
    /// the sum of all additive shares.
    #[cfg(feature = "secp256k1")]
    fn run_input(n: usize) {
        use crate::f_mult::init::InitState;

        let mut rng = rand::thread_rng();
        let parties: Vec<PartyId> = (0..n).map(|i| PartyId(i as u16)).collect();

        // --- First run init to get a distributed ElGamal keypair ---
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

        // --- Now run input with random additive shares ---
        let shares: Vec<<C as elliptic_curve::CurveArithmetic>::Scalar> =
            (0..n).map(|_| C::random_scalar(&mut rng)).collect();

        // Input Round 1: send commitments
        let mut input_states: Vec<InputState<C>> = Vec::with_capacity(n);
        let mut input_r1_msgs: Vec<InputRound1Msg> = Vec::with_capacity(n);
        for i in 0..n {
            let (state, msg) =
                InputState::<C>::new(parties[i], parties.clone(), elgamal_pk, shares[i], &mut rng);
            input_states.push(state);
            input_r1_msgs.push(msg);
        }

        // Input Round 2: decommit
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

        // Finish: verify decommitments and proofs
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

        // Verify: all parties compute the same aggregate ciphertext
        let ct0 = &input_outputs[0].ciphertext;
        for output in &input_outputs[1..] {
            assert_eq!(
                output.ciphertext, *ct0,
                "all parties must agree on the aggregate ciphertext"
            );
        }

        // Verify: aggregate ciphertext decrypts to (sum of a_i) * G
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

        // Verify: per-party ciphertexts are stored
        for output in &input_outputs {
            assert_eq!(
                output.per_party_cts.len(),
                n,
                "should have n per-party ciphertexts"
            );
        }

        // Verify: own share and randomness are preserved
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
