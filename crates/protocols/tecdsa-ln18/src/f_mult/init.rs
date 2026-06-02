// SPDX-License-Identifier: MIT OR Apache-2.0
//! Protocol 4.3 — $\mathcal{F}_\text{mult}$.init: distributed ElGamal keypair generation.
//!
//! **Round 1:** Each $P_i$ samples $d_i \xleftarrow{\$} \mathbb{Z}_q$, computes
//! $\mathcal{P}_i = d_i \cdot G$. Broadcasts a hash commitment to $\mathcal{P}_i$
//! together with a Schnorr DLog proof (commit-then-prove pattern).
//!
//! **Round 2:** Each party decommits $\mathcal{P}_i$. All parties verify commitments
//! and DLog proofs.
//!
//! **Output:** Each party stores $(d_i, \mathcal{P}, \{\mathcal{P}_j\})$ where
//! $\mathcal{P} = \sum_j \mathcal{P}_j$.

use elliptic_curve::{
    group::GroupEncoding, sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField,
};
use rand_core::CryptoRngCore;
use tecdsa_commit::HashCommitment;
use tecdsa_curve::{zk::dlog::DlogProof, TecdsaCurve};
use tecdsa_protocol::PartyId;

/// Round-1 broadcast message: commitment to $(P_i, \text{proof}_i)$.
#[derive(Clone)]
pub struct InitRound1Msg {
    /// Sender party ID.
    pub from: PartyId,
    /// Hash commitment over the serialized $(P_i, \text{proof}_i)$ payload.
    pub commitment: HashCommitment,
}

/// Round-2 broadcast message: decommitment revealing $(P_i, \text{proof}_i, \text{nonce})$.
#[derive(Clone)]
pub struct InitRound2Msg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Sender party ID.
    pub from: PartyId,
    /// ElGamal public-key share $P_i = d_i \cdot G$.
    pub p_i: C::ProjectivePoint,
    /// Schnorr DLog proof: $\text{DLOG}\{d_i : P_i = d_i \cdot G\}$.
    pub proof: DlogProof<C>,
    /// Opening nonce for the Round-1 hash commitment.
    pub nonce: [u8; 32],
}

/// Internal state for the init sub-protocol.
pub struct InitState<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// This party's ID.
    my_id: PartyId,
    /// All party IDs (sorted, including self).
    parties: Vec<PartyId>,
    /// Own ElGamal secret share $d_i$.
    d_i: C::Scalar,
    /// Own ElGamal public-key share $P_i = d_i \cdot G$.
    p_i: C::ProjectivePoint,
    /// Own DLog proof.
    proof: DlogProof<C>,
    /// Own commitment opening nonce.
    decommit_nonce: [u8; 32],
    /// Received Round-1 commitments, indexed by party index (position in `parties`).
    round1_commitments: Vec<Option<HashCommitment>>,
}

/// Output of the init sub-protocol.
#[derive(Clone)]
pub struct InitOutput<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Own ElGamal decryption-key share $d_i$.
    pub d_i: C::Scalar,
    /// Joint ElGamal public key $\mathcal{P} = \sum_j \mathcal{P}_j$.
    pub elgamal_pk: C::ProjectivePoint,
    /// Per-party ElGamal public-key shares $\{\mathcal{P}_j\}$, ordered by party index.
    pub elgamal_pk_shares: Vec<C::ProjectivePoint>,
}

/// Serialize a point and proof into a byte vector for commitment.
fn serialize_commitment_payload<C: TecdsaCurve>(
    point: &C::ProjectivePoint,
    proof: &DlogProof<C>,
) -> Vec<u8>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let mut payload = Vec::new();
    payload.extend_from_slice(point.to_bytes().as_ref());
    payload.extend_from_slice(proof.commitment.to_bytes().as_ref());
    let repr = proof.response.to_repr();
    payload.extend_from_slice(AsRef::<[u8]>::as_ref(&repr));
    payload
}

impl<C: TecdsaCurve> InitState<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// Create a new init state and produce the Round-1 broadcast message.
    ///
    /// `parties` must be sorted and contain `my_id`.
    pub fn new(
        my_id: PartyId,
        parties: Vec<PartyId>,
        rng: &mut impl CryptoRngCore,
    ) -> (Self, InitRound1Msg) {
        assert!(parties.contains(&my_id), "parties list must contain my_id");

        // Sample ElGamal secret share
        let d_i = C::random_scalar(rng);
        let p_i = C::generator() * d_i;

        // Create Schnorr DLog proof
        let ephemeral = C::random_scalar(rng);
        let proof = DlogProof::<C>::prove(&d_i, &ephemeral, &p_i, b"LN18-init");

        // Commit to (P_i, proof)
        let payload = serialize_commitment_payload::<C>(&p_i, &proof);
        let (commitment, nonce) = HashCommitment::commit(&payload, rng);

        let n = parties.len();
        let round1_msg = InitRound1Msg {
            from: my_id,
            commitment: commitment.clone(),
        };

        // Store own commitment in the right slot
        let my_index = parties.iter().position(|p| *p == my_id).unwrap();
        let mut round1_commitments = vec![None; n];
        round1_commitments[my_index] = Some(commitment);

        let state = Self {
            my_id,
            parties,
            d_i,
            p_i,
            proof,
            decommit_nonce: nonce,
            round1_commitments,
        };

        (state, round1_msg)
    }

    /// Process all Round-1 messages and produce the Round-2 decommitment message.
    ///
    /// `msgs` should contain all Round-1 messages from *other* parties (self is
    /// already stored). Returns an error if a party is missing or duplicated.
    pub fn handle_round1(&mut self, msgs: &[InitRound1Msg]) -> Result<InitRound2Msg<C>, String> {
        for msg in msgs {
            if msg.from == self.my_id {
                continue; // skip self
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

        // Verify all parties sent Round-1 messages
        for (i, slot) in self.round1_commitments.iter().enumerate() {
            if slot.is_none() {
                return Err(format!("missing Round-1 message from {}", self.parties[i]));
            }
        }

        Ok(InitRound2Msg {
            from: self.my_id,
            p_i: self.p_i,
            proof: self.proof.clone(),
            nonce: self.decommit_nonce,
        })
    }

    /// Process all Round-2 decommitments and finalize the init sub-protocol.
    ///
    /// Verifies each party's commitment opening and DLog proof, then computes the
    /// joint ElGamal public key.
    pub fn finish_round2(&self, msgs: &[InitRound2Msg<C>]) -> Result<InitOutput<C>, String> {
        let n = self.parties.len();
        let mut pk_shares: Vec<Option<C::ProjectivePoint>> = vec![None; n];

        // Store own share
        let my_index = self.parties.iter().position(|p| *p == self.my_id).unwrap();
        pk_shares[my_index] = Some(self.p_i);

        for msg in msgs {
            if msg.from == self.my_id {
                continue; // skip self — already stored
            }
            let idx = self
                .parties
                .iter()
                .position(|p| *p == msg.from)
                .ok_or_else(|| format!("unknown party {}", msg.from))?;
            if pk_shares[idx].is_some() {
                return Err(format!("duplicate Round-2 message from {}", msg.from));
            }

            // Verify commitment opening
            let payload = serialize_commitment_payload::<C>(&msg.p_i, &msg.proof);
            let commitment = self.round1_commitments[idx]
                .as_ref()
                .expect("round1 commitments must be filled");
            if !commitment.verify(&payload, &msg.nonce) {
                return Err(format!("commitment verification failed for {}", msg.from));
            }

            // Verify DLog proof
            if !msg.proof.verify(&msg.p_i, b"LN18-init") {
                return Err(format!("DLog proof verification failed for {}", msg.from));
            }

            pk_shares[idx] = Some(msg.p_i);
        }

        // Ensure all shares are present
        for (i, share) in pk_shares.iter().enumerate() {
            if share.is_none() {
                return Err(format!("missing Round-2 message from {}", self.parties[i]));
            }
        }

        let shares: Vec<C::ProjectivePoint> = pk_shares.into_iter().map(|s| s.unwrap()).collect();

        // Compute joint public key P = sum(P_j)
        let elgamal_pk = shares
            .iter()
            .copied()
            .reduce(|acc, p| acc + p)
            .expect("at least one party");

        Ok(InitOutput {
            d_i: self.d_i,
            elgamal_pk,
            elgamal_pk_shares: shares,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "secp256k1")]
    type C = k256::Secp256k1;

    /// Run the full init sub-protocol for `n` parties and verify correctness.
    #[cfg(feature = "secp256k1")]
    fn run_init(n: usize) {
        let mut rng = rand::thread_rng();
        let parties: Vec<PartyId> = (0..n).map(|i| PartyId(i as u16)).collect();

        // Each party creates state + Round-1 message
        let mut states: Vec<InitState<C>> = Vec::with_capacity(n);
        let mut r1_msgs: Vec<InitRound1Msg> = Vec::with_capacity(n);
        for i in 0..n {
            let (state, msg) = InitState::<C>::new(parties[i], parties.clone(), &mut rng);
            states.push(state);
            r1_msgs.push(msg);
        }

        // Each party processes Round-1 messages and produces Round-2 message
        let mut r2_msgs: Vec<InitRound2Msg<C>> = Vec::with_capacity(n);
        for i in 0..n {
            let others: Vec<_> = r1_msgs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, m)| m.clone())
                .collect();
            let r2 = states[i]
                .handle_round1(&others)
                .expect("Round-1 should succeed");
            r2_msgs.push(r2);
        }

        // Each party processes Round-2 messages and finishes
        let mut outputs: Vec<InitOutput<C>> = Vec::with_capacity(n);
        for i in 0..n {
            let others: Vec<_> = r2_msgs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, m)| m.clone())
                .collect();
            let output = states[i]
                .finish_round2(&others)
                .expect("Round-2 should succeed");
            outputs.push(output);
        }

        // Verify: all parties compute the same joint public key
        let pk0 = outputs[0].elgamal_pk;
        for output in &outputs[1..] {
            assert_eq!(
                output.elgamal_pk, pk0,
                "all parties must agree on the joint PK"
            );
        }

        // Verify: joint PK equals sum of all d_i * G
        let expected_pk: <C as elliptic_curve::CurveArithmetic>::ProjectivePoint = outputs
            .iter()
            .map(|o| C::generator() * o.d_i)
            .reduce(|acc, p| acc + p)
            .unwrap();
        assert_eq!(pk0, expected_pk, "joint PK must equal sum of d_i * G");

        // Verify: each party's pk_shares are consistent
        for output in &outputs {
            assert_eq!(output.elgamal_pk_shares.len(), n, "should have n pk shares");
            let recomputed: <C as elliptic_curve::CurveArithmetic>::ProjectivePoint = output
                .elgamal_pk_shares
                .iter()
                .copied()
                .reduce(|acc, p| acc + p)
                .unwrap();
            assert_eq!(recomputed, pk0, "sum of pk_shares must equal joint PK");
        }

        // Verify: joint PK is not identity (extremely unlikely with random scalars)
        assert_ne!(
            pk0,
            <C as elliptic_curve::CurveArithmetic>::ProjectivePoint::IDENTITY,
            "joint PK should not be identity"
        );
    }

    #[test]
    #[cfg(feature = "secp256k1")]
    fn init_2of2() {
        run_init(2);
    }

    #[test]
    #[cfg(feature = "secp256k1")]
    fn init_3of3() {
        run_init(3);
    }
}
