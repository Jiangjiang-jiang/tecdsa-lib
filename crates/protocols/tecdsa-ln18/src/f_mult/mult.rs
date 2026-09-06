// SPDX-License-Identifier: MIT OR Apache-2.0
//! Protocol 4.7 -- $\mathcal{F}_\text{mult}$.mult: multiply two encrypted values
//! and output additive shares of the product.
//!
//! Given stored input for $a$ (sid1, from a previous `input` call) and $b$
//! (sid2, from another `input` call), compute $c = a \cdot b$ and output
//! additive shares $c_i$ such that $\sum c_i = a \cdot b$.
//!
//! This is the full 6-round version with inlined $\mathcal{F}_\text{checkDH}$.
//!
//! **Step 0 (external):** The caller runs $\pi_\text{mult}^\text{priv}$ (Paillier
//! MtA) with inputs $(a_i, b_i)$. $P_i$ gets output $c_i$. This share is
//! provided as input to the mult protocol.
//!
//! **Round 1:** $P_i$ computes
//! $E_i = a_i \cdot X_b + s'_i \cdot G$, $F_i = a_i \cdot Y_b + s'_i \cdot \mathcal{P}$
//! and sends $(E_i, F_i)$ with $R_\text{prod}$ proof to all parties.
//!
//! **Round 2:** Verify all $R_\text{prod}$ proofs. Aggregate $(E, F) = \sum_j (E_j, F_j)$.
//! $P_i$ computes $(A_i, B_i) = \text{EGexpEnc}_\mathcal{P}(c_i; \hat{s}_i)$.
//! Sends $(A_i, B_i)$ with $R_{EG}$ proof.
//!
//! **Round 3:** Verify all $R_{EG}$ proofs. Compute
//! $\mathcal{A} = E - \sum_j A_j$, $\mathcal{B} = F - \sum_j B_j$.
//! Begin $\mathcal{F}_\text{checkDH}$ on $(\mathcal{A}, \mathcal{B})$:
//! Each $P_i$ rerandomizes: $U'_i = r_i G + s''_i \mathcal{A}$,
//! $V'_i = r_i \mathcal{P} + s''_i \mathcal{B}$. Sends $(U'_i, V'_i)$ with $R_{RE}$ proof.
//!
//! **Round 4:** Verify all $R_{RE}$ proofs. Aggregate $(U', V') = \sum (U'_j, V'_j)$.
//! Each $P_i$ computes $W_i = d_i \cdot U'$ and sends $W_i$ with $R_{DH}$ proof
//! that $(G, U', \mathcal{P}_i, W_i)$ is a DH tuple (witness $d_i$).
//!
//! **Round 5:** Verify all checkDH $R_{DH}$ proofs. Check $\sum W_j = V'$.
//! If checkDH accepts, $P_i$ sends $c_i$ with $R_{DH}$ proof that
//! $(G, \mathcal{P}, A_i, B_i - c_i \cdot G)$ is a DH tuple with witness $\hat{s}_i$.
//!
//! **Round 6 (output):** Verify all $R_{DH}$ proofs. Output $c = \sum_j c_j$.

#![allow(non_snake_case)]

use elliptic_curve::{sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField};
use rand_core::CryptoRngCore;
use tecdsa_curve::{
    elgamal_exp::{self, EgexpCiphertext},
    zk::{
        ddh::{DdhProof, DdhStatement, DdhWitness},
        egexp::{EgexpProof, EgexpStatement, EgexpWitness},
        prod::{ProdProof, ProdStatement, ProdWitness},
        rerandom::{ReProof, ReStatement, ReWitness},
    },
    TecdsaCurve,
};
use tecdsa_protocol::PartyId;

use super::input::InputOutput;

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// Round-1 broadcast message: $(E_i, F_i)$ and $R_\text{prod}$ proof.
pub struct MultRound1Msg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Sender party ID.
    pub from: PartyId,
    /// Product ciphertext part 1: $E_i = a_i \cdot X_b + s'_i \cdot G$.
    pub e_i: C::ProjectivePoint,
    /// Product ciphertext part 2: $F_i = a_i \cdot Y_b + s'_i \cdot \mathcal{P}$.
    pub f_i: C::ProjectivePoint,
    /// $R_\text{prod}$ proof.
    pub prod_proof: ProdProof<C>,
}

impl<C: TecdsaCurve> Clone for MultRound1Msg<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn clone(&self) -> Self {
        Self {
            from: self.from,
            e_i: self.e_i,
            f_i: self.f_i,
            prod_proof: self.prod_proof.clone(),
        }
    }
}

/// Round-2 broadcast message: $(A_i, B_i)$ EGexp encryption of $c_i$ and $R_{EG}$ proof.
pub struct MultRound2Msg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Sender party ID.
    pub from: PartyId,
    /// EGexp ciphertext of $c_i$: $A_i = \hat{s}_i \cdot G$.
    pub a_i: C::ProjectivePoint,
    /// EGexp ciphertext of $c_i$: $B_i = \hat{s}_i \cdot \mathcal{P} + c_i \cdot G$.
    pub b_i: C::ProjectivePoint,
    /// $R_{EG}$ proof of knowledge of $(c_i, \hat{s}_i)$.
    pub egexp_proof: EgexpProof<C>,
}

impl<C: TecdsaCurve> Clone for MultRound2Msg<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn clone(&self) -> Self {
        Self {
            from: self.from,
            a_i: self.a_i,
            b_i: self.b_i,
            egexp_proof: self.egexp_proof.clone(),
        }
    }
}

/// Round-3 broadcast message: checkDH rerandomization shares $(U'_i, V'_i)$ and $R_{RE}$ proof.
pub struct MultRound3Msg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Sender party ID.
    pub from: PartyId,
    /// Rerandomized U-share: $U'_i = r_i G + s''_i \mathcal{A}$.
    pub u_prime_i: C::ProjectivePoint,
    /// Rerandomized V-share: $V'_i = r_i \mathcal{P} + s''_i \mathcal{B}$.
    pub v_prime_i: C::ProjectivePoint,
    /// $R_{RE}$ proof.
    pub re_proof: ReProof<C>,
}

impl<C: TecdsaCurve> Clone for MultRound3Msg<C>
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

/// Round-4 broadcast message: checkDH partial decryption $W_i$ and $R_{DH}$ proof.
pub struct MultRound4Msg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Sender party ID.
    pub from: PartyId,
    /// Partial decryption: $W_i = d_i \cdot U'$.
    pub w_i: C::ProjectivePoint,
    /// $R_{DH}$ proof that $(G, U', \mathcal{P}_i, W_i)$ is a DH tuple (witness $d_i$).
    pub ddh_proof: DdhProof<C>,
}

impl<C: TecdsaCurve> Clone for MultRound4Msg<C>
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

/// Round-5 broadcast message: $c_i$ share and $R_{DH}$ proof (sent after checkDH passes).
pub struct MultRound5Msg<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Sender party ID.
    pub from: PartyId,
    /// Party's share $c_i$ of the product $a \cdot b$.
    pub c_i: C::Scalar,
    /// $R_{DH}$ proof that $(\mathcal{P}, A_i, B_i - c_i G)$ is consistent
    /// with the EGexp encryption, with witness $\hat{s}_i$.
    pub ddh_proof: DdhProof<C>,
}

impl<C: TecdsaCurve> Clone for MultRound5Msg<C>
where
    FieldBytesSize<C>: ModulusSize,
{
    fn clone(&self) -> Self {
        Self {
            from: self.from,
            c_i: self.c_i,
            ddh_proof: self.ddh_proof.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// Internal state for the mult sub-protocol (full 6-round version with checkDH).
pub struct MultState<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// This party's ID.
    my_id: PartyId,
    /// All party IDs (sorted, including self).
    parties: Vec<PartyId>,
    /// Joint ElGamal public key $\mathcal{P}$.
    elgamal_pk: C::ProjectivePoint,
    /// Per-party ciphertexts from input_a: $(U_{a,j}, V_{a,j})$.
    input_a_per_party_cts: Vec<(PartyId, EgexpCiphertext<C>)>,
    /// Aggregate ciphertext $(X_b, Y_b)$ from input_b: EGexp encryption of $b$.
    input_b_ciphertext: EgexpCiphertext<C>,
    /// MtA result: party's share $c_i$ such that $\sum c_i = a \cdot b$.
    c_i: C::Scalar,
    /// Fresh randomness $\hat{s}_i$ used for the EGexp encryption of $c_i$.
    s_hat_i: C::Scalar,
    /// Own EGexp ciphertext of $c_i$: $(A_i, B_i)$.
    own_ci_ct: Option<EgexpCiphertext<C>>,
    /// Own ElGamal secret share $d_i$ (needed for checkDH).
    d_i: C::Scalar,
    /// Own ElGamal public-key share $\mathcal{P}_i = d_i \cdot G$.
    p_i: C::ProjectivePoint,
    /// Per-party ElGamal public-key shares $\{\mathcal{P}_j\}$, ordered by party index.
    elgamal_pk_shares: Vec<C::ProjectivePoint>,
}

/// Output of the mult sub-protocol.
pub struct MultOutput<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Party's share of the product $c_i$.
    pub c_i: C::Scalar,
    /// The reconstructed product $c = \sum c_j = a \cdot b$.
    pub c: C::Scalar,
}

/// Intermediate state after processing Round-1 messages, needed for Round 2 verification.
pub struct MultRound1Result<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Aggregated product ciphertext: $E = \sum E_j$.
    pub e_agg: C::ProjectivePoint,
    /// Aggregated product ciphertext: $F = \sum F_j$.
    pub f_agg: C::ProjectivePoint,
}

/// Intermediate state after processing Round-2 messages.
pub struct MultRound2Result<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Per-party EGexp ciphertexts of $c_j$: $(A_j, B_j)$.
    pub per_party_ci_cts: Vec<(PartyId, EgexpCiphertext<C>)>,
    /// Difference ciphertext $\mathcal{A} = E - \sum A_j$.
    pub cal_a: C::ProjectivePoint,
    /// Difference ciphertext $\mathcal{B} = F - \sum B_j$.
    pub cal_b: C::ProjectivePoint,
}

/// Intermediate state after processing Round-3 messages (checkDH Round 1).
pub struct MultRound3Result<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Aggregated rerandomized $U' = \sum U'_j$.
    pub u_prime: C::ProjectivePoint,
    /// Aggregated rerandomized $V' = \sum V'_j$.
    pub v_prime: C::ProjectivePoint,
}

/// Intermediate state after processing Round-4 messages (checkDH Round 2).
pub struct MultRound4Result<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// Per-party EGexp ciphertexts of $c_j$: $(A_j, B_j)$ (passed through).
    pub per_party_ci_cts: Vec<(PartyId, EgexpCiphertext<C>)>,
}

impl<C: TecdsaCurve> MultState<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// Create a new mult state and produce the Round-1 broadcast message.
    ///
    /// # Arguments
    ///
    /// - `my_id`: this party's ID
    /// - `parties`: all party IDs (sorted, including self)
    /// - `input_a`: stored output from the `input` call for value $a$
    /// - `input_b`: stored output from the `input` call for value $b$
    /// - `c_i`: MtA result share (from running Paillier MtA externally)
    /// - `elgamal_pk`: joint ElGamal public key $\mathcal{P}$
    /// - `d_i`: own ElGamal secret share
    /// - `elgamal_pk_shares`: per-party ElGamal public-key shares
    /// - `rng`: cryptographic RNG
    pub fn new(
        my_id: PartyId,
        parties: Vec<PartyId>,
        input_a: &InputOutput<C>,
        input_b: &InputOutput<C>,
        c_i: C::Scalar,
        elgamal_pk: C::ProjectivePoint,
        d_i: C::Scalar,
        elgamal_pk_shares: Vec<C::ProjectivePoint>,
        rng: &mut impl CryptoRngCore,
    ) -> (Self, MultRound1Msg<C>) {
        assert!(parties.contains(&my_id), "parties list must contain my_id");
        assert_eq!(
            elgamal_pk_shares.len(),
            parties.len(),
            "must have one pk share per party"
        );

        let g = C::generator();
        let a_i = input_a.a_i;
        let s_a_i = input_a.s_i;

        // (X_b, Y_b) is the aggregate ciphertext for b
        let x_b = input_b.ciphertext.a;
        let y_b = input_b.ciphertext.b;

        // Sample fresh randomness s'_i for the product ciphertext
        let s_prime_i = C::random_scalar(rng);

        // Compute (E_i, F_i):
        // E_i = a_i * X_b + s'_i * G
        // F_i = a_i * Y_b + s'_i * P
        let e_i = x_b * a_i + g * s_prime_i;
        let f_i = y_b * a_i + elgamal_pk * s_prime_i;

        // Find own ciphertext from input_a: (U_{a,i}, V_{a,i})
        let own_a_ct = input_a
            .per_party_cts
            .iter()
            .find(|(pid, _)| *pid == my_id)
            .expect("input_a per_party_cts must contain own ciphertext")
            .1
            .clone();

        // Build R_prod proof.
        let prod_stmt = ProdStatement::<C> {
            p: elgamal_pk,
            a: x_b,
            b: y_b,
            c: own_a_ct.a,
            d: own_a_ct.b,
            e_pt: e_i,
            f: f_i,
        };
        let prod_wit = ProdWitness::<C> {
            t: s_a_i,
            r: s_prime_i,
            y: a_i,
        };
        let prod_proof = ProdProof::prove(&prod_stmt, &prod_wit, rng);

        // Pre-sample s_hat_i for later use in Round 2
        let s_hat_i = C::random_scalar(rng);

        // Compute own public-key share P_i = d_i * G
        let p_i = g * d_i;

        let round1_msg = MultRound1Msg {
            from: my_id,
            e_i,
            f_i,
            prod_proof,
        };

        let state = Self {
            my_id,
            parties,
            elgamal_pk,
            input_a_per_party_cts: input_a.per_party_cts.clone(),
            input_b_ciphertext: input_b.ciphertext.clone(),
            c_i,
            s_hat_i,
            own_ci_ct: None,
            d_i,
            p_i,
            elgamal_pk_shares,
        };

        (state, round1_msg)
    }

    /// Process all Round-1 messages, verify $R_\text{prod}$ proofs, and produce
    /// the Round-2 broadcast message.
    ///
    /// Aggregates $(E, F) = \sum_j (E_j, F_j)$ and encrypts $c_i$ under EGexp.
    ///
    /// `msgs` should contain all Round-1 messages from *other* parties.
    /// `own_round1` is this party's own Round-1 message (needed for aggregation).
    pub fn handle_round1(
        &mut self,
        msgs: &[MultRound1Msg<C>],
        own_round1: &MultRound1Msg<C>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(MultRound2Msg<C>, MultRound1Result<C>), String> {
        let n = self.parties.len();

        let x_b = self.input_b_ciphertext.a;
        let y_b = self.input_b_ciphertext.b;

        // Collect all (E_j, F_j) including own
        let mut e_shares: Vec<Option<C::ProjectivePoint>> = vec![None; n];
        let mut f_shares: Vec<Option<C::ProjectivePoint>> = vec![None; n];

        // Store own share
        let my_index = self.parties.iter().position(|p| *p == self.my_id).unwrap();
        e_shares[my_index] = Some(own_round1.e_i);
        f_shares[my_index] = Some(own_round1.f_i);

        for msg in msgs {
            if msg.from == self.my_id {
                continue;
            }
            let idx = self
                .parties
                .iter()
                .position(|p| *p == msg.from)
                .ok_or_else(|| format!("unknown party {}", msg.from))?;
            if e_shares[idx].is_some() {
                return Err(format!("duplicate Round-1 message from {}", msg.from));
            }

            // Find party j's ciphertext from input_a: (U_{a,j}, V_{a,j})
            let ct_a_j = self
                .input_a_per_party_cts
                .iter()
                .find(|(pid, _)| *pid == msg.from)
                .ok_or_else(|| format!("no input_a ciphertext for party {}", msg.from))?
                .1
                .clone();

            // Verify R_prod proof
            let prod_stmt = ProdStatement::<C> {
                p: self.elgamal_pk,
                a: x_b,
                b: y_b,
                c: ct_a_j.a,
                d: ct_a_j.b,
                e_pt: msg.e_i,
                f: msg.f_i,
            };
            if !msg.prod_proof.verify(&prod_stmt) {
                return Err(format!(
                    "R_prod proof verification failed for party {}",
                    msg.from
                ));
            }

            e_shares[idx] = Some(msg.e_i);
            f_shares[idx] = Some(msg.f_i);
        }

        // Ensure all parties sent Round-1 messages
        for (i, slot) in e_shares.iter().enumerate() {
            if slot.is_none() {
                return Err(format!(
                    "missing Round-1 message from party {}",
                    self.parties[i]
                ));
            }
        }

        // Aggregate: (E, F) = sum of (E_j, F_j)
        let e_agg: C::ProjectivePoint = e_shares
            .iter()
            .map(|s| s.unwrap())
            .reduce(|acc, p| acc + p)
            .expect("at least one party");
        let f_agg: C::ProjectivePoint = f_shares
            .iter()
            .map(|s| s.unwrap())
            .reduce(|acc, p| acc + p)
            .expect("at least one party");

        // Encrypt c_i under EGexp: (A_i, B_i) = EGexpEnc_P(c_i; s_hat_i)
        let ci_ct = elgamal_exp::encrypt::<C>(&self.elgamal_pk, &self.c_i, &self.s_hat_i);
        self.own_ci_ct = Some(ci_ct.clone());

        // Build R_EG proof
        let egexp_stmt = EgexpStatement::<C> {
            p: self.elgamal_pk,
            a: ci_ct.a,
            b: ci_ct.b,
        };
        let egexp_wit = EgexpWitness::<C> {
            x: self.c_i,
            r: self.s_hat_i,
        };
        let egexp_proof = EgexpProof::prove(&egexp_stmt, &egexp_wit, rng);

        let round2_msg = MultRound2Msg {
            from: self.my_id,
            a_i: ci_ct.a,
            b_i: ci_ct.b,
            egexp_proof,
        };

        let r1_result = MultRound1Result { e_agg, f_agg };

        Ok((round2_msg, r1_result))
    }

    /// Process all Round-2 messages, verify $R_{EG}$ proofs, compute
    /// $(\mathcal{A}, \mathcal{B})$, and produce the Round-3 broadcast message
    /// (checkDH Round 1: rerandomization).
    ///
    /// `msgs` should contain all Round-2 messages from *other* parties.
    pub fn handle_round2(
        &self,
        msgs: &[MultRound2Msg<C>],
        r1_result: &MultRound1Result<C>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(MultRound3Msg<C>, MultRound2Result<C>), String> {
        let n = self.parties.len();

        let ci_ct = self
            .own_ci_ct
            .as_ref()
            .expect("own_ci_ct must be set after handle_round1");

        // Collect all (A_j, B_j) including own
        let mut ci_cts: Vec<Option<(PartyId, EgexpCiphertext<C>)>> = vec![None; n];

        let my_index = self.parties.iter().position(|p| *p == self.my_id).unwrap();
        ci_cts[my_index] = Some((self.my_id, ci_ct.clone()));

        for msg in msgs {
            if msg.from == self.my_id {
                continue;
            }
            let idx = self
                .parties
                .iter()
                .position(|p| *p == msg.from)
                .ok_or_else(|| format!("unknown party {}", msg.from))?;
            if ci_cts[idx].is_some() {
                return Err(format!("duplicate Round-2 message from {}", msg.from));
            }

            // Verify R_EG proof
            let egexp_stmt = EgexpStatement::<C> {
                p: self.elgamal_pk,
                a: msg.a_i,
                b: msg.b_i,
            };
            if !msg.egexp_proof.verify(&egexp_stmt) {
                return Err(format!(
                    "R_EG proof verification failed for party {}",
                    msg.from
                ));
            }

            ci_cts[idx] = Some((
                msg.from,
                EgexpCiphertext::<C> {
                    a: msg.a_i,
                    b: msg.b_i,
                },
            ));
        }

        // Ensure all parties sent Round-2 messages
        for (i, slot) in ci_cts.iter().enumerate() {
            if slot.is_none() {
                return Err(format!(
                    "missing Round-2 message from party {}",
                    self.parties[i]
                ));
            }
        }

        let per_party_ci_cts: Vec<(PartyId, EgexpCiphertext<C>)> =
            ci_cts.into_iter().map(|s| s.unwrap()).collect();

        // Compute A_sum = sum(A_j), B_sum = sum(B_j)
        let a_sum: C::ProjectivePoint = per_party_ci_cts
            .iter()
            .map(|(_, ct)| ct.a)
            .reduce(|acc, p| acc + p)
            .expect("at least one party");
        let b_sum: C::ProjectivePoint = per_party_ci_cts
            .iter()
            .map(|(_, ct)| ct.b)
            .reduce(|acc, p| acc + p)
            .expect("at least one party");

        // Compute (cal_A, cal_B) = (E - sum(A_j), F - sum(B_j))
        // This should be an encryption of 0 under the joint key if sum(c_i) = a*b
        let cal_a = r1_result.e_agg - a_sum;
        let cal_b = r1_result.f_agg - b_sum;

        // --- Begin checkDH Round 1: rerandomize (cal_A, cal_B) ---
        let g = C::generator();
        let r_i = C::random_scalar(rng);
        let s_i = C::random_scalar(rng);

        // Compute rerandomization shares
        let u_prime_i = g * r_i + cal_a * s_i;
        let v_prime_i = self.elgamal_pk * r_i + cal_b * s_i;

        // Build R_RE proof
        let re_stmt = ReStatement::<C> {
            g,
            p: self.elgamal_pk,
            a: cal_a,
            b: cal_b,
            a_prime: u_prime_i,
            b_prime: v_prime_i,
        };
        let re_wit = ReWitness::<C> { r: r_i, s: s_i };
        let sigma = C::random_scalar(rng);
        let tau = C::random_scalar(rng);
        let re_proof = ReProof::prove(&re_stmt, &re_wit, &sigma, &tau);

        let round3_msg = MultRound3Msg {
            from: self.my_id,
            u_prime_i,
            v_prime_i,
            re_proof,
        };

        let r2_result = MultRound2Result {
            per_party_ci_cts,
            cal_a,
            cal_b,
        };

        Ok((round3_msg, r2_result))
    }

    /// Process all Round-3 messages (checkDH Round 1), verify $R_{RE}$ proofs,
    /// aggregate rerandomization shares, and produce Round-4 message
    /// (checkDH Round 2: partial decryption).
    ///
    /// `msgs` should contain all Round-3 messages from *other* parties.
    pub fn handle_round3(
        &self,
        msgs: &[MultRound3Msg<C>],
        own_round3: &MultRound3Msg<C>,
        r2_result: &MultRound2Result<C>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(MultRound4Msg<C>, MultRound3Result<C>), String> {
        let n = self.parties.len();
        let g = C::generator();

        // Collect all rerandomization shares (including own)
        let mut u_primes: Vec<Option<C::ProjectivePoint>> = vec![None; n];
        let mut v_primes: Vec<Option<C::ProjectivePoint>> = vec![None; n];

        let my_index = self.parties.iter().position(|p| *p == self.my_id).unwrap();
        u_primes[my_index] = Some(own_round3.u_prime_i);
        v_primes[my_index] = Some(own_round3.v_prime_i);

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
                return Err(format!("duplicate Round-3 message from {}", msg.from));
            }

            // Verify R_RE proof
            let re_stmt = ReStatement::<C> {
                g,
                p: self.elgamal_pk,
                a: r2_result.cal_a,
                b: r2_result.cal_b,
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

        // Ensure all parties sent Round-3 messages
        for (i, slot) in u_primes.iter().enumerate() {
            if slot.is_none() {
                return Err(format!(
                    "missing Round-3 message from party {}",
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
        let ddh_stmt = DdhStatement::<C> {
            g,
            a: u_prime,
            b: self.p_i,
            c: w_i,
        };
        let ddh_wit = DdhWitness::<C> { w: self.d_i };
        let ddh_proof = DdhProof::prove(&ddh_stmt, &ddh_wit, rng);

        let round4_msg = MultRound4Msg {
            from: self.my_id,
            w_i,
            ddh_proof,
        };

        let r3_result = MultRound3Result { u_prime, v_prime };

        Ok((round4_msg, r3_result))
    }

    /// Process all Round-4 messages (checkDH Round 2), verify $R_{DH}$ proofs,
    /// check $\sum W_j = V'$, and produce the Round-5 message (reveal $c_i$).
    ///
    /// If checkDH fails (the tuple is not DH), returns an error.
    ///
    /// `msgs` should contain all Round-4 messages from *other* parties.
    pub fn handle_round4(
        &self,
        msgs: &[MultRound4Msg<C>],
        r2_result: &MultRound2Result<C>,
        r3_result: &MultRound3Result<C>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(MultRound5Msg<C>, MultRound4Result<C>), String> {
        let n = self.parties.len();
        let g = C::generator();

        let mut w_shares: Vec<Option<C::ProjectivePoint>> = vec![None; n];

        // Compute own W_i = d_i * U'
        let my_index = self.parties.iter().position(|p| *p == self.my_id).unwrap();
        let own_w_i = r3_result.u_prime * self.d_i;
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
                return Err(format!("duplicate Round-4 message from {}", msg.from));
            }

            // Verify R_DH proof: (G, U', P_j, W_j) is DH tuple
            let ddh_stmt = DdhStatement::<C> {
                g,
                a: r3_result.u_prime,
                b: self.elgamal_pk_shares[idx],
                c: msg.w_i,
            };
            if !msg.ddh_proof.verify(&ddh_stmt) {
                return Err(format!(
                    "checkDH R_DH proof verification failed for party {}",
                    msg.from
                ));
            }

            w_shares[idx] = Some(msg.w_i);
        }

        // Ensure all parties sent Round-4 messages
        for (i, slot) in w_shares.iter().enumerate() {
            if slot.is_none() {
                return Err(format!(
                    "missing Round-4 message from party {}",
                    self.parties[i]
                ));
            }
        }

        // checkDH final check: sum(W_j) == V'
        let sum_w: C::ProjectivePoint = w_shares
            .iter()
            .map(|s| s.unwrap())
            .reduce(|acc, p| acc + p)
            .expect("at least one party");

        if sum_w != r3_result.v_prime {
            return Err("checkDH failed: (G, P, cal_A, cal_B) is NOT a DH tuple — MtA shares are inconsistent".into());
        }

        // checkDH passed! Now safe to reveal c_i.
        let ci_ct = self
            .own_ci_ct
            .as_ref()
            .expect("own_ci_ct must be set after handle_round1");

        // Build R_DH proof: prove that (G, P, A_i, B_i - c_i*G) is a DH tuple
        // with witness s_hat_i.
        let c_i_point = g * self.c_i;
        let ddh_stmt = DdhStatement::<C> {
            g,
            a: self.elgamal_pk,
            b: ci_ct.a,             // A_i = s_hat_i * G
            c: ci_ct.b - c_i_point, // B_i - c_i*G = s_hat_i * P
        };
        let ddh_wit = DdhWitness::<C> { w: self.s_hat_i };
        let ddh_proof = DdhProof::prove(&ddh_stmt, &ddh_wit, rng);

        let round5_msg = MultRound5Msg {
            from: self.my_id,
            c_i: self.c_i,
            ddh_proof,
        };

        let r4_result = MultRound4Result {
            per_party_ci_cts: r2_result.per_party_ci_cts.clone(),
        };

        Ok((round5_msg, r4_result))
    }

    /// Process all Round-5 messages, verify $R_{DH}$ proofs, and output the product.
    ///
    /// `msgs` should contain all Round-5 messages from *other* parties.
    pub fn finish_round5(
        &self,
        msgs: &[MultRound5Msg<C>],
        r4_result: &MultRound4Result<C>,
    ) -> Result<MultOutput<C>, String> {
        let n = self.parties.len();
        let g = C::generator();

        let mut c_shares: Vec<Option<C::Scalar>> = vec![None; n];

        // Store own share
        let my_index = self.parties.iter().position(|p| *p == self.my_id).unwrap();
        c_shares[my_index] = Some(self.c_i);

        for msg in msgs {
            if msg.from == self.my_id {
                continue;
            }
            let idx = self
                .parties
                .iter()
                .position(|p| *p == msg.from)
                .ok_or_else(|| format!("unknown party {}", msg.from))?;
            if c_shares[idx].is_some() {
                return Err(format!("duplicate Round-5 message from {}", msg.from));
            }

            // Find party j's EGexp ciphertext (A_j, B_j) from Round 2
            let ct_j = r4_result
                .per_party_ci_cts
                .iter()
                .find(|(pid, _)| *pid == msg.from)
                .ok_or_else(|| format!("no Round-2 ciphertext for party {}", msg.from))?
                .1
                .clone();

            // Verify R_DH proof: (G, P, A_j, B_j - c_j*G) is a DH tuple
            let c_j_point = g * msg.c_i;
            let ddh_stmt = DdhStatement::<C> {
                g,
                a: self.elgamal_pk,
                b: ct_j.a,             // A_j
                c: ct_j.b - c_j_point, // B_j - c_j*G
            };
            if !msg.ddh_proof.verify(&ddh_stmt) {
                return Err(format!(
                    "R_DH proof verification failed for party {}",
                    msg.from
                ));
            }

            c_shares[idx] = Some(msg.c_i);
        }

        // Ensure all parties sent Round-5 messages
        for (i, slot) in c_shares.iter().enumerate() {
            if slot.is_none() {
                return Err(format!(
                    "missing Round-5 message from party {}",
                    self.parties[i]
                ));
            }
        }

        // Compute c = sum(c_j)
        let c: C::Scalar = c_shares
            .iter()
            .map(|s| s.unwrap())
            .reduce(|acc, s| acc + s)
            .expect("at least one party");

        Ok(MultOutput { c_i: self.c_i, c })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use tecdsa_paillier::{
        backend::Integer, zk::mta_range::NTildeParams, BigIntExt, DecryptionKey, EncryptionKey,
    };

    use super::*;
    use crate::{
        f_mult::{init::InitState, input::InputState},
        mta::paillier::{MtaRound1Msg, MtaRound2Msg, PaillierMtaState},
    };

    #[cfg(feature = "secp256k1")]
    type C = k256::Secp256k1;

    /// Generate a test Paillier decryption key with 512-bit primes.
    #[cfg(feature = "secp256k1")]
    fn test_paillier_dk(rng: &mut impl CryptoRngCore) -> DecryptionKey {
        let p = Integer::generate_safe_prime(rng, 512);
        let q = Integer::generate_safe_prime(rng, 512);
        DecryptionKey::from_primes(p, q).expect("valid primes")
    }

    /// Generate Ring-Pedersen auxiliary parameters for testing.
    #[cfg(feature = "secp256k1")]
    fn test_ntilde(rng: &mut impl CryptoRngCore) -> NTildeParams {
        let p = Integer::generate_safe_prime(rng, 256);
        let q = Integer::generate_safe_prime(rng, 256);
        let n_tilde = Integer::from(&p * &q);
        let h1 = Integer::sample_in_mult_group_of(rng, &n_tilde);
        let phi_n = (p - Integer::one()) * (q - Integer::one());
        let lambda = phi_n.sample_below_ref(rng);
        let h2 = Integer::from(h1.pow_mod_ref(&lambda, &n_tilde).expect("pow_mod defined"));
        NTildeParams {
            N_tilde: n_tilde,
            h1,
            h2,
        }
    }

    /// Run the init sub-protocol for `n` parties and return party IDs and outputs.
    #[cfg(feature = "secp256k1")]
    fn run_init(
        n: usize,
        rng: &mut impl CryptoRngCore,
    ) -> (Vec<PartyId>, Vec<crate::f_mult::init::InitOutput<C>>) {
        let parties: Vec<PartyId> = (0..n).map(|i| PartyId(i as u16)).collect();

        let mut init_states: Vec<InitState<C>> = Vec::with_capacity(n);
        let mut r1_msgs = Vec::with_capacity(n);
        for i in 0..n {
            let (state, msg) = InitState::<C>::new(parties[i], parties.clone(), rng);
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

    /// Run the input sub-protocol for `n` parties with given shares.
    #[cfg(feature = "secp256k1")]
    fn run_input(
        parties: &[PartyId],
        elgamal_pk: <C as elliptic_curve::CurveArithmetic>::ProjectivePoint,
        shares: &[<C as elliptic_curve::CurveArithmetic>::Scalar],
        rng: &mut impl CryptoRngCore,
    ) -> Vec<InputOutput<C>> {
        let n = parties.len();

        let mut input_states: Vec<InputState<C>> = Vec::with_capacity(n);
        let mut input_r1_msgs = Vec::with_capacity(n);
        for i in 0..n {
            let (state, msg) =
                InputState::<C>::new(parties[i], parties.to_vec(), elgamal_pk, shares[i], rng);
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

        input_outputs
    }

    /// Run the Paillier MtA protocol for `n` parties and return c_i shares.
    #[cfg(feature = "secp256k1")]
    fn run_paillier_mta(
        parties: &[PartyId],
        a_shares: &[<C as elliptic_curve::CurveArithmetic>::Scalar],
        b_shares: &[<C as elliptic_curve::CurveArithmetic>::Scalar],
        rng: &mut impl CryptoRngCore,
    ) -> Vec<<C as elliptic_curve::CurveArithmetic>::Scalar> {
        let n = parties.len();

        // Generate Paillier keys + N_tilde params
        let mut dks: Vec<DecryptionKey> = Vec::with_capacity(n);
        let mut eks: BTreeMap<PartyId, EncryptionKey> = BTreeMap::new();
        let mut ntilde_map: BTreeMap<PartyId, NTildeParams> = BTreeMap::new();
        for &pid in parties {
            let dk = test_paillier_dk(rng);
            eks.insert(pid, dk.encryption_key().clone());
            dks.push(dk);
            ntilde_map.insert(pid, test_ntilde(rng));
        }

        // Round 1
        let mut states: Vec<PaillierMtaState<C>> = Vec::with_capacity(n);
        let mut all_r1_msgs: Vec<Vec<(PartyId, MtaRound1Msg)>> = Vec::with_capacity(n);
        for i in 0..n {
            let (state, r1_msgs) = PaillierMtaState::<C>::new(
                parties[i],
                parties.to_vec(),
                dks[i].clone(),
                eks.clone(),
                ntilde_map.clone(),
                a_shares[i],
                b_shares[i],
                rng,
            );
            states.push(state);
            all_r1_msgs.push(r1_msgs);
        }

        // Round 2
        let mut all_r2_msgs: Vec<Vec<(PartyId, MtaRound2Msg<C>)>> = Vec::with_capacity(n);
        for i in 0..n {
            let mut msgs_for_i: Vec<MtaRound1Msg> = Vec::new();
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
            let r2_msgs = states[i]
                .handle_round1(&msgs_for_i, rng)
                .expect("MtA Round-1 should succeed");
            all_r2_msgs.push(r2_msgs);
        }

        // Finish
        let mut c_shares = Vec::with_capacity(n);
        for i in 0..n {
            let mut msgs_for_i: Vec<MtaRound2Msg<C>> = Vec::new();
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
                .expect("MtA finish should succeed");
            c_shares.push(c_i);
        }

        c_shares
    }

    /// Run the full mult sub-protocol (6 rounds, with checkDH):
    /// init -> input(a) -> input(b) -> Paillier MtA -> mult, verify sum(c_i) == a*b.
    #[cfg(feature = "secp256k1")]
    fn run_mult(n: usize) {
        let mut rng = rand::thread_rng();
        let (parties, init_outputs) = run_init(n, &mut rng);

        let elgamal_pk = init_outputs[0].elgamal_pk;
        let pk_shares = &init_outputs[0].elgamal_pk_shares;

        // Generate random additive shares for a and b
        let a_shares: Vec<<C as elliptic_curve::CurveArithmetic>::Scalar> =
            (0..n).map(|_| C::random_scalar(&mut rng)).collect();
        let b_shares: Vec<<C as elliptic_curve::CurveArithmetic>::Scalar> =
            (0..n).map(|_| C::random_scalar(&mut rng)).collect();

        // Run input for a
        let input_a_outputs = run_input(&parties, elgamal_pk, &a_shares, &mut rng);

        // Run input for b
        let input_b_outputs = run_input(&parties, elgamal_pk, &b_shares, &mut rng);

        // Run Paillier MtA
        let mta_c_shares = run_paillier_mta(&parties, &a_shares, &b_shares, &mut rng);

        // --- Mult Round 1: each party creates state + sends (E_i, F_i) ---
        let mut mult_states: Vec<MultState<C>> = Vec::with_capacity(n);
        let mut r1_msgs: Vec<MultRound1Msg<C>> = Vec::with_capacity(n);
        for i in 0..n {
            let (state, msg) = MultState::<C>::new(
                parties[i],
                parties.clone(),
                &input_a_outputs[i],
                &input_b_outputs[i],
                mta_c_shares[i],
                elgamal_pk,
                init_outputs[i].d_i,
                pk_shares.clone(),
                &mut rng,
            );
            mult_states.push(state);
            r1_msgs.push(msg);
        }

        // --- Mult Round 2: verify R_prod, send (A_i, B_i) + R_EG ---
        let mut r2_msgs: Vec<MultRound2Msg<C>> = Vec::with_capacity(n);
        let mut r1_results: Vec<MultRound1Result<C>> = Vec::with_capacity(n);
        for i in 0..n {
            let others: Vec<_> = r1_msgs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, m)| m.clone())
                .collect();
            let (r2, r1_res) = mult_states[i]
                .handle_round1(&others, &r1_msgs[i], &mut rng)
                .expect("mult Round-1 should succeed");
            r2_msgs.push(r2);
            r1_results.push(r1_res);
        }

        // Verify all parties agree on (E, F) aggregate
        for i in 1..n {
            assert_eq!(
                r1_results[0].e_agg, r1_results[i].e_agg,
                "all parties must agree on E aggregate"
            );
            assert_eq!(
                r1_results[0].f_agg, r1_results[i].f_agg,
                "all parties must agree on F aggregate"
            );
        }

        // --- Mult Round 3: verify R_EG, compute (cal_A, cal_B), checkDH Round 1 ---
        let mut r3_msgs: Vec<MultRound3Msg<C>> = Vec::with_capacity(n);
        let mut r2_results: Vec<MultRound2Result<C>> = Vec::with_capacity(n);
        for i in 0..n {
            let others: Vec<_> = r2_msgs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, m)| m.clone())
                .collect();
            let (r3, r2_res) = mult_states[i]
                .handle_round2(&others, &r1_results[i], &mut rng)
                .expect("mult Round-2 should succeed");
            r3_msgs.push(r3);
            r2_results.push(r2_res);
        }

        // --- Mult Round 4: checkDH Round 2 (partial decryption W_i) ---
        let mut r4_msgs: Vec<MultRound4Msg<C>> = Vec::with_capacity(n);
        let mut r3_results: Vec<MultRound3Result<C>> = Vec::with_capacity(n);
        for i in 0..n {
            let others: Vec<_> = r3_msgs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, m)| m.clone())
                .collect();
            let (r4, r3_res) = mult_states[i]
                .handle_round3(&others, &r3_msgs[i], &r2_results[i], &mut rng)
                .expect("mult Round-3 should succeed");
            r4_msgs.push(r4);
            r3_results.push(r3_res);
        }

        // --- Mult Round 5: checkDH verify, send c_i + R_DH ---
        let mut r5_msgs: Vec<MultRound5Msg<C>> = Vec::with_capacity(n);
        let mut r4_results: Vec<MultRound4Result<C>> = Vec::with_capacity(n);
        for i in 0..n {
            let others: Vec<_> = r4_msgs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, m)| m.clone())
                .collect();
            let (r5, r4_res) = mult_states[i]
                .handle_round4(&others, &r2_results[i], &r3_results[i], &mut rng)
                .expect("mult Round-4 should succeed");
            r5_msgs.push(r5);
            r4_results.push(r4_res);
        }

        // --- Mult Round 6: verify R_DH, output c ---
        let mut mult_outputs: Vec<MultOutput<C>> = Vec::with_capacity(n);
        for i in 0..n {
            let others: Vec<_> = r5_msgs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, m)| m.clone())
                .collect();
            let output = mult_states[i]
                .finish_round5(&others, &r4_results[i])
                .expect("mult Round-5 should succeed");
            mult_outputs.push(output);
        }

        // --- Verify correctness ---

        // 1. All parties should agree on the product c
        let c0 = mult_outputs[0].c;
        for output in &mult_outputs[1..] {
            assert_eq!(output.c, c0, "all parties must agree on the product c");
        }

        // 2. c should equal sum(a_i) * sum(b_i)
        let sum_a: <C as elliptic_curve::CurveArithmetic>::Scalar =
            a_shares.iter().copied().reduce(|acc, x| acc + x).unwrap();
        let sum_b: <C as elliptic_curve::CurveArithmetic>::Scalar =
            b_shares.iter().copied().reduce(|acc, x| acc + x).unwrap();
        let expected = sum_a * sum_b;

        assert_eq!(c0, expected, "product c must equal sum(a_i) * sum(b_i)");

        // 3. Each party's c_i share should be preserved
        for (i, output) in mult_outputs.iter().enumerate() {
            assert_eq!(
                output.c_i, mta_c_shares[i],
                "party {}'s c_i share must be preserved",
                i
            );
        }

        // 4. Verify that sum(c_i) == c (consistency with the MtA output)
        let sum_ci: <C as elliptic_curve::CurveArithmetic>::Scalar = mult_outputs
            .iter()
            .map(|o| o.c_i)
            .reduce(|acc, x| acc + x)
            .unwrap();
        assert_eq!(sum_ci, c0, "sum of c_i shares must equal the product c");
    }

    #[test]
    #[cfg(feature = "secp256k1")]
    fn mult_2of2() {
        run_mult(2);
    }

    #[test]
    #[cfg(feature = "secp256k1")]
    fn mult_3of3() {
        run_mult(3);
    }
}
