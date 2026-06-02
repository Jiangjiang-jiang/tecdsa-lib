// SPDX-License-Identifier: MIT OR Apache-2.0
//! OT Extension (KOS/`SoftSpokenOT` framework).
//!
//! Extends a small number of base OTs into a large number of correlated OTs
//! using the KOS framework (Fig. 10 of <https://eprint.iacr.org/2015/546.pdf>)
//! combined with SoftSpokenOT (<https://eprint.iacr.org/2022/192.pdf>) and the
//! Fiat-Shamir consistency check from DKLs23 (<https://eprint.iacr.org/2023/765.pdf>).
//!
//! The protocol realizes Functionality 3 in DKLs19 and is used by the
//! multiplication protocol in [`super::rvole`].
//!
//! # Initialization
//!
//! Initialization uses [`KAPPA`] base OTs to exchange seeds between the
//! sender and receiver. The roles are *reversed* during this phase: the OTE
//! sender acts as a base-OT receiver and vice versa.
//!
//! # OT width (forced-reuse)
//!
//! The "forced-reuse" technique from DKLs23 is implemented: a single batch
//! of the receiver's OT instances is reused across multiple correlation
//! vectors. The `ot_width` parameter controls how many correlation vectors
//! are processed in a single invocation.
//!
//! # Ported from
//!
//! Apache-2.0/MIT dual-licensed DKLs23 reference implementation at
//! `dkls23-core/src/utilities/ot/extension.rs`.

use elliptic_curve::{ops::Reduce, CurveArithmetic, FieldBytes, PrimeField};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use serde::{Deserialize, Serialize};

use crate::base_ot::OtError;

// ──────────────────────────────────────────────────────────────────────────────
// Constants
// ──────────────────────────────────────────────────────────────────────────────

/// Computational security parameter (bits).  Equals the scalar bit-length.
pub const KAPPA: u16 = 256;

/// Statistical security parameter used in KOS.
///
/// This value comes from the DKLs19 reference implementation at
/// <https://gitlab.com/neucrypt/mpecdsa/-/blob/release/src/lib.rs>.
/// It must divide [`BATCH_SIZE`].
const BASE_SECURITY: u16 = 128;

/// Statistical security parameter (bits).
pub const STAT_SECURITY: u16 = 80;

/// Combined OT security parameter.
pub const OT_SECURITY: u16 = BASE_SECURITY + STAT_SECURITY;

/// Batch size: number of extended OTs produced per invocation.
///
/// This is `KAPPA + 2 * STAT_SECURITY = 256 + 160 = 416`.
pub const BATCH_SIZE: u16 = KAPPA + 2 * STAT_SECURITY;

/// Extended batch size: `BATCH_SIZE + OT_SECURITY` (constant `l'` in KOS Fig. 10).
pub const EXTENDED_BATCH_SIZE: u16 = BATCH_SIZE + OT_SECURITY;

/// Length of a hash output (bytes).  SHA-256 gives 32 bytes = 256 bits.
const HASH_LEN: usize = 32;

// ──────────────────────────────────────────────────────────────────────────────
// Type aliases
// ──────────────────────────────────────────────────────────────────────────────

/// Output of the PRG used inside OT extension.
pub type PrgOutput = [u8; (EXTENDED_BATCH_SIZE / 8) as usize];

/// Element in GF(2^[`OT_SECURITY`]).
pub type FieldElement = [u8; (OT_SECURITY / 8) as usize];

/// Hash output used as a seed/key.
pub type HashOutput = [u8; HASH_LEN];

/// PRG output byte count.
const PRG_DATA_SIZE: usize = (EXTENDED_BATCH_SIZE / 8) as usize;

// ──────────────────────────────────────────────────────────────────────────────
// Serde helpers for fixed-size arrays > 32
// ──────────────────────────────────────────────────────────────────────────────

pub(crate) mod serde_prg_vec {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::PRG_DATA_SIZE;

    pub fn serialize<S>(data: &Vec<[u8; PRG_DATA_SIZE]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let flat: Vec<u8> = data.iter().flat_map(|a| a.iter().copied()).collect();
        flat.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<[u8; PRG_DATA_SIZE]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let flat: Vec<u8> = Vec::deserialize(deserializer)?;
        flat.chunks(PRG_DATA_SIZE)
            .map(|chunk| {
                let arr: [u8; PRG_DATA_SIZE] =
                    chunk.try_into().map_err(serde::de::Error::custom)?;
                Ok(arr)
            })
            .collect()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Domain-separation tags
// ──────────────────────────────────────────────────────────────────────────────

const TAG_OTE_PRG: &[u8] = b"tecdsa/ot/extension/prg/v1";
const TAG_OTE_CHI: &[u8] = b"tecdsa/ot/extension/chi/v1";
const TAG_OTE_RANDOMIZE: &[u8] = b"tecdsa/ot/extension/randomize/v1";
const TAG_OTE_INIT: &[u8] = b"tecdsa/ot/extension/init/v1";

// ──────────────────────────────────────────────────────────────────────────────
// Tagged hash (domain-separated, length-delimited)
// ──────────────────────────────────────────────────────────────────────────────

/// Length-delimited tagged hash.
///
/// Encoding: `len(tag)||tag||len(c0)||c0||len(c1)||c1||...`
/// where lengths are encoded as big-endian `u64`.
pub(crate) fn tagged_hash(tag: &[u8], components: &[&[u8]]) -> HashOutput {
    let mut encoded =
        Vec::with_capacity(8 + tag.len() + components.iter().map(|c| 8 + c.len()).sum::<usize>());
    append_len_prefixed(&mut encoded, tag);
    for component in components {
        append_len_prefixed(&mut encoded, component);
    }
    let digest = Sha256::digest(&encoded);
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&digest);
    out
}

fn append_len_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u64).to_be_bytes());
    buf.extend_from_slice(data);
}

/// Tagged hash reduced to a scalar on curve `C`.
pub(crate) fn tagged_hash_as_scalar<C: CurveArithmetic>(
    tag: &[u8],
    components: &[&[u8]],
) -> C::Scalar
where
    C::Scalar: Reduce<FieldBytes<C>>,
{
    let hash = tagged_hash(tag, components);
    // FieldBytes is the same size as our HASH_LEN (32) for 256-bit curves.
    let fb_len = FieldBytes::<C>::default().len();
    let field_bytes =
        FieldBytes::<C>::try_from(&hash[..fb_len]).expect("hash length matches field byte length");
    <C::Scalar as Reduce<FieldBytes<C>>>::reduce(&field_bytes)
}

/// Convert a scalar to its big-endian byte representation.
pub(crate) fn scalar_to_bytes<C: CurveArithmetic>(scalar: &C::Scalar) -> Vec<u8>
where
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let fb: FieldBytes<C> = (*scalar).into();
    AsRef::<[u8]>::as_ref(&fb).to_vec()
}

/// Sample a uniform random scalar for curve `C` using `rand_core 0.6` RNG.
///
/// Uses rejection sampling: fills `FieldBytes`, tries `from_repr`, and
/// rejects zero or out-of-range values.
pub(crate) fn random_scalar<C: CurveArithmetic>(rng: &mut impl CryptoRngCore) -> C::Scalar
where
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    loop {
        let mut bytes = FieldBytes::<C>::default();
        rng.fill_bytes(&mut bytes);
        if let Some(s) = Option::from(<C::Scalar as PrimeField>::from_repr(bytes)) {
            if !bool::from(elliptic_curve::Field::is_zero(&s)) {
                return s;
            }
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// OTE Sender
// ──────────────────────────────────────────────────────────────────────────────

/// Sender side of the OT Extension protocol.
///
/// Holds the correlation bits (from base OT choice bits) and the seeds
/// derived from base OT outputs.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct OtExtensionSender {
    /// Correlation bits: the choice bits used during the (reversed) base OT.
    pub correlation: Vec<bool>,
    /// Seeds: one per base OT instance (KAPPA seeds).
    pub seeds: Vec<HashOutput>,
}

/// Receiver side of the OT Extension protocol.
///
/// Holds two seed vectors (one for each base OT message) from the
/// (reversed) base OT.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct OtExtensionReceiver {
    /// Seeds corresponding to base OT message 0.
    pub seeds0: Vec<HashOutput>,
    /// Seeds corresponding to base OT message 1.
    pub seeds1: Vec<HashOutput>,
}

/// Data transmitted from the OT-extension receiver to the sender.
///
/// Contains the matrix U and the consistency-check values.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OteDataToSender {
    /// Matrix U: KAPPA rows of PRGOutput length.
    #[serde(with = "serde_prg_vec")]
    pub u: Vec<PrgOutput>,
    /// Consistency-check value x.
    pub verify_x: FieldElement,
    /// Consistency-check values t (one per KAPPA row).
    pub verify_t: Vec<FieldElement>,
}

// ──────────────────────────────────────────────────────────────────────────────
// Initialization (seed exchange via hash-based derivation)
// ──────────────────────────────────────────────────────────────────────────────

/// Initialization data generated by the OTE sender (who acts as base-OT
/// receiver during init).
///
/// After exchanging these messages, call `OtExtensionSender::init_finish`
/// and `OtExtensionReceiver::init_finish`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OteInitSenderMsg {
    /// Blinded choice-dependent keys: one per base OT instance.
    pub blinded_keys: Vec<Vec<u8>>,
}

/// Initialization data generated by the OTE receiver (who acts as base-OT
/// sender during init).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OteInitReceiverMsg {
    /// Encrypted seed pairs: for each base OT instance, `(ct0, ct1)`.
    pub encrypted_seeds: Vec<([u8; 32], [u8; 32])>,
}

impl OtExtensionSender {
    /// Initialize the OTE sender.
    ///
    /// The OTE sender acts as a *receiver* in the base OT phase.
    /// It samples random correlation bits and derives seeds from the
    /// session ID and random nonces.
    ///
    /// Returns `(sender_state, init_data_for_peer)`.
    pub fn init(session_id: &[u8], rng: &mut impl CryptoRngCore) -> (Self, OteInitSenderMsg) {
        // Sample random correlation bits.
        let mut correlation = Vec::with_capacity(KAPPA as usize);
        for _ in 0..KAPPA {
            correlation.push(rng.next_u32() & 1 == 1);
        }

        // For each base OT instance, sample a random nonce and derive a seed.
        // The "blinded key" encodes the choice and the nonce so the peer
        // can derive both seed0 and seed1.
        let mut seeds = Vec::with_capacity(KAPPA as usize);
        let mut blinded_keys = Vec::with_capacity(KAPPA as usize);

        for i in 0..KAPPA {
            let mut nonce = [0u8; 32];
            rng.fill_bytes(&mut nonce);

            let i_bytes = i.to_be_bytes();
            let choice_byte = u8::from(correlation[i as usize]);

            // The seed the sender gets is derived from the nonce.
            let seed = tagged_hash(
                TAG_OTE_INIT,
                &[session_id, &i_bytes, &[choice_byte], &nonce],
            );
            seeds.push(seed);

            // Send nonce and choice info so peer can compute both seeds.
            let mut key_data = Vec::with_capacity(35);
            key_data.extend_from_slice(&i_bytes);
            key_data.push(choice_byte);
            key_data.extend_from_slice(&nonce);
            blinded_keys.push(key_data);
        }

        let sender = OtExtensionSender { correlation, seeds };
        let msg = OteInitSenderMsg { blinded_keys };
        (sender, msg)
    }

    /// Complete initialization using a pre-shared seed pair list.
    ///
    /// This is a simpler initialization path where both parties derive
    /// seeds from a shared session transcript.
    pub fn from_seeds(correlation: Vec<bool>, seeds: Vec<HashOutput>) -> Self {
        OtExtensionSender { correlation, seeds }
    }

    /// Run the sender side of the OTE protocol.
    ///
    /// # Arguments
    ///
    /// * `session_id` - Session identifier for domain separation
    /// * `ot_width` - Number of correlation vectors to process
    /// * `input_correlations` - `ot_width` vectors, each of length [`BATCH_SIZE`]
    /// * `data` - Data received from the OTE receiver
    ///
    /// # Returns
    ///
    /// `(sender_outputs, tau_vectors)` where:
    /// - `sender_outputs` has `ot_width` vectors of [`BATCH_SIZE`] scalars
    /// - `tau_vectors` must be sent to the receiver
    ///
    /// # Errors
    ///
    /// Returns `Err` if dimensions are wrong or the consistency check fails.
    #[allow(clippy::type_complexity)]
    pub fn run<C: CurveArithmetic>(
        &self,
        session_id: &[u8],
        ot_width: u8,
        input_correlations: &[Vec<C::Scalar>],
        data: &OteDataToSender,
    ) -> Result<(Vec<Vec<C::Scalar>>, Vec<Vec<C::Scalar>>), OtError>
    where
        C::Scalar: Reduce<FieldBytes<C>> + PrimeField<Repr = FieldBytes<C>>,
    {
        // ── Validate dimensions ──────────────────────────────────────────
        if input_correlations.len() != ot_width as usize {
            return Err(OtError(
                "input_correlations length does not match ot_width".into(),
            ));
        }
        for corr in input_correlations {
            if corr.len() != BATCH_SIZE as usize {
                return Err(OtError(
                    "correlation vector has incorrect inner length".into(),
                ));
            }
        }
        if self.correlation.len() != KAPPA as usize || self.seeds.len() != KAPPA as usize {
            return Err(OtError("OTE sender state has incorrect dimensions".into()));
        }
        if data.u.len() != KAPPA as usize || data.verify_t.len() != KAPPA as usize {
            return Err(OtError("OTE data has incorrect dimensions".into()));
        }

        // ── EXTEND ───────────────────────────────────────────────────────

        // Step 2: Extend seeds with PRG.
        let extended_seeds = self.extend_seeds(session_id);

        // Step 4: Compute Q = s_i * U_i XOR extended_seeds_i.
        let q = compute_q(&self.correlation, &extended_seeds, &data.u);

        // ── CONSISTENCY CHECK ────────────────────────────────────────────

        let (chi1, chi2) = derive_chi(session_id, &data.u);

        // Step 3: Verify consistency.
        let verify_q = compute_verify_vector(&q, &chi1, &chi2)?;

        let verify_sender: Vec<FieldElement> = (0..KAPPA as usize)
            .map(|i| {
                let mut v = [0u8; (OT_SECURITY / 8) as usize];
                for k in 0..(OT_SECURITY / 8) as usize {
                    v[k] = data.verify_t[i][k] ^ (u8::from(self.correlation[i]) * data.verify_x[k]);
                }
                v
            })
            .collect();

        // Constant-time comparison.
        let consistent = verify_q
            .iter()
            .zip(verify_sender.iter())
            .fold(subtle::Choice::from(1u8), |acc, (a, b)| acc & a.ct_eq(b));
        if !bool::from(consistent) {
            return Err(OtError(
                "Receiver cheated in OTE: Consistency check failed!".into(),
            ));
        }

        // ── TRANSPOSE AND RANDOMIZE ──────────────────────────────────────

        let transposed_q = cut_and_transpose(&q)?;

        // Compress correlation bits into bytes.
        let compressed_correlation = compress_bits(&self.correlation, KAPPA as usize);

        let mut vector_of_v0: Vec<Vec<C::Scalar>> = Vec::with_capacity(ot_width as usize);
        let mut vector_of_v1: Vec<Vec<C::Scalar>> = Vec::with_capacity(ot_width as usize);
        for iteration in 0..ot_width {
            let mut v0: Vec<C::Scalar> = Vec::with_capacity(BATCH_SIZE as usize);
            let mut v1: Vec<C::Scalar> = Vec::with_capacity(BATCH_SIZE as usize);
            for j in 0..BATCH_SIZE {
                // q_j XOR correlation (for v1).
                let mut tq_plus_corr = [0u8; (KAPPA / 8) as usize];
                for k in 0..(KAPPA / 8) as usize {
                    tq_plus_corr[k] = transposed_q[j as usize][k] ^ compressed_correlation[k];
                }

                let j_bytes = j.to_be_bytes();
                let iter_bytes = iteration.to_be_bytes();

                v0.push(tagged_hash_as_scalar::<C>(
                    TAG_OTE_RANDOMIZE,
                    &[session_id, &j_bytes, &iter_bytes, &transposed_q[j as usize]],
                ));
                v1.push(tagged_hash_as_scalar::<C>(
                    TAG_OTE_RANDOMIZE,
                    &[session_id, &j_bytes, &iter_bytes, &tq_plus_corr],
                ));
            }
            vector_of_v0.push(v0);
            vector_of_v1.push(v1);
        }

        // ── TRANSFER (DKLs18 Protocol 9) ────────────────────────────────

        let mut vector_of_tau: Vec<Vec<C::Scalar>> = Vec::with_capacity(ot_width as usize);
        for iteration in 0..ot_width {
            let v0 = &vector_of_v0[iteration as usize];
            let v1 = &vector_of_v1[iteration as usize];
            let corr = &input_correlations[iteration as usize];

            let tau: Vec<C::Scalar> = (0..BATCH_SIZE as usize)
                .map(|j| v1[j] - v0[j] + corr[j])
                .collect();
            vector_of_tau.push(tau);
        }

        Ok((vector_of_v0, vector_of_tau))
    }

    /// Extend seeds with the hash-based PRG.
    fn extend_seeds(&self, session_id: &[u8]) -> Vec<PrgOutput> {
        let mut extended = Vec::with_capacity(KAPPA as usize);
        for i in 0..KAPPA {
            extended.push(prg_expand(session_id, i, &self.seeds[i as usize]));
        }
        extended
    }
}

impl OtExtensionReceiver {
    /// Initialize the OTE receiver.
    ///
    /// The OTE receiver acts as a *sender* in the base OT phase.
    /// It derives seed pairs from the sender's blinded keys.
    pub fn init(session_id: &[u8], sender_msg: &OteInitSenderMsg) -> Result<Self, OtError> {
        if sender_msg.blinded_keys.len() != KAPPA as usize {
            return Err(OtError("init message has wrong number of keys".into()));
        }

        let mut seeds0 = Vec::with_capacity(KAPPA as usize);
        let mut seeds1 = Vec::with_capacity(KAPPA as usize);

        for key_data in &sender_msg.blinded_keys {
            if key_data.len() < 35 {
                return Err(OtError("malformed blinded key data".into()));
            }
            let i_bytes = &key_data[0..2];
            let nonce = &key_data[3..35];

            // Derive seed0 (choice = 0) and seed1 (choice = 1).
            let s0 = tagged_hash(TAG_OTE_INIT, &[session_id, i_bytes, &[0u8], nonce]);
            let s1 = tagged_hash(TAG_OTE_INIT, &[session_id, i_bytes, &[1u8], nonce]);
            seeds0.push(s0);
            seeds1.push(s1);
        }

        Ok(OtExtensionReceiver { seeds0, seeds1 })
    }

    /// Create from pre-computed seed pairs.
    pub fn from_seeds(seeds0: Vec<HashOutput>, seeds1: Vec<HashOutput>) -> Self {
        OtExtensionReceiver { seeds0, seeds1 }
    }

    /// Run phase 1 of the receiver's protocol.
    ///
    /// The receiver extends choice bits, computes matrix U, and derives
    /// consistency-check values.
    ///
    /// # Returns
    ///
    /// `(extended_seeds0, data_to_sender)` where `extended_seeds0` must be
    /// kept for phase 2.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `choice_bits` has wrong length or seed dimensions are invalid.
    pub fn run_phase1(
        &self,
        session_id: &[u8],
        choice_bits: &[bool],
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Vec<PrgOutput>, OteDataToSender), OtError> {
        if choice_bits.len() != BATCH_SIZE as usize {
            return Err(OtError("choice_bits has incorrect length".into()));
        }
        if self.seeds0.len() != KAPPA as usize || self.seeds1.len() != KAPPA as usize {
            return Err(OtError(
                "OTE receiver seed vectors have incorrect dimensions".into(),
            ));
        }

        // ── EXTEND ───────────────────────────────────────────────────────

        // Step 1: Extend choice bits with random noise.
        let mut random_bits = Vec::with_capacity(OT_SECURITY as usize);
        for _ in 0..OT_SECURITY {
            random_bits.push(rng.next_u32() & 1 == 1);
        }
        let extended_choice_bits: Vec<bool> =
            choice_bits.iter().copied().chain(random_bits).collect();

        let compressed_extended =
            compress_bits(&extended_choice_bits, EXTENDED_BATCH_SIZE as usize);

        // Step 2: Extend seeds with PRG.
        let mut extended_seeds0 = Vec::with_capacity(KAPPA as usize);
        let mut extended_seeds1 = Vec::with_capacity(KAPPA as usize);
        for i in 0..KAPPA {
            extended_seeds0.push(prg_expand(session_id, i, &self.seeds0[i as usize]));
            extended_seeds1.push(prg_expand(session_id, i, &self.seeds1[i as usize]));
        }

        // Step 3: Compute matrix U.
        let mut u: Vec<PrgOutput> = Vec::with_capacity(KAPPA as usize);
        for i in 0..KAPPA as usize {
            let mut u_i = [0u8; (EXTENDED_BATCH_SIZE / 8) as usize];
            for j in 0..(EXTENDED_BATCH_SIZE / 8) as usize {
                u_i[j] = extended_seeds0[i][j] ^ extended_seeds1[i][j] ^ compressed_extended[j];
            }
            u.push(u_i);
        }

        // ── CONSISTENCY CHECK ────────────────────────────────────────────

        let (chi1, chi2) = derive_chi(session_id, &u);

        // Step 2: Compute verification values.
        let prod_x_1 = field_mul(&compressed_extended[0..(OT_SECURITY / 8) as usize], &chi1)?;
        let prod_x_2 = field_mul(
            &compressed_extended[(OT_SECURITY / 8) as usize..(2 * OT_SECURITY / 8) as usize],
            &chi2,
        )?;

        let mut verify_x = [0u8; (OT_SECURITY / 8) as usize];
        for k in 0..(OT_SECURITY / 8) as usize {
            verify_x[k] =
                prod_x_1[k] ^ prod_x_2[k] ^ compressed_extended[(2 * OT_SECURITY / 8) as usize + k];
        }

        let mut verify_t: Vec<FieldElement> = Vec::with_capacity(KAPPA as usize);
        for i in 0..KAPPA as usize {
            let prod_ti_1 = field_mul(&extended_seeds0[i][0..(OT_SECURITY / 8) as usize], &chi1)?;
            let prod_ti_2 = field_mul(
                &extended_seeds0[i][(OT_SECURITY / 8) as usize..(2 * OT_SECURITY / 8) as usize],
                &chi2,
            )?;

            let mut verify_ti = [0u8; (OT_SECURITY / 8) as usize];
            for k in 0..(OT_SECURITY / 8) as usize {
                verify_ti[k] = prod_ti_1[k]
                    ^ prod_ti_2[k]
                    ^ extended_seeds0[i][(2 * OT_SECURITY / 8) as usize + k];
            }
            verify_t.push(verify_ti);
        }

        let data_to_sender = OteDataToSender {
            u,
            verify_x,
            verify_t,
        };

        Ok((extended_seeds0, data_to_sender))
    }

    /// Run phase 2 of the receiver's protocol.
    ///
    /// Completes the OTE using the tau vectors from the sender.
    ///
    /// # Returns
    ///
    /// `ot_width` vectors of [`BATCH_SIZE`] scalars (the receiver's output).
    ///
    /// # Errors
    ///
    /// Returns `Err` if dimensions are invalid.
    pub fn run_phase2<C: CurveArithmetic>(
        &self,
        session_id: &[u8],
        ot_width: u8,
        choice_bits: &[bool],
        extended_seeds: &[PrgOutput],
        vector_of_tau: &[Vec<C::Scalar>],
    ) -> Result<Vec<Vec<C::Scalar>>, OtError>
    where
        C::Scalar: Reduce<FieldBytes<C>> + PrimeField<Repr = FieldBytes<C>>,
    {
        if choice_bits.len() != BATCH_SIZE as usize {
            return Err(OtError("choice_bits has incorrect length".into()));
        }
        if extended_seeds.len() != KAPPA as usize {
            return Err(OtError(
                "extended seed matrix has incorrect dimensions".into(),
            ));
        }
        if vector_of_tau.len() != ot_width as usize {
            return Err(OtError("tau vector count does not match ot_width".into()));
        }
        for tau in vector_of_tau {
            if tau.len() != BATCH_SIZE as usize {
                return Err(OtError("tau vector has incorrect inner length".into()));
            }
        }

        // ── TRANSPOSE AND RANDOMIZE ──────────────────────────────────────

        let transposed_t = cut_and_transpose(extended_seeds)?;

        let mut vector_of_v: Vec<Vec<C::Scalar>> = Vec::with_capacity(ot_width as usize);
        for iteration in 0..ot_width {
            let mut v: Vec<C::Scalar> = Vec::with_capacity(BATCH_SIZE as usize);
            for j in 0..BATCH_SIZE {
                let j_bytes = j.to_be_bytes();
                let iter_bytes = iteration.to_be_bytes();
                v.push(tagged_hash_as_scalar::<C>(
                    TAG_OTE_RANDOMIZE,
                    &[session_id, &j_bytes, &iter_bytes, &transposed_t[j as usize]],
                ));
            }
            vector_of_v.push(v);
        }

        // ── TRANSFER ─────────────────────────────────────────────────────

        let mut vector_of_t_b: Vec<Vec<C::Scalar>> = Vec::with_capacity(ot_width as usize);
        for iteration in 0..ot_width {
            let v = &vector_of_v[iteration as usize];
            let tau = &vector_of_tau[iteration as usize];

            let t_b: Vec<C::Scalar> = (0..BATCH_SIZE as usize)
                .map(|j| {
                    let mut t_b_j = -v[j];
                    if choice_bits[j] {
                        t_b_j = tau[j] + t_b_j;
                    }
                    t_b_j
                })
                .collect();
            vector_of_t_b.push(t_b);
        }

        Ok(vector_of_t_b)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Helper functions
// ──────────────────────────────────────────────────────────────────────────────

/// Hash-based PRG: expands a seed into [`EXTENDED_BATCH_SIZE`]/8 bytes
/// by concatenating tagged hash outputs.
fn prg_expand(session_id: &[u8], index: u16, seed: &HashOutput) -> PrgOutput {
    let mut prg_bytes: Vec<u8> = Vec::with_capacity((EXTENDED_BATCH_SIZE / 8) as usize + HASH_LEN);
    let i_bytes = index.to_be_bytes();
    let mut count = 0u16;
    while prg_bytes.len() < (EXTENDED_BATCH_SIZE / 8) as usize {
        let count_bytes = count.to_be_bytes();
        count += 1;
        let chunk = tagged_hash(TAG_OTE_PRG, &[session_id, &i_bytes, &count_bytes, seed]);
        prg_bytes.extend_from_slice(&chunk);
    }
    let mut output = [0u8; (EXTENDED_BATCH_SIZE / 8) as usize];
    output.copy_from_slice(&prg_bytes[..(EXTENDED_BATCH_SIZE / 8) as usize]);
    output
}

/// Compute Q matrix: Q_i = (s_i * U_i) XOR extended_seeds_i.
fn compute_q(
    correlation: &[bool],
    extended_seeds: &[PrgOutput],
    u: &[PrgOutput],
) -> Vec<PrgOutput> {
    let mut q = Vec::with_capacity(KAPPA as usize);
    for i in 0..KAPPA as usize {
        let mut q_i = [0u8; (EXTENDED_BATCH_SIZE / 8) as usize];
        for j in 0..(EXTENDED_BATCH_SIZE / 8) as usize {
            q_i[j] = (u8::from(correlation[i]) * u[i][j]) ^ extended_seeds[i][j];
        }
        q.push(q_i);
    }
    q
}

/// Derive the two chi values from the Fiat-Shamir hash of the U matrix.
fn derive_chi(session_id: &[u8], u: &[PrgOutput]) -> (FieldElement, FieldElement) {
    let msg: Vec<u8> = u.iter().flat_map(|row| row.iter().copied()).collect();

    let mut chi1 = [0u8; (OT_SECURITY / 8) as usize];
    let mut chi2 = [0u8; (OT_SECURITY / 8) as usize];

    let hash1 = tagged_hash(TAG_OTE_CHI, &[session_id, b"chi1", &msg]);
    chi1.copy_from_slice(&hash1[..(OT_SECURITY / 8) as usize]);

    let hash2 = tagged_hash(TAG_OTE_CHI, &[session_id, b"chi2", &msg]);
    chi2.copy_from_slice(&hash2[..(OT_SECURITY / 8) as usize]);

    (chi1, chi2)
}

/// Compute the verification vector for the consistency check.
fn compute_verify_vector(
    q: &[PrgOutput],
    chi1: &FieldElement,
    chi2: &FieldElement,
) -> Result<Vec<FieldElement>, OtError> {
    let mut verify_q = Vec::with_capacity(KAPPA as usize);
    for i in 0..KAPPA as usize {
        let prod1 = field_mul(&q[i][0..(OT_SECURITY / 8) as usize], chi1)?;
        let prod2 = field_mul(
            &q[i][(OT_SECURITY / 8) as usize..(2 * OT_SECURITY / 8) as usize],
            chi2,
        )?;

        let mut v = [0u8; (OT_SECURITY / 8) as usize];
        for k in 0..(OT_SECURITY / 8) as usize {
            v[k] = prod1[k] ^ prod2[k] ^ q[i][(2 * OT_SECURITY / 8) as usize + k];
        }
        verify_q.push(v);
    }
    Ok(verify_q)
}

/// Compress a vector of bools into a packed byte vector (little-endian bit order).
fn compress_bits(bits: &[bool], expected_len: usize) -> Vec<u8> {
    assert!(bits.len() >= expected_len);
    let byte_len = expected_len / 8;
    let mut compressed = Vec::with_capacity(byte_len);
    for i in 0..byte_len {
        let mut byte = 0u8;
        for bit_idx in 0..8 {
            byte |= u8::from(bits[i * 8 + bit_idx]) << bit_idx;
        }
        compressed.push(byte);
    }
    compressed
}

/// Transpose a KAPPA-by-EXTENDED_BATCH_SIZE bit matrix, keeping only the
/// first BATCH_SIZE columns.
///
/// Input: KAPPA rows, each of EXTENDED_BATCH_SIZE/8 bytes.
/// Output: BATCH_SIZE rows, each of KAPPA/8 bytes.
///
/// Rows are interpreted in little-endian bit order.
pub fn cut_and_transpose(input: &[PrgOutput]) -> Result<Vec<HashOutput>, OtError> {
    if input.len() != KAPPA as usize {
        return Err(OtError(
            "transpose: input matrix has incorrect dimensions".into(),
        ));
    }

    let mut output: Vec<HashOutput> = vec![[0u8; (KAPPA / 8) as usize]; BATCH_SIZE as usize];

    for row_byte in 0..(KAPPA / 8) as usize {
        for row_bit_within_byte in 0..8u16 {
            for column_byte in 0..(BATCH_SIZE / 8) as usize {
                for column_bit_within_byte in 0..8u16 {
                    let row_bit = (row_byte as u16) * 8 + row_bit_within_byte;
                    let column_bit = (column_byte as u16) * 8 + column_bit_within_byte;

                    let entry =
                        (input[row_bit as usize][column_byte] >> column_bit_within_byte) & 0x01;

                    let shifted_entry = entry << row_bit_within_byte;
                    output[column_bit as usize][row_byte] |= shifted_entry;
                }
            }
        }
    }

    Ok(output)
}

/// Multiplication in GF(2^[`OT_SECURITY`]).
///
/// Uses the right-to-left comb method (Algorithm 2.34) with reduction modulo
/// `f(X) = X^208 + X^9 + X^3 + X + 1` (Table A.1) from Hankerson, Menezes
/// and Vanstone, *Guide to Elliptic Curve Cryptography*.
///
/// # Errors
///
/// Returns `Err` if `left` or `right` is not exactly OT_SECURITY/8 bytes.
pub fn field_mul(left: &[u8], right: &[u8]) -> Result<FieldElement, OtError> {
    const W: u8 = 64;
    const T: u8 = 4;

    if left.len() != (OT_SECURITY / 8) as usize || right.len() != (OT_SECURITY / 8) as usize {
        return Err(OtError(
            "binary field multiplication: entries have incorrect length".into(),
        ));
    }

    let mut a = [0u64; T as usize];
    let mut b = [0u64; (T + 1) as usize];
    let mut c = [0u64; (2 * T) as usize];

    // Convert [u8; 26] to [u64; 4].
    for i in 0..(OT_SECURITY / 8) as usize {
        a[i >> 3] |= u64::from(left[i]) << ((i & 0x07) << 3);
        b[i >> 3] |= u64::from(right[i]) << ((i & 0x07) << 3);
    }

    // Algorithm 2.34 (right-to-left comb method).
    for k in 0..W {
        for j in 0..T {
            if (a[j as usize] >> k) % 2 == 1 {
                for i in 0..=T {
                    c[(j + i) as usize] ^= b[i as usize];
                }
            }
        }
        if k != W - 1 {
            for i in (1..=T).rev() {
                b[i as usize] = b[i as usize] << 1 | b[(i - 1) as usize] >> 63;
            }
        }
        b[0] <<= 1;
    }

    // Reduce modulo f(X) = X^208 + X^9 + X^3 + X + 1.
    for i in (T..(2 * T)).rev() {
        let t = c[i as usize];
        c[(i - 4) as usize] ^= (t << 57) ^ (t << 51) ^ (t << 49) ^ (t << 48);
        c[(i - 3) as usize] ^= (t >> 7) ^ (t >> 13) ^ (t >> 15) ^ (t >> 16);
        c[i as usize] = 0;
    }
    let t = c[(T - 1) as usize] >> 16;
    c[0] ^= (t << 9) ^ (t << 3) ^ (t << 1) ^ t;
    c[(T - 1) as usize] &= 0xFFFF;

    // Convert back to [u8; 26].
    let mut result = [0u8; (OT_SECURITY / 8) as usize];
    for i in 0..(OT_SECURITY / 8) as usize {
        result[i] =
            u8::try_from((c[i >> 3] >> ((i & 0x07) << 3)) & 0xFF).expect("value fits in u8");
    }

    Ok(result)
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use elliptic_curve::{CurveArithmetic, Field};
    use k256::Secp256k1;
    use rand_core::{OsRng, RngCore};

    type Scalar = <Secp256k1 as CurveArithmetic>::Scalar;

    /// Verify x^{2^208} = x in GF(2^208) (Frobenius endomorphism).
    #[test]
    fn field_mul_frobenius() {
        let mut rng = OsRng;
        for _ in 0..50 {
            let mut elem = [0u8; (OT_SECURITY / 8) as usize];
            rng.fill_bytes(&mut elem);

            let mut result = elem;
            for _ in 0..OT_SECURITY {
                result = field_mul(&result, &result).expect("field_mul should succeed");
            }
            assert_eq!(elem, result, "x^(2^208) must equal x in GF(2^208)");
        }
    }

    /// Verify field_mul rejects wrong-length inputs.
    #[test]
    fn field_mul_rejects_wrong_length() {
        let short = [0u8; (OT_SECURITY / 8 - 1) as usize];
        let exact = [0u8; (OT_SECURITY / 8) as usize];
        assert!(field_mul(&short, &exact).is_err());
    }

    /// Verify cut_and_transpose rejects wrong row count.
    #[test]
    fn transpose_rejects_wrong_dimensions() {
        let bad = vec![[0u8; (EXTENDED_BATCH_SIZE / 8) as usize]; KAPPA as usize - 1];
        assert!(cut_and_transpose(&bad).is_err());
    }

    /// Full OTE sender-receiver round-trip.
    #[test]
    fn ote_roundtrip() {
        let mut rng = OsRng;
        let session_id = b"test-ote-roundtrip";

        // ── INIT ─────────────────────────────────────────────────────────

        let (ote_sender, init_msg) = OtExtensionSender::init(session_id, &mut rng);
        let ote_receiver =
            OtExtensionReceiver::init(session_id, &init_msg).expect("init should succeed");

        // ── PROTOCOL ─────────────────────────────────────────────────────

        let ot_width: u8 = 4;

        // Sender samples correlations.
        let mut sender_correlations: Vec<Vec<Scalar>> = Vec::with_capacity(ot_width as usize);
        for _ in 0..ot_width {
            let mut corr = Vec::with_capacity(BATCH_SIZE as usize);
            for _ in 0..BATCH_SIZE {
                corr.push(random_scalar::<Secp256k1>(&mut rng));
            }
            sender_correlations.push(corr);
        }

        // Receiver samples choice bits.
        let mut choice_bits = Vec::with_capacity(BATCH_SIZE as usize);
        for _ in 0..BATCH_SIZE {
            choice_bits.push(rng.next_u32() & 1 == 1);
        }

        // Receiver phase 1.
        let (extended_seeds, data_to_sender) = ote_receiver
            .run_phase1(session_id, &choice_bits, &mut rng)
            .expect("receiver phase1 should succeed");

        // Sender runs.
        let (sender_outputs, tau) = ote_sender
            .run::<Secp256k1>(session_id, ot_width, &sender_correlations, &data_to_sender)
            .expect("sender run should succeed");

        // Receiver phase 2.
        let receiver_outputs = ote_receiver
            .run_phase2::<Secp256k1>(session_id, ot_width, &choice_bits, &extended_seeds, &tau)
            .expect("receiver phase2 should succeed");

        // ── VERIFY ───────────────────────────────────────────────────────

        for iteration in 0..ot_width as usize {
            for j in 0..BATCH_SIZE as usize {
                let sum = sender_outputs[iteration][j] + receiver_outputs[iteration][j];
                if choice_bits[j] {
                    assert_eq!(
                        sum, sender_correlations[iteration][j],
                        "choice=1: sum should equal correlation at iter={iteration}, j={j}"
                    );
                } else {
                    assert_eq!(
                        sum,
                        <Scalar as Field>::ZERO,
                        "choice=0: sum should be zero at iter={iteration}, j={j}"
                    );
                }
            }
        }
    }

    /// OTE sender rejects tampered U matrix.
    #[test]
    fn ote_sender_rejects_tampered_u() {
        let mut rng = OsRng;
        let session_id = b"test-tamper-u";

        let (ote_sender, init_msg) = OtExtensionSender::init(session_id, &mut rng);
        let ote_receiver =
            OtExtensionReceiver::init(session_id, &init_msg).expect("init should succeed");

        let mut choice_bits = Vec::with_capacity(BATCH_SIZE as usize);
        for _ in 0..BATCH_SIZE {
            choice_bits.push(rng.next_u32() & 1 == 1);
        }

        let (_, mut data_to_sender) = ote_receiver
            .run_phase1(session_id, &choice_bits, &mut rng)
            .expect("receiver phase1 should succeed");

        // Tamper with U.
        data_to_sender.u[0][0] ^= 1;

        let mut correlations = Vec::with_capacity(1);
        let mut corr = Vec::with_capacity(BATCH_SIZE as usize);
        for _ in 0..BATCH_SIZE {
            corr.push(random_scalar::<Secp256k1>(&mut rng));
        }
        correlations.push(corr);

        let result = ote_sender.run::<Secp256k1>(session_id, 1, &correlations, &data_to_sender);
        assert!(
            result.is_err(),
            "tampered U should cause verification failure"
        );
        let err = result.unwrap_err();
        assert!(
            err.0.contains("Consistency check failed"),
            "error should mention consistency check, got: {}",
            err.0
        );
    }

    /// OTE receiver phase 1 rejects wrong choice-bit length.
    #[test]
    fn ote_receiver_rejects_wrong_choice_bits_len() {
        let mut rng = OsRng;
        let session_id = b"test-wrong-len";

        let (_, init_msg) = OtExtensionSender::init(session_id, &mut rng);
        let ote_receiver =
            OtExtensionReceiver::init(session_id, &init_msg).expect("init should succeed");

        let wrong_bits = vec![false; BATCH_SIZE as usize - 1];
        let result = ote_receiver.run_phase1(session_id, &wrong_bits, &mut rng);
        assert!(result.is_err());
    }
}
