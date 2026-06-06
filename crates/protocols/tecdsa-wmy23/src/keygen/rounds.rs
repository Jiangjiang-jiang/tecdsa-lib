// SPDX-License-Identifier: MIT OR Apache-2.0
//! WMY23 keygen round functions (Feldman-VSS based, t-of-n).
//!
//! A commit/reveal Feldman-VSS distributed key generation:
//!
//! - **Round 1:** Each party generates a CL keypair and a degree-`t`
//!   polynomial `f_i` with `f_i(0) = x_i` (its additive contribution to the
//!   joint key). It broadcasts a hash commitment to its Feldman commitments
//!   `[a_{i,l} · G]` and CL public key.
//! - **Round 2:** Each party decommits (reveals its Feldman commitments and CL
//!   public key) and sends every party `j` its VSS share `s_{i,j} = f_i(j)`
//!   over a private channel.
//! - **Finalize:** After verifying every commitment and VSS share, each party
//!   `j` computes its threshold share `x̂_j = Σ_i f_i(j) = F(j)` (a Shamir
//!   share of the joint secret `x = F(0) = Σ_i x_i`), the joint public key
//!   `X = Σ_i a_{i,0}·G`, and the public verification shares `X_k = F(k)·G`.
//!
//! Unlike the previous additive (n-of-n only) variant, the resulting shares are
//! genuine `(t+1, n)` Shamir shares, so any quorum of `t+1` signers can
//! reconstruct the key via Lagrange interpolation (applied in presigning).
//!
//! # v0.2.1 refactor
//!
//! With bicycl-rs v0.2.1, `ClSecretKey` and `ClPublicKey` are `Send`.
//! The key share stores CL types directly instead of serialised
//! decimal strings.  The CL public keys are still serialised in the
//! broadcast messages (abc decimal form) because messages must be
//! `Serialize + Send` and reconstruction requires a `ClSetup` context.

#![allow(non_snake_case)]

use std::str::FromStr;

use elliptic_curve::{group::GroupEncoding, CurveArithmetic};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tecdsa_class_group::cl::{ClPublicKey, ClSecretKey, ClSetup, Mpz, Qfi};
use tecdsa_curve::TecdsaCurve;

use crate::key_share::Wmy23KeyShare;

/// Per-party state after Round 1.
pub struct KeygenR1State {
    /// This party's index (0-based internally, 1-based in KeyShare).
    pub index: usize,
    /// Total parties.
    pub n: u16,
    /// Reconstruction threshold `t+1` (number of signers required).
    pub threshold: u16,
    /// Secret contribution `x_i = f_i(0)` to the joint key.
    pub x_i: k256::Scalar,
    /// VSS shares `f_i(j)` this party deals, indexed by recipient 0-based
    /// position `j` (so `poly_shares[j]` is the share for party at index `j`,
    /// i.e. evaluated at the point `j + 1`).
    pub poly_shares: Vec<k256::Scalar>,
    /// Feldman commitments `[a_{i,l} · G]` for `l = 0..t` (length = `threshold`).
    pub feldman_commitments: Vec<k256::ProjectivePoint>,
    /// CL secret key (stored directly; `Option` so `keygen_finalize` can
    /// take ownership without conflicting with the `Drop` impl).
    pub cl_sk: Option<ClSecretKey>,
    /// CL public key QFI abc (serialised for broadcast messages).
    pub cl_pk_abc: (String, String, String),
    /// Commitment nonce.
    pub nonce: [u8; 32],
    /// The commitment hash.
    pub commitment: [u8; 32],
    /// CL setup seed (preserved for the key share).
    pub cl_setup_seed: String,
    /// Whether to use 128-bit security CL parameters.
    pub use_128bit_security: bool,
}

impl zeroize::Zeroize for KeygenR1State {
    fn zeroize(&mut self) {
        self.x_i.zeroize();
        for s in &mut self.poly_shares {
            s.zeroize();
        }
        self.nonce.zeroize();
        self.cl_setup_seed.zeroize();
    }
}

impl Drop for KeygenR1State {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.zeroize();
    }
}

/// Data broadcast in Round 1.
#[derive(Clone, Debug)]
pub struct KeygenR1Bcast {
    /// Hash commitment `H(nonce || feldman_commitments || cl_pk_abc)`.
    pub commitment: [u8; 32],
}

/// Data broadcast in Round 2 (decommitment).
#[derive(Clone, Debug)]
pub struct KeygenR2Bcast {
    /// Commitment nonce.
    pub nonce: [u8; 32],
    /// Feldman commitments `[a_{i,l} · G]` as compressed point bytes
    /// (length = `threshold`); `feldman_commitments[0]` is `x_i · G`.
    pub feldman_commitments: Vec<Vec<u8>>,
    /// CL public key QFI coefficients (a, b, c) as decimal strings.
    pub cl_pk_abc: (String, String, String),
}

/// Serialize a projective point to compressed bytes.
fn point_to_bytes(p: &k256::ProjectivePoint) -> Vec<u8> {
    p.to_bytes().to_vec()
}

/// Deserialize a compressed projective point.
fn point_from_bytes(bytes: &[u8], label: &str) -> Result<k256::ProjectivePoint, String> {
    let repr = k256::CompressedPoint::try_from(bytes)
        .map_err(|e| format!("invalid point bytes ({label}): {e}"))?;
    Option::from(k256::ProjectivePoint::from_bytes(&repr))
        .ok_or_else(|| format!("invalid EC point: {label}"))
}

/// Evaluate a Feldman commitment polynomial in the exponent at `x` (1-based):
/// `Σ_l commitments[l] · x^l`.
fn eval_commitments(commitments: &[k256::ProjectivePoint], x: u16) -> k256::ProjectivePoint {
    let x_scalar = k256::Scalar::from(u64::from(x));
    let mut acc = k256::ProjectivePoint::IDENTITY;
    let mut x_pow = k256::Scalar::ONE;
    for com in commitments {
        acc += *com * x_pow;
        x_pow *= x_scalar;
    }
    acc
}

/// Build the commitment message for hashing.
fn commitment_message(
    feldman_commitments: &[Vec<u8>],
    cl_pk_abc: &(String, String, String),
) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&(feldman_commitments.len() as u32).to_le_bytes());
    for c in feldman_commitments {
        msg.extend_from_slice(&(c.len() as u32).to_le_bytes());
        msg.extend_from_slice(c);
    }
    msg.extend_from_slice(cl_pk_abc.0.as_bytes());
    msg.extend_from_slice(cl_pk_abc.1.as_bytes());
    msg.extend_from_slice(cl_pk_abc.2.as_bytes());
    msg
}

/// Reconstruct a `ClPublicKey` from its serialised (a,b,c) decimal form.
fn reconstruct_cl_pk(
    setup: &ClSetup,
    (a, b, c): &(String, String, String),
) -> Result<ClPublicKey, Box<dyn std::error::Error>> {
    let qfi = Qfi::from_abc(Mpz::from_str(a)?, Mpz::from_str(b)?, Mpz::from_str(c)?);
    let pk_raw = ClPublicKey::from_qfi(setup.cl(), qfi)?;
    Ok(pk_raw)
}

/// Round 1: each party generates keys, deals a Feldman VSS of its
/// contribution, and broadcasts a commitment.
///
/// # Arguments
///
/// * `setup` - CL-HSM setup context.
/// * `cl_setup_seed` - The seed used to create this `ClSetup`.  Stored in the
///   resulting key share so that a fresh `ClSetup` can be recreated per session.
/// * `index` - This party's 0-based index.
/// * `n` - Total number of parties.
/// * `threshold` - Reconstruction threshold `t+1` (number of signers needed).
/// * `use_128bit_security` - Whether the CL setup uses 128-bit security
///   parameters.  Stored in the key share so that `create_cl_setup()` can
///   recreate the correct setup later.
/// * `rng` - Cryptographic RNG.
///
/// # Errors
///
/// Returns an error if CL key generation or serialization fails.
pub fn keygen_round1(
    setup: &mut ClSetup,
    cl_setup_seed: &str,
    index: usize,
    n: u16,
    threshold: u16,
    use_128bit_security: bool,
    rng: &mut impl CryptoRngCore,
) -> Result<(KeygenR1State, KeygenR1Bcast), Box<dyn std::error::Error>> {
    if threshold == 0 || threshold > n {
        return Err(format!("invalid reconstruction threshold {threshold} for n={n}").into());
    }

    // Generate CL keypair
    let (cl_sk, cl_pk) = setup.keygen()?;

    // Serialize CL public key for broadcast messages
    let pk_qfi = cl_pk.elt();
    let cl_pk_abc = (
        pk_qfi.a().to_string(),
        pk_qfi.b().to_string(),
        pk_qfi.c().to_string(),
    );

    // Sample this party's contribution x_i and deal a Feldman VSS of it:
    // f_i is a degree-(threshold-1) polynomial with f_i(0) = x_i.
    let x_i = k256::Secp256k1::random_scalar(rng);
    let (shares, feldman_commitments) =
        tecdsa_vss::feldman::split::<k256::Secp256k1>(&x_i, threshold, n, rng);
    // shares[k] = (index = k+1, value = f_i(k+1)); store by 0-based recipient.
    let poly_shares: Vec<k256::Scalar> = shares.iter().map(|s| s.value).collect();

    let fc_bytes: Vec<Vec<u8>> = feldman_commitments.iter().map(point_to_bytes).collect();

    // Compute commitment: H(nonce || feldman_commitments || cl_pk_abc)
    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);
    let msg = commitment_message(&fc_bytes, &cl_pk_abc);
    let commitment: [u8; 32] = Sha256::new()
        .chain_update(nonce)
        .chain_update(&msg)
        .finalize()
        .into();

    // cl_pk is consumed here -- it was only needed for serialisation.
    // It will be reconstructed from the broadcast abc strings during
    // finalize along with all other parties' public keys.
    drop(cl_pk);

    let state = KeygenR1State {
        index,
        n,
        threshold,
        x_i,
        poly_shares,
        feldman_commitments,
        cl_sk: Some(cl_sk),
        cl_pk_abc,
        nonce,
        commitment,
        cl_setup_seed: cl_setup_seed.to_string(),
        use_128bit_security,
    };

    let bcast = KeygenR1Bcast { commitment };

    Ok((state, bcast))
}

/// Round 2 (broadcast part): reveal Feldman commitments + CL public key.
///
/// The private VSS shares are delivered separately via
/// [`keygen_round2_share`].
#[must_use]
pub fn keygen_round2_bcast(state: &KeygenR1State) -> KeygenR2Bcast {
    let feldman_commitments = state
        .feldman_commitments
        .iter()
        .map(point_to_bytes)
        .collect();
    KeygenR2Bcast {
        nonce: state.nonce,
        feldman_commitments,
        cl_pk_abc: state.cl_pk_abc.clone(),
    }
}

/// Round 2 (private part): the VSS share `f_i(recipient+1)` this party sends to
/// the party at 0-based position `recipient`.
#[must_use]
pub fn keygen_round2_share(state: &KeygenR1State, recipient_0based: usize) -> k256::Scalar {
    state.poly_shares[recipient_0based]
}

/// Finalize keygen: verify all decommitments and VSS shares, then compute the
/// threshold key share.
///
/// # Arguments
///
/// * `state` - This party's Round 1 state (consumed).
/// * `r1_bcasts` - All parties' Round 1 broadcasts (indexed 0..n-1).
/// * `r2_bcasts` - All parties' Round 2 broadcasts (indexed 0..n-1).
/// * `received_shares` - The VSS share each party sent to *this* party, indexed
///   0..n-1 by sender (`received_shares[index]` is this party's own
///   `f_index(index+1)`).
/// * `setup` - CL-HSM setup context, needed to reconstruct CL public keys.
///
/// # Errors
///
/// Returns an error if any commitment or VSS-share verification fails, point
/// deserialization fails, or the CL secret key was already taken.
pub fn keygen_finalize(
    mut state: KeygenR1State,
    r1_bcasts: &[KeygenR1Bcast],
    r2_bcasts: &[KeygenR2Bcast],
    received_shares: &[k256::Scalar],
    setup: &ClSetup,
) -> Result<Wmy23KeyShare, Box<dyn std::error::Error>> {
    let n = state.n as usize;
    assert_eq!(r1_bcasts.len(), n);
    assert_eq!(r2_bcasts.len(), n);
    assert_eq!(received_shares.len(), n);

    let my_1based = (state.index + 1) as u16;

    // 1. Verify all commitments match the revealed (Feldman commitments, CL pk).
    for j in 0..n {
        let msg = commitment_message(&r2_bcasts[j].feldman_commitments, &r2_bcasts[j].cl_pk_abc);
        let expected: [u8; 32] = Sha256::new()
            .chain_update(r2_bcasts[j].nonce)
            .chain_update(&msg)
            .finalize()
            .into();
        if bool::from(!expected.ct_eq(&r1_bcasts[j].commitment)) {
            return Err(format!("commitment verification failed for party {j}").into());
        }
    }

    // 2. Deserialize every party's Feldman commitments.
    let mut all_commitments: Vec<Vec<k256::ProjectivePoint>> = Vec::with_capacity(n);
    for j in 0..n {
        if r2_bcasts[j].feldman_commitments.len() != state.threshold as usize {
            return Err(format!(
                "party {j} sent {} Feldman commitments, expected {}",
                r2_bcasts[j].feldman_commitments.len(),
                state.threshold
            )
            .into());
        }
        let coms: Vec<k256::ProjectivePoint> = r2_bcasts[j]
            .feldman_commitments
            .iter()
            .map(|b| point_from_bytes(b, &format!("feldman commitment from party {j}")))
            .collect::<Result<_, _>>()?;
        all_commitments.push(coms);
    }

    // 3. Verify each received VSS share against the sender's Feldman commitments.
    for j in 0..n {
        if !tecdsa_vss::feldman::verify::<k256::Secp256k1>(
            &received_shares[j],
            my_1based,
            &all_commitments[j],
        ) {
            return Err(format!("VSS share from party {j} failed verification").into());
        }
    }

    // 4. Threshold share: x̂_i = Σ_j f_j(i) = F(i)  (a Shamir share of x).
    let secret_share = received_shares
        .iter()
        .fold(k256::Scalar::ZERO, |acc, s| acc + s);

    // 5. Joint public key: X = Σ_j a_{j,0}·G = Σ_j commitments[j][0].
    let public_key = all_commitments.iter().fold(
        <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::IDENTITY,
        |acc, coms| acc + coms[0],
    );

    // 6. Public verification shares: X_k = F(k+1)·G = Σ_j eval(commitments_j, k+1).
    let mut public_shares = Vec::with_capacity(n);
    for k in 0..n {
        let point_x = (k + 1) as u16;
        let x_k = all_commitments
            .iter()
            .fold(k256::ProjectivePoint::IDENTITY, |acc, coms| {
                acc + eval_commitments(coms, point_x)
            });
        public_shares.push(x_k);
    }

    // Reconstruct all parties' CL public keys directly.
    let cl_pks: Vec<ClPublicKey> = r2_bcasts
        .iter()
        .map(|r| reconstruct_cl_pk(setup, &r.cl_pk_abc))
        .collect::<Result<Vec<_>, _>>()?;

    // Take CL secret key from state.
    let cl_sk = state
        .cl_sk
        .take()
        .ok_or("CL secret key already taken from keygen state")?;

    let threshold = state.threshold;
    let total = state.n;
    let use_128bit_security = state.use_128bit_security;
    let cl_setup_seed = std::mem::take(&mut state.cl_setup_seed);

    Ok(Wmy23KeyShare {
        party_index: my_1based,
        secret_share,
        public_key,
        public_shares,
        cl_sk,
        cl_pks,
        cl_setup_seed,
        use_128bit_security,
        threshold,
        total,
    })
}
