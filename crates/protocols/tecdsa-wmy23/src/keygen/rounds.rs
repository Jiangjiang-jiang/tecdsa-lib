// SPDX-License-Identifier: GPL-3.0-or-later
//! WMY23 keygen round functions (simplified 2-round protocol).
//!
//! Instead of the full 4-round DRG-based TKeygen from the paper,
//! this implements a simplified 2-round keygen:
//!
//! - **Round 1:** Each party generates a CL keypair and an ECDSA key share,
//!   then broadcasts a hash commitment to `(X_i, CL_pk_i)`.
//! - **Round 2:** Each party decommits, revealing `X_i` and `CL_pk_i`.
//!   After verification, the joint public key is computed as `X = sum(X_i)`.
//!
//! This skips the full DRG/Feldman-VSS distribution and instead uses
//! additive key shares, which is correct for the (n, n) threshold case
//! used in the SoK comparison.
//!
//! # v0.2.1 refactor
//!
//! With bicycl-rs v0.2.1, `ClSecretKey` and `ClPublicKey` are `Send`.
//! The key share now stores CL types directly instead of serialised
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
    /// Threshold.
    pub threshold: u16,
    /// Secret ECDSA key share x_i.
    pub x_i: k256::Scalar,
    /// Public share X_i = x_i * G.
    pub big_x_i: k256::ProjectivePoint,
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
    /// Hash commitment H(nonce || X_i_bytes || pk_a || pk_b || pk_c).
    pub commitment: [u8; 32],
}

/// Data broadcast in Round 2 (decommitment).
#[derive(Clone, Debug)]
pub struct KeygenR2Bcast {
    /// Commitment nonce.
    pub nonce: [u8; 32],
    /// Public share X_i (compressed point bytes via GroupEncoding).
    pub big_x_i_bytes: Vec<u8>,
    /// CL public key QFI coefficients (a, b, c) as decimal strings.
    pub cl_pk_abc: (String, String, String),
}

/// Build the commitment message for hashing.
fn commitment_message(big_x_i_bytes: &[u8], cl_pk_abc: &(String, String, String)) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(big_x_i_bytes);
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

/// Round 1: Each party generates keys and broadcasts a commitment.
///
/// # Arguments
///
/// * `setup` - CL-HSM setup context.
/// * `cl_setup_seed` - The seed used to create this `ClSetup`.  Stored in the
///   resulting key share so that a fresh `ClSetup` can be recreated per session.
/// * `index` - This party's 0-based index.
/// * `n` - Total number of parties.
/// * `threshold` - Reconstruction threshold.
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
    // Generate CL keypair
    let (cl_sk, cl_pk) = setup.keygen()?;

    // Serialize CL public key for broadcast messages
    let pk_qfi = cl_pk.elt();
    let cl_pk_abc = (
        pk_qfi.a().to_string(),
        pk_qfi.b().to_string(),
        pk_qfi.c().to_string(),
    );

    // Generate ECDSA key share
    let x_i = k256::Secp256k1::random_scalar(rng);
    let big_x_i = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * x_i;
    let big_x_i_bytes = big_x_i.to_bytes().to_vec();

    // Compute commitment: H(nonce || X_i || pk_abc)
    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);
    let msg = commitment_message(&big_x_i_bytes, &cl_pk_abc);
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
        big_x_i,
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

/// Round 2: Decommit and compute the joint public key.
///
/// After calling this, each party verifies all decommitments, then
/// computes the joint public key.
///
/// # Arguments
///
/// * `state` - This party's Round 1 state.
///
/// # Returns
///
/// The decommitment broadcast message for this party.
pub fn keygen_round2_bcast(state: &KeygenR1State) -> KeygenR2Bcast {
    let big_x_i_bytes = state.big_x_i.to_bytes().to_vec();
    KeygenR2Bcast {
        nonce: state.nonce,
        big_x_i_bytes,
        cl_pk_abc: state.cl_pk_abc.clone(),
    }
}

/// Finalize keygen: verify all decommitments and compute the key share.
///
/// # Arguments
///
/// * `state` - This party's Round 1 state (consumed).
/// * `r1_bcasts` - All parties' Round 1 broadcasts (indexed 0..n-1).
/// * `r2_bcasts` - All parties' Round 2 broadcasts (indexed 0..n-1).
/// * `setup` - CL-HSM setup context, needed to reconstruct CL public keys.
///
/// # Errors
///
/// Returns an error if any commitment verification fails, point
/// deserialization fails, or the CL secret key was already taken.
pub fn keygen_finalize(
    mut state: KeygenR1State,
    r1_bcasts: &[KeygenR1Bcast],
    r2_bcasts: &[KeygenR2Bcast],
    setup: &ClSetup,
) -> Result<Wmy23KeyShare, Box<dyn std::error::Error>> {
    let n = state.n as usize;
    assert_eq!(r1_bcasts.len(), n);
    assert_eq!(r2_bcasts.len(), n);

    // Verify all commitments
    for j in 0..n {
        let msg = commitment_message(&r2_bcasts[j].big_x_i_bytes, &r2_bcasts[j].cl_pk_abc);
        let expected: [u8; 32] = Sha256::new()
            .chain_update(r2_bcasts[j].nonce)
            .chain_update(&msg)
            .finalize()
            .into();
        if bool::from(!expected.ct_eq(&r1_bcasts[j].commitment)) {
            return Err(format!("commitment verification failed for party {j}").into());
        }
    }

    // Deserialize all public shares using GroupEncoding
    let mut public_shares = Vec::with_capacity(n);
    for j in 0..n {
        let repr = k256::CompressedPoint::try_from(r2_bcasts[j].big_x_i_bytes.as_slice())
            .map_err(|e| format!("invalid point bytes for party {j}: {e}"))?;
        let point: k256::ProjectivePoint =
            Option::from(k256::ProjectivePoint::from_bytes(&repr))
                .ok_or_else(|| format!("invalid EC point for party {j}"))?;
        public_shares.push(point);
    }

    // Compute joint public key X = sum(X_i)
    let public_key = public_shares.iter().fold(
        <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::IDENTITY,
        |acc, x| acc + x,
    );

    // Reconstruct all parties' CL public keys directly
    let cl_pks: Vec<ClPublicKey> = r2_bcasts
        .iter()
        .map(|r| reconstruct_cl_pk(setup, &r.cl_pk_abc))
        .collect::<Result<Vec<_>, _>>()?;

    // Take CL secret key from state
    let cl_sk = state
        .cl_sk
        .take()
        .ok_or("CL secret key already taken from keygen state")?;

    let index = state.index;
    let threshold = state.threshold;
    let total = state.n;
    let x_i = state.x_i;
    let use_128bit_security = state.use_128bit_security;
    let cl_setup_seed = std::mem::take(&mut state.cl_setup_seed);

    Ok(Wmy23KeyShare {
        party_index: (index + 1) as u16, // 1-based
        secret_share: x_i,
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
