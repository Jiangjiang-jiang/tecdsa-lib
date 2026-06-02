// SPDX-License-Identifier: GPL-3.0-or-later
#![allow(non_snake_case)]

//! LLZ25 key generation.
//!
//! ## Protocol (LLZ25, Section 4.1)
//!
//! 1. **Trusted dealer**: Shamir secret sharing $x \to \{x_i\}$,
//!    compute $X = x \cdot G$ and $X_i = x_i \cdot G$.
//! 2. Each party $i$: $(pe_{x,i}, st_{x,i}) \gets \text{NIM.Encode\_B}(crs, x_i)$.
//! 3. Prove $\pi_{x,i}$: `NIZKAoK_{CL-DL}` that $pe_{x,i}$ encrypts the
//!    discrete log of $X_i$.
//! 4. Broadcast $(pe_{x,i}, \pi_{x,i})$.
//! 5. Output: $pk = X$, $pk_i = (X_i, pe_{x,i})$, $sk_i = (x_i, st_{x,i})$.
//!
//! ## Implementation
//!
//! This module provides two modes:
//! - `keygen_with_dealer`: single-shot trusted dealer (for testing).
//! - `Llz25KeygenMachine`: interactive 3-round DKG with Feldman VSS.

pub mod machine;
pub mod msg;
pub mod rounds;

pub use machine::Llz25KeygenMachine;
pub use msg::Llz25KeygenMsg;

use elliptic_curve::group::GroupEncoding;
use elliptic_curve::CurveArithmetic;

use crate::error::qfi_to_abc;
use tecdsa_class_group::bicycl_glue::ClSetup;
use tecdsa_class_group::bicycl_glue::{
    BicyclCiphertext as ClHsmqkCiphertext, BicyclPublicKey as ClHsmqkPublicKey,
};
use tecdsa_class_group::nim::{Nim, NimEncodeBOutput};
use tecdsa_class_group::zk::r_cl_dl_ec::RClDlEcProof;
use tecdsa_curve::TecdsaCurve;
use tecdsa_vss::shamir;

use crate::error::Llz25Error;
use crate::key_share::Llz25KeyShare;

/// Output of the keygen NIM encoding step for one party.
///
/// This is broadcast to all parties so they can later use `pe_x_i`
/// in NIM decoding during the sign phase.
pub struct KeygenAuxInfo {
    /// Party 1-based index.
    pub party_index: u16,
    /// NIM `Encode_B` ciphertext of $x_i$ (CL ciphertext).
    pub pe_x: ClHsmqkCiphertext,
    /// ZK proof that `pe_x` encrypts the dlog of $X_i$.
    pub proof: RClDlEcProof,
}

/// Run trusted-dealer keygen + NIM encoding for all parties.
///
/// Returns `(key_shares, aux_infos)` where:
/// - `key_shares[i]` is party `i+1`'s key share.
/// - `aux_infos[i]` contains the broadcast `pe_{x,i}` and proof.
///
/// # Arguments
/// - `n`: total number of parties.
/// - `threshold`: reconstruction threshold (need `threshold+1` to sign).
/// - `setup`: mutable CL setup (used for NIM encoding and ZK proofs).
/// - `pk_crs`: the CRS public key for NIM encoding.
/// - `cl_setup_seed`: seed string for CL setup recreation.
/// - `use_128bit`: whether 128-bit security CL params are used.
pub fn keygen_with_dealer(
    n: u16,
    threshold: u16,
    setup: &mut ClSetup,
    pk_crs: &ClHsmqkPublicKey,
    cl_setup_seed: &str,
    use_128bit: bool,
) -> Result<(Vec<Llz25KeyShare>, Vec<KeygenAuxInfo>), Llz25Error> {
    let mut rng = rand::thread_rng();

    // 1. Trusted dealer: generate random signing key and Shamir shares.
    let x = k256::Secp256k1::random_scalar(&mut rng);
    let shares = shamir::split::<k256::Secp256k1>(&x, threshold + 1, n, &mut rng);
    let public_key = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * x;

    // Compute public verification shares.
    let public_shares: Vec<k256::ProjectivePoint> = shares
        .iter()
        .map(|s| <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * s.value)
        .collect();

    // 2-4. For each party: NIM.Encode_B + ZK proof.
    let mut key_shares = Vec::with_capacity(n as usize);
    let mut aux_infos = Vec::with_capacity(n as usize);
    let mut all_pe_x_components: Vec<(String, String, String, String, String, String)> =
        Vec::with_capacity(n as usize);

    for (i, share) in shares.iter().enumerate() {
        let x_i_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&share.value);

        // NIM.Encode_B(crs, x_i) -- CL encryption of x_i.
        let mut nim = Nim::new(setup);
        let NimEncodeBOutput { pe_b, state: st_b } = nim
            .encode_b(&x_i_bytes, pk_crs)
            .map_err(|e| Llz25Error::ClassGroup(format!("NIM.Encode_B failed: {e}")))?;

        // Serialize pe_x ciphertext components
        let (c1, c2) = setup
            .ct_components(&pe_b)
            .map_err(|e| Llz25Error::ClassGroup(format!("ct_components: {e}")))?;
        let c1_abc = qfi_to_abc(setup.ctx(), &c1)?;
        let c2_abc = qfi_to_abc(setup.ctx(), &c2)?;
        all_pe_x_components.push((
            c1_abc.0.clone(),
            c1_abc.1.clone(),
            c1_abc.2.clone(),
            c2_abc.0.clone(),
            c2_abc.1.clone(),
            c2_abc.2.clone(),
        ));

        // Compute X_i = x_i * G (compressed point for ZK proof).
        let big_x_i_bytes = public_shares[i].to_bytes().to_vec();

        // ZK proof: NIZKAoK_{CL-DL} that pe_b encrypts dlog of X_i.
        let proof = RClDlEcProof::prove(
            setup,
            pk_crs,
            &pe_b,
            &big_x_i_bytes,
            &x_i_bytes,
            &st_b.s_bytes,
        )
        .map_err(|e| Llz25Error::ClassGroup(format!("R_CL_DL_EC prove failed: {e}")))?;

        key_shares.push(Llz25KeyShare {
            party_index: share.index,
            secret_share: share.value,
            public_key,
            public_shares: public_shares.clone(),
            st_x_bytes: st_b.s_bytes,
            pe_x_components: (
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            ),
            all_pe_x_components: Vec::new(),
            cl_setup_seed: cl_setup_seed.to_string(),
            use_128bit_security: use_128bit,
            threshold,
            total: n,
        });

        aux_infos.push(KeygenAuxInfo {
            party_index: share.index,
            pe_x: pe_b,
            proof,
        });
    }

    // Populate pe_x components in key shares
    for (i, ks) in key_shares.iter_mut().enumerate() {
        ks.pe_x_components = all_pe_x_components[i].clone();
        ks.all_pe_x_components = all_pe_x_components.clone();
    }

    // 5. Verify all proofs (simulate broadcast + verification).
    for (i, aux) in aux_infos.iter().enumerate() {
        let big_x_i_bytes = public_shares[i].to_bytes().to_vec();
        let valid = aux
            .proof
            .verify(setup, pk_crs, &aux.pe_x, &big_x_i_bytes)
            .map_err(|e| Llz25Error::ClassGroup(format!("R_CL_DL_EC verify failed: {e}")))?;
        if !valid {
            return Err(Llz25Error::InvalidProof(format!(
                "keygen ZK proof verification failed for party {}",
                aux.party_index
            )));
        }
    }

    Ok((key_shares, aux_infos))
}
