// SPDX-License-Identifier: MIT OR Apache-2.0
//! WMY23 keygen round functions (DRG-based, paper-compliant).
//!
//! Implements TKeygen from WMY23 (Wang, Mei, Yu. "Real Threshold ECDSA."
//! NDSS 2023, Figure 3) using the DRG primitive (Figure 2).
//!
//! ## Protocol Rounds
//!
//! 1. **Commit:** CL keygen + R_Key proof + DRG.Gen (Pedersen VSS + CL
//!    encrypt + R_Enc-PC). Broadcast hash commitment.
//! 2. **Decommit:** Reveal all Phase 1+2a data. P2P Pedersen VSS shares.
//!    Receivers verify R_Key, R_Enc-PC, and Pedersen VSS (GenVf).
//! 3. **Combine:** DRG.Comb + RevealExp. Broadcast combined share proof.
//!    Receivers verify CombVf + ExpVf.
//! 4. **Finalize:** Compute public key via Lagrange interpolation on X_j.

#![allow(non_snake_case)]

use std::str::FromStr;

use elliptic_curve::{group::GroupEncoding, ops::Reduce, CurveArithmetic, PrimeField};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tecdsa_class_group::{
    cl::{ClCiphertext, ClPublicKey, ClSecretKey, ClSetup, Mpz, Qfi},
    drg::{drg_comb, drg_gen, drg_gen_verify, DrgGenOutput, PedersenVssShare},
    zk::{r_enc_pc::REncPcProof, r_key::RKeyProof},
};

use crate::key_share::Wmy23KeyShare;

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

fn write_var(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
    buf.extend_from_slice(data);
}

fn read_var<'a>(data: &'a [u8], pos: &mut usize) -> Result<&'a [u8], String> {
    if *pos + 4 > data.len() {
        return Err("truncated at length".into());
    }
    let len = u32::from_le_bytes(data[*pos..*pos + 4].try_into().unwrap()) as usize;
    *pos += 4;
    if *pos + len > data.len() {
        return Err("truncated at data".into());
    }
    let result = &data[*pos..*pos + len];
    *pos += len;
    Ok(result)
}

fn write_string(buf: &mut Vec<u8>, s: &str) {
    write_var(buf, s.as_bytes());
}

fn read_string(data: &[u8], pos: &mut usize) -> Result<String, String> {
    let bytes = read_var(data, pos)?;
    std::str::from_utf8(bytes)
        .map(|s| s.to_string())
        .map_err(|e| format!("invalid UTF-8: {e}"))
}

fn write_qfi(buf: &mut Vec<u8>, q: &Qfi) {
    write_var(buf, &q.to_bytes());
}

fn read_qfi(data: &[u8], pos: &mut usize) -> Result<Qfi, String> {
    let bytes = read_var(data, pos)?;
    Ok(Qfi::from_bytes(bytes))
}

fn point_to_bytes(p: &k256::ProjectivePoint) -> Vec<u8> {
    p.to_bytes().to_vec()
}

fn point_from_bytes(bytes: &[u8], label: &str) -> Result<k256::ProjectivePoint, String> {
    let repr = k256::CompressedPoint::try_from(bytes)
        .map_err(|e| format!("invalid point bytes ({label}): {e}"))?;
    Option::from(k256::ProjectivePoint::from_bytes(&repr))
        .ok_or_else(|| format!("invalid EC point: {label}"))
}

// ---------------------------------------------------------------------------
// Proof serialization
// ---------------------------------------------------------------------------

fn serialize_r_key_proof(p: &RKeyProof) -> Vec<u8> {
    let mut buf = Vec::new();
    write_qfi(&mut buf, &p.t);
    write_var(&mut buf, &p.z);
    write_var(&mut buf, &p.e);
    buf
}

fn deserialize_r_key_proof(data: &[u8]) -> Result<RKeyProof, String> {
    let mut pos = 0;
    let t = read_qfi(data, &mut pos)?;
    let z = read_var(data, &mut pos)?.to_vec();
    let e = read_var(data, &mut pos)?.to_vec();
    Ok(RKeyProof { t, z, e })
}

fn serialize_ciphertext(setup: &ClSetup, ct: &ClCiphertext) -> Result<Vec<u8>, String> {
    let (c1, c2) = setup
        .ct_components(ct)
        .map_err(|e| format!("ct_components: {e}"))?;
    let mut buf = Vec::new();
    write_qfi(&mut buf, &c1);
    write_qfi(&mut buf, &c2);
    Ok(buf)
}

fn deserialize_ciphertext(
    setup: &ClSetup,
    data: &[u8],
    pos: &mut usize,
) -> Result<ClCiphertext, String> {
    let c1 = read_qfi(data, pos)?;
    let c2 = read_qfi(data, pos)?;
    setup
        .ct_from_components(&c1, &c2)
        .map_err(|e| format!("ct_from_components: {e}"))
}

fn serialize_r_enc_pc_proof(p: &REncPcProof) -> Vec<u8> {
    let mut buf = Vec::new();
    write_var(&mut buf, &p.r_pc_bytes);
    write_qfi(&mut buf, &p.r_c0);
    write_qfi(&mut buf, &p.r_c1);
    write_var(&mut buf, &p.z1);
    write_var(&mut buf, &p.z2);
    write_var(&mut buf, &p.z3);
    write_var(&mut buf, &p.e);
    buf
}

fn deserialize_r_enc_pc_proof(data: &[u8]) -> Result<REncPcProof, String> {
    let mut pos = 0;
    Ok(REncPcProof {
        r_pc_bytes: read_var(data, &mut pos)?.to_vec(),
        r_c0: read_qfi(data, &mut pos)?,
        r_c1: read_qfi(data, &mut pos)?,
        z1: read_var(data, &mut pos)?.to_vec(),
        z2: read_var(data, &mut pos)?.to_vec(),
        z3: read_var(data, &mut pos)?.to_vec(),
        e: read_var(data, &mut pos)?.to_vec(),
    })
}

// ---------------------------------------------------------------------------
// R_DL-PC: proves same scalar in both EC DLog and EC Pedersen commitment.
//
// R_DL-PC = {((PC, Q), (m, r)) : Q = G*m  AND  PC = G*m + H*r}
//
// Sigma protocol (Fiat-Shamir):
//   commit:  R_Q = G*a1,  R_PC = G*a1 + H*a2
//   challenge: e = H(PC || Q || R_Q || R_PC)
//   response: z1 = a1 + e*m,  z2 = a2 + e*r
// Verify:   G*z1 == R_Q + Q*e,  G*z1 + H*z2 == R_PC + PC*e
// ---------------------------------------------------------------------------

pub struct RDlPcProof {
    pub r_q_bytes: Vec<u8>,
    pub r_pc_bytes: Vec<u8>,
    pub z1: k256::Scalar,
    pub z2: k256::Scalar,
}

impl RDlPcProof {
    pub fn prove(
        m: &k256::Scalar,
        r: &k256::Scalar,
        q_point: &k256::ProjectivePoint,
        pc: &k256::ProjectivePoint,
        rng: &mut impl CryptoRngCore,
    ) -> Self {
        let g = k256::ProjectivePoint::GENERATOR;
        let h = <k256::Secp256k1 as tecdsa_curve::TecdsaCurve>::nums_pedersen_h();

        use tecdsa_curve::TecdsaCurve;
        let a1 = k256::Secp256k1::random_scalar(rng);
        let a2 = k256::Secp256k1::random_scalar(rng);
        let r_q = g * a1;
        let r_pc = g * a1 + h * a2;

        let r_q_bytes = r_q.to_bytes().to_vec();
        let r_pc_bytes_v = r_pc.to_bytes().to_vec();

        let e = rdlpc_challenge(pc, q_point, &r_q_bytes, &r_pc_bytes_v);
        let z1 = a1 + e * m;
        let z2 = a2 + e * r;

        Self {
            r_q_bytes,
            r_pc_bytes: r_pc_bytes_v,
            z1,
            z2,
        }
    }

    pub fn verify(
        &self,
        q_point: &k256::ProjectivePoint,
        pc: &k256::ProjectivePoint,
    ) -> Result<bool, String> {
        let g = k256::ProjectivePoint::GENERATOR;
        let h = <k256::Secp256k1 as tecdsa_curve::TecdsaCurve>::nums_pedersen_h();

        let r_q = point_from_bytes(&self.r_q_bytes, "R_Q")?;
        let r_pc = point_from_bytes(&self.r_pc_bytes, "R_PC")?;

        let e = rdlpc_challenge(pc, q_point, &self.r_q_bytes, &self.r_pc_bytes);

        // Check 1: G * z1 == R_Q + Q * e
        if g * self.z1 != r_q + *q_point * e {
            return Ok(false);
        }
        // Check 2: G * z1 + H * z2 == R_PC + PC * e
        if g * self.z1 + h * self.z2 != r_pc + *pc * e {
            return Ok(false);
        }
        Ok(true)
    }
}

fn rdlpc_challenge(
    pc: &k256::ProjectivePoint,
    q: &k256::ProjectivePoint,
    r_q_bytes: &[u8],
    r_pc_bytes: &[u8],
) -> k256::Scalar {
    let hash = Sha256::new()
        .chain_update(b"R_DL-PC")
        .chain_update(pc.to_bytes())
        .chain_update(q.to_bytes())
        .chain_update(r_q_bytes)
        .chain_update(r_pc_bytes)
        .finalize();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&hash);
    k256::Scalar::reduce(&k256::U256::from_be_slice(&buf))
}

fn serialize_r_dl_pc_proof(p: &RDlPcProof) -> Vec<u8> {
    let mut buf = Vec::new();
    write_var(&mut buf, &p.r_q_bytes);
    write_var(&mut buf, &p.r_pc_bytes);
    buf.extend_from_slice(&p.z1.to_repr());
    buf.extend_from_slice(&p.z2.to_repr());
    buf
}

fn deserialize_r_dl_pc_proof(data: &[u8]) -> Result<RDlPcProof, String> {
    use elliptic_curve::PrimeField;
    let mut pos = 0;
    let r_q_bytes = read_var(data, &mut pos)?.to_vec();
    let r_pc_bytes = read_var(data, &mut pos)?.to_vec();
    if pos + 64 > data.len() {
        return Err("R_DL-PC proof truncated at z1/z2".into());
    }
    let mut z1_repr = k256::FieldBytes::default();
    z1_repr.copy_from_slice(&data[pos..pos + 32]);
    pos += 32;
    let mut z2_repr = k256::FieldBytes::default();
    z2_repr.copy_from_slice(&data[pos..pos + 32]);
    pos += 32;
    let z1 = k256::Scalar::from_repr(z1_repr)
        .into_option()
        .ok_or("invalid z1 scalar")?;
    let z2 = k256::Scalar::from_repr(z2_repr)
        .into_option()
        .ok_or("invalid z2 scalar")?;
    let _ = pos;
    Ok(RDlPcProof {
        r_q_bytes,
        r_pc_bytes,
        z1,
        z2,
    })
}

// ---------------------------------------------------------------------------
// Round 1: CL keygen + R_Key + DRG.Gen + commit
// ---------------------------------------------------------------------------

/// Per-party state after Round 1.
pub struct KeygenR1State {
    pub index: usize,
    pub n: u16,
    pub threshold: u16,
    pub cl_sk: Option<ClSecretKey>,
    pub cl_pk_abc: (String, String, String),
    pub sk_bytes: Vec<u8>,
    pub drg_gen: DrgGenOutput,
    pub r_key_proof: RKeyProof,
    pub nonce: [u8; 32],
    pub commitment: [u8; 32],
    pub cl_setup_seed: String,
    pub use_128bit_security: bool,
}

impl zeroize::Zeroize for KeygenR1State {
    fn zeroize(&mut self) {
        self.sk_bytes.zeroize();
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

/// Round 1 broadcast (commitment hash).
#[derive(Clone, Debug)]
pub struct KeygenR1Bcast {
    pub commitment: [u8; 32],
}

/// Build the commitment message from all R2 broadcast content.
fn commitment_message(
    pedersen_commitments: &[Vec<u8>],
    cl_pk_abc: &(String, String, String),
    r_key_data: &[u8],
    ct_data: &[u8],
    enc_pc_data: &[u8],
    pc_bytes: &[u8],
) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&(pedersen_commitments.len() as u32).to_le_bytes());
    for c in pedersen_commitments {
        write_var(&mut msg, c);
    }
    write_string(&mut msg, &cl_pk_abc.0);
    write_string(&mut msg, &cl_pk_abc.1);
    write_string(&mut msg, &cl_pk_abc.2);
    write_var(&mut msg, r_key_data);
    write_var(&mut msg, ct_data);
    write_var(&mut msg, enc_pc_data);
    write_var(&mut msg, pc_bytes);
    msg
}

/// Round 1: CL keygen + R_Key proof + DRG.Gen + commitment.
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
        return Err(format!("invalid threshold {threshold} for n={n}").into());
    }

    // Phase 1: CL keygen + R_Key proof
    let (cl_sk, cl_pk) = setup.keygen()?;
    let sk_bytes = setup.sk_to_bytes(&cl_sk)?;
    let r_key_proof = RKeyProof::prove(setup, &cl_pk, &sk_bytes)?;

    let pk_qfi = cl_pk.elt();
    let cl_pk_abc = (
        pk_qfi.a().to_string(),
        pk_qfi.b().to_string(),
        pk_qfi.c().to_string(),
    );

    // Phase 2a: DRG.Gen (Pedersen VSS + CL encrypt + R_Enc-PC)
    let drg_gen = drg_gen(setup, &cl_pk, threshold, n, rng)?;

    // Serialize components for commitment
    let pc_com_bytes: Vec<Vec<u8>> = drg_gen.commitments.iter().map(point_to_bytes).collect();
    let r_key_data = serialize_r_key_proof(&r_key_proof);
    let ct_data = serialize_ciphertext(setup, &drg_gen.ciphertext)?;
    let enc_pc_data = serialize_r_enc_pc_proof(&drg_gen.proof);

    let msg = commitment_message(
        &pc_com_bytes,
        &cl_pk_abc,
        &r_key_data,
        &ct_data,
        &enc_pc_data,
        &drg_gen.pc_bytes,
    );

    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);
    let commitment: [u8; 32] = Sha256::new()
        .chain_update(nonce)
        .chain_update(&msg)
        .finalize()
        .into();

    let state = KeygenR1State {
        index,
        n,
        threshold,
        cl_sk: Some(cl_sk),
        cl_pk_abc,
        sk_bytes,
        drg_gen,
        r_key_proof,
        nonce,
        commitment,
        cl_setup_seed: cl_setup_seed.to_string(),
        use_128bit_security,
    };

    Ok((state, KeygenR1Bcast { commitment }))
}

// ---------------------------------------------------------------------------
// Round 2: decommit + P2P shares
// ---------------------------------------------------------------------------

/// Round 2 broadcast data (decommitment).
#[derive(Clone, Debug)]
pub struct KeygenR2Bcast {
    pub nonce: [u8; 32],
    pub pedersen_commitments: Vec<Vec<u8>>,
    pub cl_pk_abc: (String, String, String),
    pub r_key_data: Vec<u8>,
    pub ct_data: Vec<u8>,
    pub enc_pc_data: Vec<u8>,
    pub pc_bytes: Vec<u8>,
}

/// Create the Round 2 broadcast (decommit).
#[must_use]
pub fn keygen_round2_bcast(state: &KeygenR1State, setup: &ClSetup) -> KeygenR2Bcast {
    let pedersen_commitments = state
        .drg_gen
        .commitments
        .iter()
        .map(point_to_bytes)
        .collect();
    let r_key_data = serialize_r_key_proof(&state.r_key_proof);
    let ct_data = serialize_ciphertext(setup, &state.drg_gen.ciphertext).expect("ct serialization");
    let enc_pc_data = serialize_r_enc_pc_proof(&state.drg_gen.proof);

    KeygenR2Bcast {
        nonce: state.nonce,
        pedersen_commitments,
        cl_pk_abc: state.cl_pk_abc.clone(),
        r_key_data,
        ct_data,
        enc_pc_data,
        pc_bytes: state.drg_gen.pc_bytes.clone(),
    }
}

/// Return the Pedersen VSS share for a specific recipient (0-based index).
#[must_use]
pub fn keygen_round2_share(
    state: &KeygenR1State,
    recipient_0based: usize,
) -> (k256::Scalar, k256::Scalar) {
    let share = &state.drg_gen.vss_shares[recipient_0based];
    (share.value, share.randomness)
}

/// Serialize a [`KeygenR2Bcast`] to bytes.
pub fn serialize_r2(r2: &KeygenR2Bcast) -> Vec<u8> {
    let msg_data = commitment_message(
        &r2.pedersen_commitments,
        &r2.cl_pk_abc,
        &r2.r_key_data,
        &r2.ct_data,
        &r2.enc_pc_data,
        &r2.pc_bytes,
    );
    let mut buf = Vec::new();
    buf.extend_from_slice(&r2.nonce);
    buf.extend_from_slice(&msg_data);
    buf
}

/// Deserialize a [`KeygenR2Bcast`] from bytes.
pub fn deserialize_r2(data: &[u8]) -> Result<KeygenR2Bcast, String> {
    if data.len() < 32 {
        return Err("R2 data too short".into());
    }
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&data[..32]);
    let mut pos = 32;

    let num_coms = {
        if pos + 4 > data.len() {
            return Err("R2 truncated at num_coms".into());
        }
        u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize
    };
    pos += 4;

    let mut pedersen_commitments = Vec::with_capacity(num_coms);
    for _ in 0..num_coms {
        pedersen_commitments.push(read_var(data, &mut pos)?.to_vec());
    }

    let a = read_string(data, &mut pos)?;
    let b = read_string(data, &mut pos)?;
    let c = read_string(data, &mut pos)?;
    let r_key_data = read_var(data, &mut pos)?.to_vec();
    let ct_data = read_var(data, &mut pos)?.to_vec();
    let enc_pc_data = read_var(data, &mut pos)?.to_vec();
    let pc_bytes = read_var(data, &mut pos)?.to_vec();

    if pos != data.len() {
        return Err(format!("R2 has {} trailing bytes", data.len() - pos));
    }

    Ok(KeygenR2Bcast {
        nonce,
        pedersen_commitments,
        cl_pk_abc: (a, b, c),
        r_key_data,
        ct_data,
        enc_pc_data,
        pc_bytes,
    })
}

/// Verified data extracted from an R2 broadcast.
#[derive(Clone)]
pub struct VerifiedR2 {
    pub commitments: Vec<k256::ProjectivePoint>,
    pub cl_pk_abc: (String, String, String),
}

/// Verify an R2 broadcast: commitment, R_Key, R_Enc-PC, Pedersen VSS.
pub fn verify_r2(
    setup: &ClSetup,
    r1_commitment: &[u8; 32],
    r2: &KeygenR2Bcast,
    my_share: &PedersenVssShare,
) -> Result<VerifiedR2, String> {
    // 1. Verify commitment opening
    let msg = commitment_message(
        &r2.pedersen_commitments,
        &r2.cl_pk_abc,
        &r2.r_key_data,
        &r2.ct_data,
        &r2.enc_pc_data,
        &r2.pc_bytes,
    );
    let expected: [u8; 32] = Sha256::new()
        .chain_update(r2.nonce)
        .chain_update(&msg)
        .finalize()
        .into();
    if bool::from(!expected.ct_eq(r1_commitment)) {
        return Err("commitment verification failed".into());
    }

    // 2. Deserialize Pedersen commitments
    let commitments: Vec<k256::ProjectivePoint> = r2
        .pedersen_commitments
        .iter()
        .enumerate()
        .map(|(i, b)| point_from_bytes(b, &format!("commitment[{i}]")))
        .collect::<Result<_, _>>()?;

    // 3. Reconstruct CL public key
    let cl_pk = reconstruct_cl_pk(setup, &r2.cl_pk_abc)?;

    // 4. Verify R_Key proof
    let r_key_proof = deserialize_r_key_proof(&r2.r_key_data)?;
    if !r_key_proof
        .verify(setup, &cl_pk)
        .map_err(|e| format!("R_Key verify error: {e}"))?
    {
        return Err("R_Key proof verification failed".into());
    }

    // 5. Verify R_Enc-PC + Pedersen VSS (GenVf)
    let mut ct_pos = 0;
    let ciphertext = deserialize_ciphertext(setup, &r2.ct_data, &mut ct_pos)?;
    let enc_pc_proof = deserialize_r_enc_pc_proof(&r2.enc_pc_data)?;

    let ok = drg_gen_verify(
        setup,
        &cl_pk,
        &commitments,
        &ciphertext,
        &enc_pc_proof,
        &r2.pc_bytes,
        my_share,
    )
    .map_err(|e| format!("GenVf error: {e}"))?;
    if !ok {
        return Err("GenVf (R_Enc-PC + VSS) verification failed".into());
    }

    Ok(VerifiedR2 {
        commitments,
        cl_pk_abc: r2.cl_pk_abc.clone(),
    })
}

// ---------------------------------------------------------------------------
// Round 3: DRG.Comb + RevealExp
// ---------------------------------------------------------------------------

/// State after Round 3 computation (combine phase).
pub struct KeygenR3State {
    pub combined_share: k256::Scalar,
    pub x_point: k256::ProjectivePoint,
}

/// Round 3 broadcast data (combine + reveal).
#[derive(Clone, Debug)]
pub struct KeygenR3Bcast {
    pub combined_pc_bytes: Vec<u8>,
    pub combined_ct_data: Vec<u8>,
    pub combined_enc_pc_data: Vec<u8>,
    pub x_point_bytes: Vec<u8>,
    pub r_dl_pc_data: Vec<u8>,
}

/// Run DRG.Comb + RevealExp with explicit shares and commitments.
pub fn keygen_round3_with_shares(
    setup: &mut ClSetup,
    cl_pk_abc: &(String, String, String),
    my_index_1based: u16,
    received_shares: &[(u16, PedersenVssShare)],
    all_commitments: &[(u16, Vec<k256::ProjectivePoint>)],
) -> Result<(KeygenR3State, KeygenR3Bcast), Box<dyn std::error::Error>> {
    let cl_pk = reconstruct_cl_pk(setup, cl_pk_abc)?;

    // DRG.Comb: combine shares + CL encrypt + R_Enc-PC proof
    let comb = drg_comb(
        setup,
        &cl_pk,
        my_index_1based,
        received_shares,
        all_commitments,
    )?;

    // RevealExp: X_i = G * x_i, prove R_DL-PC binding X_i to PC_xi
    let g = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR;
    let x_point = g * comb.combined_share;
    let mut rng = rand::thread_rng();
    let r_dl_pc = RDlPcProof::prove(
        &comb.combined_share,
        &comb.combined_randomness,
        &x_point,
        &comb.pedersen_commitment,
        &mut rng,
    );

    // Serialize for broadcast
    let combined_ct_data = serialize_ciphertext(setup, &comb.ciphertext)?;
    let combined_enc_pc_data = serialize_r_enc_pc_proof(&comb.proof);

    let r3_bcast = KeygenR3Bcast {
        combined_pc_bytes: comb.pc_bytes.clone(),
        combined_ct_data,
        combined_enc_pc_data,
        x_point_bytes: point_to_bytes(&x_point),
        r_dl_pc_data: serialize_r_dl_pc_proof(&r_dl_pc),
    };

    let r3_state = KeygenR3State {
        combined_share: comb.combined_share,
        x_point,
    };

    Ok((r3_state, r3_bcast))
}

/// Serialize a [`KeygenR3Bcast`] to bytes.
pub fn serialize_r3(r3: &KeygenR3Bcast) -> Vec<u8> {
    let mut buf = Vec::new();
    write_var(&mut buf, &r3.combined_pc_bytes);
    write_var(&mut buf, &r3.combined_ct_data);
    write_var(&mut buf, &r3.combined_enc_pc_data);
    write_var(&mut buf, &r3.x_point_bytes);
    write_var(&mut buf, &r3.r_dl_pc_data);
    buf
}

/// Deserialize a [`KeygenR3Bcast`] from bytes.
pub fn deserialize_r3(data: &[u8]) -> Result<KeygenR3Bcast, String> {
    let mut pos = 0;
    let result = KeygenR3Bcast {
        combined_pc_bytes: read_var(data, &mut pos)?.to_vec(),
        combined_ct_data: read_var(data, &mut pos)?.to_vec(),
        combined_enc_pc_data: read_var(data, &mut pos)?.to_vec(),
        x_point_bytes: read_var(data, &mut pos)?.to_vec(),
        r_dl_pc_data: read_var(data, &mut pos)?.to_vec(),
    };
    if pos != data.len() {
        return Err(format!("R3 has {} trailing bytes", data.len() - pos));
    }
    Ok(result)
}

/// Verify an R3 broadcast: CombVf + ExpVf.
pub fn verify_r3(
    setup: &ClSetup,
    sender_cl_pk_abc: &(String, String, String),
    sender_index_1based: u16,
    all_commitments: &[(u16, Vec<k256::ProjectivePoint>)],
    r3: &KeygenR3Bcast,
) -> Result<k256::ProjectivePoint, String> {
    // 1. Recompute expected combined Pedersen commitment at sender's index
    let x = k256::Scalar::from(u64::from(sender_index_1based));
    let mut expected_pc = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::IDENTITY;
    for (_sender, coms) in all_commitments {
        let mut x_pow = k256::Scalar::ONE;
        for com in coms {
            expected_pc += *com * x_pow;
            x_pow *= x;
        }
    }

    // 2. Check broadcast PC matches expected
    let broadcast_pc = point_from_bytes(&r3.combined_pc_bytes, "combined_pc")?;
    if broadcast_pc != expected_pc {
        return Err("CombVf: combined Pedersen commitment mismatch".into());
    }

    // 3. Verify combined R_Enc-PC proof
    let cl_pk = reconstruct_cl_pk(setup, sender_cl_pk_abc)?;
    let mut ct_pos = 0;
    let combined_ct = deserialize_ciphertext(setup, &r3.combined_ct_data, &mut ct_pos)?;
    let combined_proof = deserialize_r_enc_pc_proof(&r3.combined_enc_pc_data)?;
    let enc_ok = combined_proof
        .verify(setup, &cl_pk, &combined_ct, &r3.combined_pc_bytes)
        .map_err(|e| format!("R_Enc-PC verify error: {e}"))?;
    if !enc_ok {
        return Err("CombVf: R_Enc-PC proof verification failed".into());
    }

    // 4. Verify R_DL-PC proof (ExpVf): binds X_i to PC_xi
    let x_point = point_from_bytes(&r3.x_point_bytes, "X_i")?;
    let r_dl_pc = deserialize_r_dl_pc_proof(&r3.r_dl_pc_data)?;
    let exp_ok = r_dl_pc
        .verify(&x_point, &expected_pc)
        .map_err(|e| format!("ExpVf error: {e}"))?;
    if !exp_ok {
        return Err("ExpVf: R_DL-PC proof verification failed".into());
    }

    Ok(x_point)
}

// ---------------------------------------------------------------------------
// Finalize: compute key share
// ---------------------------------------------------------------------------

/// Construct the final key share from verified data.
pub fn keygen_finalize(
    mut state: KeygenR1State,
    r3_state: KeygenR3State,
    x_points: &[k256::ProjectivePoint],
    setup: &ClSetup,
    all_cl_pk_abcs: &[(String, String, String)],
) -> Result<Wmy23KeyShare, Box<dyn std::error::Error>> {
    let my_1based = (state.index + 1) as u16;

    // Public verification shares = {X_j} (the revealed points)
    let public_shares = x_points.to_vec();

    // Public key: Lagrange interpolation on {X_j} at x=0
    let indices: Vec<u16> = (1..=state.n).collect();
    let coeffs = tecdsa_vss::lagrange::coefficients::<k256::Secp256k1>(&indices);
    let public_key = x_points.iter().zip(coeffs.iter()).fold(
        <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::IDENTITY,
        |acc, (p, c)| acc + *p * c,
    );

    // Reconstruct all CL public keys
    let cl_pks: Vec<ClPublicKey> = all_cl_pk_abcs
        .iter()
        .map(|abc| reconstruct_cl_pk(setup, abc))
        .collect::<Result<Vec<_>, _>>()?;

    let cl_sk = state.cl_sk.take().ok_or("CL secret key already taken")?;

    let threshold = state.threshold;
    let total = state.n;
    let use_128bit_security = state.use_128bit_security;
    let cl_setup_seed = std::mem::take(&mut state.cl_setup_seed);

    Ok(Wmy23KeyShare {
        party_index: my_1based,
        secret_share: r3_state.combined_share,
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn reconstruct_cl_pk(
    setup: &ClSetup,
    (a, b, c): &(String, String, String),
) -> Result<ClPublicKey, String> {
    let qfi = Qfi::from_abc(
        Mpz::from_str(a).map_err(|e| format!("Mpz parse a: {e}"))?,
        Mpz::from_str(b).map_err(|e| format!("Mpz parse b: {e}"))?,
        Mpz::from_str(c).map_err(|e| format!("Mpz parse c: {e}"))?,
    );
    ClPublicKey::from_qfi(setup.cl(), qfi).map_err(|e| format!("ClPublicKey: {e}"))
}
