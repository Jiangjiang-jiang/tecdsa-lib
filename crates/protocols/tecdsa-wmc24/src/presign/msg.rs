// SPDX-License-Identifier: MIT OR Apache-2.0
//! WMC24 presign message types and serialization helpers.

use elliptic_curve::group::GroupEncoding;
use serde::{Deserialize, Serialize};
use tecdsa_class_group::{
    cl::{ClCiphertext, ClSetup, Qfi},
    zk::{r_dl_cl::RDlClProof, r_el_cl::RElClProof, r_enc::REncProof, r_part_dec::RPartDecProof},
};
use tecdsa_curve::zk::ddh::DdhProof;

use crate::curve_wire::point_from_bytes;

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Wmc24PresignMsg {
    Round1(Vec<u8>),
    Round2(Vec<u8>),
    Round3(Vec<u8>),
}

// ---------------------------------------------------------------------------
// Serialized CL types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SerializedQfi {
    pub(crate) data: Vec<u8>,
}

impl SerializedQfi {
    pub(crate) fn from_qfi(qfi: &Qfi) -> Result<Self, String> {
        let data = qfi.to_bytes();
        Ok(Self { data })
    }

    pub(crate) fn to_qfi(&self) -> Result<Qfi, String> {
        Ok(Qfi::from_bytes(&self.data))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SerializedClCt {
    pub(crate) c1: Vec<u8>,
    pub(crate) c2: Vec<u8>,
}

impl SerializedClCt {
    pub(crate) fn from_bicycl_ct(setup: &ClSetup, ct: &ClCiphertext) -> Result<Self, String> {
        let (c1, c2) = setup
            .ct_components(ct)
            .map_err(|e| format!("ct_comp: {e}"))?;
        Ok(Self {
            c1: c1.to_bytes(),
            c2: c2.to_bytes(),
        })
    }

    pub(crate) fn to_bicycl_ct(&self, setup: &ClSetup) -> Result<ClCiphertext, String> {
        let c1 = Qfi::from_bytes(&self.c1);
        let c2 = Qfi::from_bytes(&self.c2);
        setup
            .ct_from_components(&c1, &c2)
            .map_err(|e| format!("ct_from: {e}"))
    }
}

// Serialized proofs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SerREncProof {
    pub(crate) t1: SerializedQfi,
    pub(crate) t2: SerializedQfi,
    pub(crate) u1: Vec<u8>,
    pub(crate) u2: Vec<u8>,
    pub(crate) e: Vec<u8>,
}

impl SerREncProof {
    pub(crate) fn from_proof(proof: &REncProof) -> Result<Self, String> {
        Ok(Self {
            t1: SerializedQfi::from_qfi(&proof.t1)?,
            t2: SerializedQfi::from_qfi(&proof.t2)?,
            u1: proof.u1.clone(),
            u2: proof.u2.clone(),
            e: proof.e.clone(),
        })
    }
    pub(crate) fn to_proof(&self) -> Result<REncProof, String> {
        Ok(REncProof {
            t1: self.t1.to_qfi()?,
            t2: self.t2.to_qfi()?,
            u1: self.u1.clone(),
            u2: self.u2.clone(),
            e: self.e.clone(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SerRDlClProof {
    pub(crate) t1: SerializedQfi,
    pub(crate) t2: SerializedQfi,
    pub(crate) t_ec_bytes: Vec<u8>,
    pub(crate) z: Vec<u8>,
    pub(crate) e: Vec<u8>,
}

impl SerRDlClProof {
    pub(crate) fn from_proof(proof: &RDlClProof) -> Result<Self, String> {
        Ok(Self {
            t1: SerializedQfi::from_qfi(&proof.t1)?,
            t2: SerializedQfi::from_qfi(&proof.t2)?,
            t_ec_bytes: proof.t_ec_bytes.clone(),
            z: proof.z.clone(),
            e: proof.e.clone(),
        })
    }
    pub(crate) fn to_proof(&self) -> Result<RDlClProof, String> {
        Ok(RDlClProof {
            t1: self.t1.to_qfi()?,
            t2: self.t2.to_qfi()?,
            t_ec_bytes: self.t_ec_bytes.clone(),
            z: self.z.clone(),
            e: self.e.clone(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SerRElClProof {
    pub(crate) r_elg_bytes: Vec<u8>,
    pub(crate) s_elg_bytes: Vec<u8>,
    pub(crate) r_ck: SerializedQfi,
    pub(crate) s_ck: SerializedQfi,
    pub(crate) z1: Vec<u8>,
    pub(crate) z2: Vec<u8>,
    pub(crate) e: Vec<u8>,
}

impl SerRElClProof {
    pub(crate) fn from_proof(proof: &RElClProof) -> Result<Self, String> {
        Ok(Self {
            r_elg_bytes: proof.r_elg_bytes.clone(),
            s_elg_bytes: proof.s_elg_bytes.clone(),
            r_ck: SerializedQfi::from_qfi(&proof.r_ck)?,
            s_ck: SerializedQfi::from_qfi(&proof.s_ck)?,
            z1: proof.z1.clone(),
            z2: proof.z2.clone(),
            e: proof.e.clone(),
        })
    }
    pub(crate) fn to_proof(&self) -> Result<RElClProof, String> {
        Ok(RElClProof {
            r_elg_bytes: self.r_elg_bytes.clone(),
            s_elg_bytes: self.s_elg_bytes.clone(),
            r_ck: self.r_ck.to_qfi()?,
            s_ck: self.s_ck.to_qfi()?,
            z1: self.z1.clone(),
            z2: self.z2.clone(),
            e: self.e.clone(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SerRPartDecProof {
    pub(crate) t1: SerializedQfi,
    pub(crate) t2: SerializedQfi,
    pub(crate) z: Vec<u8>,
    pub(crate) e: Vec<u8>,
}

impl SerRPartDecProof {
    pub(crate) fn from_proof(proof: &RPartDecProof) -> Result<Self, String> {
        Ok(Self {
            t1: SerializedQfi::from_qfi(&proof.t1)?,
            t2: SerializedQfi::from_qfi(&proof.t2)?,
            z: proof.z.clone(),
            e: proof.e.clone(),
        })
    }
    pub(crate) fn to_proof(&self) -> Result<RPartDecProof, String> {
        Ok(RPartDecProof {
            t1: self.t1.to_qfi()?,
            t2: self.t2.to_qfi()?,
            z: self.z.clone(),
            e: self.e.clone(),
        })
    }
}

/// Serialized EC DDH proof for ElGamal partial decryption correctness.
///
/// Proves knowledge of `eldk_i` such that `elek_i = eldk_i * G` and
/// `pd_elg_i = eldk_i * c_0` (i.e., the partial decryption is correct).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SerDdhProof {
    /// Commitment R_G = r * G (compressed SEC1).
    pub(crate) g_r_bytes: Vec<u8>,
    /// Commitment R_A = r * A (compressed SEC1).
    pub(crate) a_r_bytes: Vec<u8>,
    /// Response scalar z = r - e * w (big-endian bytes).
    pub(crate) z_bytes: Vec<u8>,
}

impl SerDdhProof {
    pub(crate) fn from_proof(proof: &DdhProof<k256::Secp256k1>) -> Self {
        use elliptic_curve::ff::PrimeField;
        Self {
            g_r_bytes: proof.g_r.to_bytes().to_vec(),
            a_r_bytes: proof.a_r.to_bytes().to_vec(),
            z_bytes: proof.z.to_repr().to_vec(),
        }
    }

    pub(crate) fn to_proof(&self) -> Result<DdhProof<k256::Secp256k1>, String> {
        use elliptic_curve::ff::PrimeField;
        let g_r = point_from_bytes(&self.g_r_bytes, "ddh_g_r")?;
        let a_r = point_from_bytes(&self.a_r_bytes, "ddh_a_r")?;
        if self.z_bytes.len() != 32 {
            return Err(format!(
                "ddh z: expected 32 bytes, got {}",
                self.z_bytes.len()
            ));
        }
        let mut z_arr = k256::FieldBytes::default();
        z_arr.copy_from_slice(&self.z_bytes);
        let z = Option::from(k256::Scalar::from_repr(z_arr))
            .ok_or_else(|| "ddh z: non-canonical scalar".to_string())?;
        Ok(DdhProof { g_r, a_r, z })
    }
}

// ---------------------------------------------------------------------------
// Round payloads
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct R1Payload {
    pub(crate) k_bar_i: SerializedClCt,
    pub(crate) r_enc_proof: SerREncProof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct R2Payload {
    pub(crate) xk_bar_i: SerializedClCt,
    pub(crate) pi_dl_cl_x: SerRDlClProof,
    /// ElGamal ciphertext of g^{gamma_i}: (c0_bytes, c1_bytes)
    pub(crate) d_gamma_c0_bytes: Vec<u8>,
    pub(crate) d_gamma_c1_bytes: Vec<u8>,
    pub(crate) gk_bar_i: SerializedClCt,
    pub(crate) pi_el_cl: SerRElClProof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct R3Payload {
    /// ElGamal partial decryption: eldk_i * D_gamma.c0
    pub(crate) pd_elg_bytes: Vec<u8>,
    /// DDH proof for ElGamal partial decryption correctness.
    /// Proves (G, D_gamma.c0, elek_i, pd_elg_i) is a DDH tuple with witness eldk_i.
    pub(crate) pi_part_dec_elg: SerDdhProof,
    /// CL partial decryption of gk_bar
    pub(crate) pd_cl: SerializedQfi,
    pub(crate) pi_part_dec_cl: SerRPartDecProof,
    pub(crate) party_index: usize,
    /// Index of this party in the all_parties list (for elek_shares lookup).
    pub(crate) party_dkg_index: usize,
}
