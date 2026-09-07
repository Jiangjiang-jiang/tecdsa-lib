// SPDX-License-Identifier: MIT OR Apache-2.0
//! WMC24 presign round state types and transition logic.

use std::collections::BTreeMap;

use elliptic_curve::{group::GroupEncoding, CurveArithmetic};
use rug::Integer;
use tecdsa_bigint::BigIntExt;
use tecdsa_class_group::{
    cl::{ClCiphertext, ClPublicKey, ClSetup, Qfi},
    t_cl::{self as threshold_cl, PartialDecryption as ClPartialDecryption},
    zk::{r_dl_cl::RDlClProof, r_el_cl::RElClProof, r_part_dec::RPartDecProof},
};
use tecdsa_core::TecdsaError;
use tecdsa_curve::{
    zk::ddh::{DdhProof, DdhStatement, DdhWitness},
    ScalarExt, TecdsaCurve,
};
use tecdsa_elgamal::Ciphertext as ElGamalCiphertext;
use tecdsa_protocol::{state_machine::Outgoing, PartyId, Recipient};
use zeroize::Zeroize;

use super::{msg::*, QfiAbc, Wmc24Presignature};
use crate::error::Wmc24Error;

// ---------------------------------------------------------------------------
// Received data
// ---------------------------------------------------------------------------

pub(crate) struct ReceivedR1 {
    pub(crate) k_bar_i: ClCiphertext,
}

pub(crate) struct ReceivedR2 {
    pub(crate) xk_bar_i: ClCiphertext,
    pub(crate) d_gamma_i: ElGamalCiphertext,
    pub(crate) gk_bar_i: ClCiphertext,
}

pub(crate) struct ReceivedR3 {
    pub(crate) pd_elg: k256::ProjectivePoint,
    pub(crate) pd_cl: Qfi,
    pub(crate) party_index: usize,
    #[allow(dead_code)]
    pub(crate) party_dkg_index: usize,
}

// ---------------------------------------------------------------------------
// State machine states
// ---------------------------------------------------------------------------

pub(crate) struct Round1State {
    pub(crate) my_id: PartyId,
    pub(crate) all_parties: Vec<PartyId>,
    pub(crate) k_i: k256::Scalar,
    pub(crate) received: BTreeMap<PartyId, ReceivedR1>,
    pub(crate) outgoing: Vec<Outgoing<Wmc24PresignMsg>>,
}

pub(crate) struct Round2State {
    pub(crate) my_id: PartyId,
    pub(crate) all_parties: Vec<PartyId>,
    pub(crate) k_i: k256::Scalar,
    pub(crate) _gamma_i: k256::Scalar,
    pub(crate) k_bar: ClCiphertext,
    pub(crate) received: BTreeMap<PartyId, ReceivedR2>,
    pub(crate) outgoing: Vec<Outgoing<Wmc24PresignMsg>>,
}

pub(crate) struct Round3State {
    pub(crate) my_id: PartyId,
    pub(crate) all_parties: Vec<PartyId>,
    pub(crate) k_i: k256::Scalar,
    pub(crate) k_bar: ClCiphertext,
    pub(crate) xk_bar: ClCiphertext,
    pub(crate) d_gamma: ElGamalCiphertext,
    pub(crate) gk_bar: ClCiphertext,
    pub(crate) received: BTreeMap<PartyId, ReceivedR3>,
    pub(crate) outgoing: Vec<Outgoing<Wmc24PresignMsg>>,
}

pub(crate) enum PresignRound {
    Round1(Round1State),
    Round2(Round2State),
    Round3(Round3State),
    Done(Wmc24Presignature),
    Poisoned,
}

pub(crate) struct KeyMaterial {
    pub(crate) x_i: k256::Scalar,
    pub(crate) public_shares: Vec<k256::ProjectivePoint>,
    pub(crate) threshold: u16,
    pub(crate) cl_sk_share: Vec<u8>,
    pub(crate) cl_pk: ClPublicKey,
    pub(crate) cl_pk_abc: QfiAbc,
    pub(crate) cl_pk_share_abcs: BTreeMap<u16, QfiAbc>,
    pub(crate) cl_setup_seed: String,
    pub(crate) use_128bit_security: bool,
    pub(crate) n_parties_dkg: usize,
    pub(crate) eldk_i: k256::Scalar,
    pub(crate) elek: k256::ProjectivePoint,
    /// Per-party ElGamal encryption key shares (elek_j = eldk_j * G).
    pub(crate) elek_shares: Vec<k256::ProjectivePoint>,
}

impl Zeroize for KeyMaterial {
    fn zeroize(&mut self) {
        self.x_i.zeroize();
        self.cl_sk_share.zeroize();
        self.eldk_i.zeroize();
    }
}

impl Drop for KeyMaterial {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub(crate) fn scalar_mul_ct(
    setup: &ClSetup,
    ct: &ClCiphertext,
    x: &Integer,
) -> Result<ClCiphertext, Wmc24Error> {
    let (c1, c2) = setup.ct_components(ct)?;
    let c1_x = setup.exp(&c1, x)?;
    let c2_x = setup.exp(&c2, x)?;
    let result = setup.ct_from_components(&c1_x, &c2_x)?;
    Ok(result)
}

pub(crate) fn add_ct_components(
    setup: &ClSetup,
    ct_a: &ClCiphertext,
    ct_b: &ClCiphertext,
) -> Result<ClCiphertext, Wmc24Error> {
    let (a1, a2) = setup.ct_components(ct_a)?;
    let (b1, b2) = setup.ct_components(ct_b)?;
    let c1 = setup.compose(&a1, &b1)?;
    let c2 = setup.compose(&a2, &b2)?;
    Ok(setup.ct_from_components(&c1, &c2)?)
}

pub(crate) fn copy_ct(setup: &ClSetup, ct: &ClCiphertext) -> Result<ClCiphertext, Wmc24Error> {
    let (c1, c2) = setup.ct_components(ct)?;
    Ok(setup.ct_from_components(&c1, &c2)?)
}

// ---------------------------------------------------------------------------
// Transitions
// ---------------------------------------------------------------------------

pub(crate) fn transition_r1_to_r2(
    state: Round1State,
    setup: &mut ClSetup,
    key_mat: &KeyMaterial,
) -> tecdsa_core::Result<Round2State> {
    let party_ids_1based: Vec<u16> = state.all_parties.iter().map(|p| p.0).collect();

    // Compute k_bar = sum of all k_bar_j (homomorphic sum).
    let mut k_bar: Option<ClCiphertext> = None;
    for r1 in state.received.values() {
        match k_bar.take() {
            None => {
                k_bar = Some(
                    copy_ct(setup, &r1.k_bar_i)
                        .map_err(|e| TecdsaError::Other(format!("copy_ct: {e}")))?,
                );
            }
            Some(acc) => {
                let sum = add_ct_components(setup, &acc, &r1.k_bar_i)
                    .map_err(|e| TecdsaError::Other(format!("add_ct: {e}")))?;
                k_bar = Some(sum);
            }
        }
    }
    let k_bar = k_bar.ok_or_else(|| TecdsaError::Other("no k_bar data".into()))?;

    // Compute xk_bar_i = x_i * k_bar (with Lagrange coefficient).
    let my_idx = state
        .all_parties
        .iter()
        .position(|p| *p == state.my_id)
        .ok_or_else(|| TecdsaError::Other("my_id not in all_parties".into()))?;

    let lagrange_coeffs = tecdsa_vss::lagrange::coefficients::<k256::Secp256k1>(&party_ids_1based);
    let lambda_i = lagrange_coeffs[my_idx];
    let lambda_x_i = lambda_i * key_mat.x_i;
    let lambda_x_i_int = lambda_x_i.to_integer();

    let xk_bar_i = scalar_mul_ct(setup, &k_bar, &lambda_x_i_int)
        .map_err(|e| TecdsaError::Other(format!("scalar_mul xk_bar_i: {e}")))?;

    let x_i_lambda_point =
        <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * lambda_x_i;

    let pi_dl_cl_x =
        RDlClProof::prove(setup, &x_i_lambda_point, &k_bar, &xk_bar_i, &lambda_x_i_int)
            .map_err(|e| TecdsaError::Other(format!("R_dl-cl x prove: {e}")))?;

    // Sample gamma_i.
    let gamma_i_int = {
        let (sk, _) = setup
            .keygen()
            .map_err(|e| TecdsaError::Other(format!("keygen: {e}")))?;
        setup.sk_to_integer(&sk).modulo(setup.cl().q())
    };
    let gamma_i = k256::Secp256k1::scalar_from_integer(&gamma_i_int);

    // ElGamal encrypt g^{gamma_i}: D_gamma_i = t-ElG.Enc(elek, g^{gamma_i}; r_{gamma_i}).
    let g = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR;
    let g_gamma_i = g * gamma_i;

    // Sample ElGamal randomness.
    let r_elg_i_int = {
        let (sk, _) = setup
            .keygen()
            .map_err(|e| TecdsaError::Other(format!("keygen: {e}")))?;
        setup.sk_to_integer(&sk).modulo(setup.cl().q())
    };
    let r_elg_i = k256::Secp256k1::scalar_from_integer(&r_elg_i_int);
    let d_gamma_i = tecdsa_elgamal::encrypt(&key_mat.elek, &g_gamma_i, &r_elg_i);

    // Compute gk_bar_i = gamma_i * k_bar.
    let gk_bar_i = scalar_mul_ct(setup, &k_bar, &gamma_i_int)
        .map_err(|e| TecdsaError::Other(format!("scalar_mul gk_bar_i: {e}")))?;

    // R_El-CL proof.
    let (ck_0, ck_1) = setup
        .ct_components(&k_bar)
        .map_err(|e| TecdsaError::Other(format!("k_bar comp: {e}")))?;
    let (cgk_0, cgk_1) = setup
        .ct_components(&gk_bar_i)
        .map_err(|e| TecdsaError::Other(format!("gk_bar comp: {e}")))?;

    let pi_el_cl = RElClProof::prove(
        setup,
        &g,
        &key_mat.elek,
        &d_gamma_i.c0,
        &d_gamma_i.c1,
        &ck_0,
        &ck_1,
        &cgk_0,
        &cgk_1,
        &gamma_i_int,
        &r_elg_i_int,
    )
    .map_err(|e| TecdsaError::Other(format!("R_El-CL prove: {e}")))?;

    // Build Round 2 payload.
    let xk_bar_i_ser = SerializedClCt::from_bicycl_ct(setup, &xk_bar_i)
        .map_err(|e| TecdsaError::Other(format!("ser xk_bar_i: {e}")))?;
    let pi_dl_cl_x_ser = SerRDlClProof::from_proof(&pi_dl_cl_x)
        .map_err(|e| TecdsaError::Other(format!("ser pi_dl_cl_x: {e}")))?;
    let gk_bar_i_ser = SerializedClCt::from_bicycl_ct(setup, &gk_bar_i)
        .map_err(|e| TecdsaError::Other(format!("ser gk_bar_i: {e}")))?;
    let pi_el_cl_ser = SerRElClProof::from_proof(&pi_el_cl)
        .map_err(|e| TecdsaError::Other(format!("ser pi_el_cl: {e}")))?;

    let r2_payload = R2Payload {
        xk_bar_i: xk_bar_i_ser,
        pi_dl_cl_x: pi_dl_cl_x_ser,
        d_gamma_c0_bytes: d_gamma_i.c0.to_bytes().to_vec(),
        d_gamma_c1_bytes: d_gamma_i.c1.to_bytes().to_vec(),
        gk_bar_i: gk_bar_i_ser,
        pi_el_cl: pi_el_cl_ser,
    };

    let payload_bytes = bincode::serde::encode_to_vec(&r2_payload, bincode::config::standard())
        .map_err(|e| TecdsaError::Other(format!("serialize R2: {e}")))?;

    let outgoing = vec![Outgoing {
        to: Recipient::Broadcast,
        msg: Wmc24PresignMsg::Round2(payload_bytes),
    }];

    let mut received = BTreeMap::new();
    received.insert(
        state.my_id,
        ReceivedR2 {
            xk_bar_i,
            d_gamma_i,
            gk_bar_i,
        },
    );

    Ok(Round2State {
        my_id: state.my_id,
        all_parties: state.all_parties,
        k_i: state.k_i,
        _gamma_i: gamma_i,
        k_bar,
        received,
        outgoing,
    })
}

pub(crate) fn transition_r2_to_r3(
    state: Round2State,
    setup: &mut ClSetup,
    key_mat: &KeyMaterial,
) -> tecdsa_core::Result<Round3State> {
    // Compute xk_bar = sum(xk_bar_j) -- Lagrange already baked in during Round 2.
    let mut xk_bar: Option<ClCiphertext> = None;
    for r2 in state.received.values() {
        match xk_bar.take() {
            None => {
                xk_bar = Some(
                    copy_ct(setup, &r2.xk_bar_i)
                        .map_err(|e| TecdsaError::Other(format!("copy_ct: {e}")))?,
                );
            }
            Some(acc) => {
                let sum = add_ct_components(setup, &acc, &r2.xk_bar_i)
                    .map_err(|e| TecdsaError::Other(format!("add_ct xk_bar: {e}")))?;
                xk_bar = Some(sum);
            }
        }
    }
    let xk_bar = xk_bar.ok_or_else(|| TecdsaError::Other("no xk_bar data".into()))?;

    // Compute D_gamma = product(D_gamma_j) (ElGamal component-wise add).
    let mut d_gamma: Option<ElGamalCiphertext> = None;
    for r2 in state.received.values() {
        match d_gamma.take() {
            None => {
                d_gamma = Some(r2.d_gamma_i);
            }
            Some(acc) => {
                d_gamma = Some(tecdsa_elgamal::add(&acc, &r2.d_gamma_i));
            }
        }
    }
    let d_gamma = d_gamma.ok_or_else(|| TecdsaError::Other("no d_gamma data".into()))?;

    // Compute gk_bar = sum(gk_bar_j).
    let mut gk_bar: Option<ClCiphertext> = None;
    for r2 in state.received.values() {
        match gk_bar.take() {
            None => {
                gk_bar = Some(
                    copy_ct(setup, &r2.gk_bar_i)
                        .map_err(|e| TecdsaError::Other(format!("copy_ct: {e}")))?,
                );
            }
            Some(acc) => {
                let sum = add_ct_components(setup, &acc, &r2.gk_bar_i)
                    .map_err(|e| TecdsaError::Other(format!("add_ct gk_bar: {e}")))?;
                gk_bar = Some(sum);
            }
        }
    }
    let gk_bar = gk_bar.ok_or_else(|| TecdsaError::Other("no gk_bar data".into()))?;

    // Partial decrypt D_gamma: pd_elg_i = eldk_i * D_gamma.c0.
    let pd_elg_i = tecdsa_elgamal::partial_decrypt(&d_gamma, &key_mat.eldk_i);

    // DDH proof for ElGamal partial decryption correctness.
    // Statement: (G, D_gamma.c0, elek_i, pd_elg_i) is a DDH tuple.
    // Witness: eldk_i such that elek_i = eldk_i * G AND pd_elg_i = eldk_i * D_gamma.c0.
    let g = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR;
    let my_dkg_idx = super::party_id_to_dkg_idx(state.my_id)?;
    let elek_i = key_mat.elek_shares[my_dkg_idx];
    let ddh_stmt = DdhStatement::<k256::Secp256k1> {
        g,
        a: d_gamma.c0,
        b: elek_i,
        c: pd_elg_i,
    };
    let ddh_wit = DdhWitness::<k256::Secp256k1> { w: key_mat.eldk_i };
    let pi_part_dec_elg = DdhProof::prove(&ddh_stmt, &ddh_wit, &mut rand::thread_rng());

    // Partial decrypt gk_bar: pd_cl_i = t-CL.PartDec.
    // PartyId.0 is 1-based, matching t-CL evaluation points.
    let my_party_index = state.my_id.0 as usize;
    let (gk_c1, _) = setup
        .ct_components(&gk_bar)
        .map_err(|e| TecdsaError::Other(format!("gk_bar comp: {e}")))?;
    let cl_sk_share_int = Integer::from_bytes_msf(&key_mat.cl_sk_share);
    let pd_cl_i = setup
        .exp(&gk_c1, &cl_sk_share_int)
        .map_err(|e| TecdsaError::Other(format!("pd_cl: {e}")))?;

    // R_part_dec proof for CL.
    let my_pk_abc = key_mat
        .cl_pk_share_abcs
        .get(&state.my_id.0)
        .ok_or_else(|| TecdsaError::Other("missing own CL pk share abc".into()))?;
    let my_pk_qfi = { Qfi::from_bytes(&my_pk_abc.data) };
    let my_pk_raw = setup
        .pk_from_qfi(&my_pk_qfi)
        .map_err(|e| TecdsaError::Other(format!("pk_from_qfi: {e}")))?;

    let pi_part_dec_cl =
        RPartDecProof::prove(setup, &my_pk_raw, &gk_bar, &pd_cl_i, &cl_sk_share_int)
            .map_err(|e| TecdsaError::Other(format!("R_part_dec_cl prove: {e}")))?;

    // Serialize and broadcast.
    let pd_cl_ser = SerializedQfi::from_qfi(&pd_cl_i)
        .map_err(|e| TecdsaError::Other(format!("ser pd_cl: {e}")))?;
    let pi_ser = SerRPartDecProof::from_proof(&pi_part_dec_cl)
        .map_err(|e| TecdsaError::Other(format!("ser pi_part_dec: {e}")))?;

    let r3_payload = R3Payload {
        pd_elg_bytes: pd_elg_i.to_bytes().to_vec(),
        pi_part_dec_elg: SerDdhProof::from_proof(&pi_part_dec_elg),
        pd_cl: pd_cl_ser,
        pi_part_dec_cl: pi_ser,
        party_index: my_party_index,
        party_dkg_index: my_dkg_idx,
    };

    let payload_bytes = bincode::serde::encode_to_vec(&r3_payload, bincode::config::standard())
        .map_err(|e| TecdsaError::Other(format!("serialize R3: {e}")))?;

    let outgoing = vec![Outgoing {
        to: Recipient::Broadcast,
        msg: Wmc24PresignMsg::Round3(payload_bytes),
    }];

    let mut received = BTreeMap::new();
    received.insert(
        state.my_id,
        ReceivedR3 {
            pd_elg: pd_elg_i,
            pd_cl: pd_cl_i,
            party_index: my_party_index,
            party_dkg_index: my_dkg_idx,
        },
    );

    Ok(Round3State {
        my_id: state.my_id,
        all_parties: state.all_parties,
        k_i: state.k_i,
        k_bar: state.k_bar,
        xk_bar,
        d_gamma,
        gk_bar,
        received,
        outgoing,
    })
}

pub(crate) fn finalize(
    state: &Round3State,
    setup: &ClSetup,
    key_mat: &KeyMaterial,
) -> tecdsa_core::Result<Wmc24Presignature> {
    let n = state.all_parties.len();

    // 1. g^gamma = ElGamal final decrypt of D_gamma.
    // ElGamal key shares use Shamir sharing: need Lagrange coefficients.
    let party_ids_1based: Vec<u16> = state.all_parties.iter().map(|p| p.0).collect();
    let lagrange_coeffs = tecdsa_vss::lagrange::coefficients::<k256::Secp256k1>(&party_ids_1based);

    let mut pd_elg_pairs: Vec<(k256::Scalar, k256::ProjectivePoint)> = Vec::new();
    for (&party_j, r3) in &state.received {
        let idx = state
            .all_parties
            .iter()
            .position(|p| *p == party_j)
            .ok_or_else(|| TecdsaError::Other(format!("party {party_j} not in all_parties")))?;
        pd_elg_pairs.push((lagrange_coeffs[idx], r3.pd_elg));
    }
    let g_gamma = tecdsa_elgamal::combine_partials(&state.d_gamma, &pd_elg_pairs);

    // 2. gamma*k = t-CL final decrypt of gk_bar.
    let mut pd_cls: Vec<ClPartialDecryption> = Vec::new();
    for r3 in state.received.values() {
        let bytes = r3.pd_cl.to_bytes();
        let copy = Qfi::from_bytes(&bytes);
        pd_cls.push(ClPartialDecryption {
            party_index: r3.party_index,
            dec_share: copy,
        });
    }

    let gamma_k_int =
        threshold_cl::final_decrypt(setup, &state.gk_bar, key_mat.n_parties_dkg, &pd_cls)
            .map_err(|e| TecdsaError::Other(format!("final_decrypt gk: {e}")))?;

    let gamma_k = k256::Secp256k1::scalar_from_integer(&gamma_k_int);

    // 3. R = (g^gamma)^{1/(gamma*k)} = g^{1/k}.
    let gamma_k_inv: k256::Scalar = {
        let inv = gamma_k.invert();
        if bool::from(inv.is_none()) {
            return Err(TecdsaError::Other("gamma*k is zero, cannot invert".into()));
        }
        inv.unwrap()
    };

    let r_point: k256::ProjectivePoint = g_gamma * gamma_k_inv;
    let r_x = <k256::Secp256k1 as TecdsaCurve>::xcoord_mod_q(&r_point.to_affine());

    // Serialize k_bar and xk_bar as QfiAbc (compact binary).
    let (kb_c1, kb_c2) = setup
        .ct_components(&state.k_bar)
        .map_err(|e| TecdsaError::Other(format!("k_bar comp: {e}")))?;
    let k_bar_c1_abc = QfiAbc {
        data: kb_c1.to_bytes(),
    };
    let k_bar_c2_abc = QfiAbc {
        data: kb_c2.to_bytes(),
    };

    let (xk_c1, xk_c2) = setup
        .ct_components(&state.xk_bar)
        .map_err(|e| TecdsaError::Other(format!("xk_bar comp: {e}")))?;
    let xk_bar_c1_abc = QfiAbc {
        data: xk_c1.to_bytes(),
    };
    let xk_bar_c2_abc = QfiAbc {
        data: xk_c2.to_bytes(),
    };

    Ok(Wmc24Presignature {
        party_index: state.my_id.0,
        r_point,
        r_x,
        k_i: state.k_i,
        n_signers: n,
        threshold: key_mat.threshold,
        k_bar_c1_abc,
        k_bar_c2_abc,
        xk_bar_c1_abc,
        xk_bar_c2_abc,
        cl_setup_seed: key_mat.cl_setup_seed.clone(),
        use_128bit_security: key_mat.use_128bit_security,
        cl_sk_share: key_mat.cl_sk_share.clone(),
        cl_pk_abc: key_mat.cl_pk_abc.clone(),
        cl_pk_share_abcs: key_mat.cl_pk_share_abcs.clone(),
        n_parties_dkg: key_mat.n_parties_dkg,
    })
}
