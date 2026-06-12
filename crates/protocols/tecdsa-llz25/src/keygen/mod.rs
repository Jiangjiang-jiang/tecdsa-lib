#![allow(non_snake_case)]

pub mod machine;
pub mod msg;
pub mod rounds;

use elliptic_curve::{group::GroupEncoding, CurveArithmetic};
pub use machine::Llz25KeygenMachine;
pub use msg::Llz25KeygenMsg;
use tecdsa_class_group::{
    cl::{ClCiphertext as ClHsmqkCiphertext, ClPublicKey as ClHsmqkPublicKey, ClSetup},
    nim::{Nim, NimEncodeBOutput},
    zk::r_cl_dl_ec::RClDlEcProof,
};
use tecdsa_curve::TecdsaCurve;
use tecdsa_vss::shamir;

use crate::{error::Llz25Error, key_share::Llz25KeyShare};

pub struct KeygenAuxInfo {
    pub party_index: u16,
    pub pe_x: ClHsmqkCiphertext,
    pub proof: RClDlEcProof,
}

pub fn keygen_with_dealer(
    n: u16,
    threshold: u16,
    setup: &mut ClSetup,
    pk_crs: &ClHsmqkPublicKey,
    cl_setup_seed: &str,
    use_128bit: bool,
) -> Result<(Vec<Llz25KeyShare>, Vec<KeygenAuxInfo>), Llz25Error> {
    let mut rng = rand::thread_rng();

    let x = k256::Secp256k1::random_scalar(&mut rng);
    let shares = shamir::split::<k256::Secp256k1>(&x, threshold, n, &mut rng);
    let public_key = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * x;

    let public_shares: Vec<k256::ProjectivePoint> = shares
        .iter()
        .map(|s| <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR * s.value)
        .collect();

    let mut key_shares = Vec::with_capacity(n as usize);
    let mut aux_infos = Vec::with_capacity(n as usize);
    let mut all_pe_x_components: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(n as usize);

    for (i, share) in shares.iter().enumerate() {
        let x_i_bytes = tecdsa_curve::conv::scalar_to_bytes::<k256::Secp256k1>(&share.value);

        let mut nim = Nim::new(setup);
        let NimEncodeBOutput { pe_b, state: st_b } = nim
            .encode_b(&x_i_bytes, pk_crs)
            .map_err(|e| Llz25Error::ClassGroup(format!("NIM.Encode_B failed: {e}")))?;

        let (c1, c2) = setup
            .ct_components(&pe_b)
            .map_err(|e| Llz25Error::ClassGroup(format!("ct_components: {e}")))?;
        all_pe_x_components.push((c1.to_bytes(), c2.to_bytes()));

        let big_x_i_bytes = public_shares[i].to_bytes().to_vec();

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
            pe_x_components: (Vec::new(), Vec::new()),
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

    for (i, ks) in key_shares.iter_mut().enumerate() {
        ks.pe_x_components = all_pe_x_components[i].clone();
        ks.all_pe_x_components = all_pe_x_components.clone();
    }

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
