#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    non_snake_case
)]

pub mod machine;
pub mod msg;
pub mod rounds;

use elliptic_curve::group::GroupEncoding;
pub use machine::Tx25KeygenMachine;
pub use msg::Tx25KeygenMsg;
use tecdsa_class_group::{
    cl::Qfi,
    zk::{r_dec_dl::RDecDlProof, r_key::RKeyProof, r_sh::RShProof},
};

use crate::{error::Tx25Error, pvss::PvssOutput};

fn write_field(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
    buf.extend_from_slice(data);
}

fn read_field(data: &[u8], pos: usize) -> Result<(&[u8], usize), Tx25Error> {
    if pos + 4 > data.len() {
        return Err(Tx25Error::InvalidInput("truncated field length".into()));
    }
    let len = u32::from_le_bytes(
        data[pos..pos + 4]
            .try_into()
            .map_err(|_| Tx25Error::InvalidInput("bad length bytes".into()))?,
    ) as usize;
    let start = pos + 4;
    let end = start + len;
    if end > data.len() {
        return Err(Tx25Error::InvalidInput("truncated field data".into()));
    }
    Ok((&data[start..end], end))
}

fn write_qfi_bin(buf: &mut Vec<u8>, qfi: &Qfi) {
    let bytes = qfi.to_bytes();
    write_field(buf, &bytes);
}

fn read_qfi_bin(data: &[u8], pos: usize) -> Result<(Qfi, usize), Tx25Error> {
    let (bytes, new_pos) = read_field(data, pos)?;
    Ok((Qfi::from_bytes(bytes), new_pos))
}

fn serialize_round1(pk: &Qfi, proof: &RKeyProof) -> Result<Vec<u8>, Tx25Error> {
    let mut buf = Vec::new();

    write_qfi_bin(&mut buf, pk);

    write_qfi_bin(&mut buf, &proof.t);
    write_field(&mut buf, &proof.z);
    write_field(&mut buf, &proof.e);

    Ok(buf)
}

fn deserialize_round1(data: &[u8]) -> Result<(Qfi, RKeyProof), Tx25Error> {
    let (pk, pos) = read_qfi_bin(data, 0)?;
    let (t, pos) = read_qfi_bin(data, pos)?;
    let (z_bytes, pos) = read_field(data, pos)?;
    let (e_bytes, _pos) = read_field(data, pos)?;

    let proof = RKeyProof {
        t,
        z: z_bytes.to_vec(),
        e: e_bytes.to_vec(),
    };

    Ok((pk, proof))
}

fn serialize_round2(pvss: &PvssOutput) -> Result<Vec<u8>, Tx25Error> {
    let mut buf = Vec::new();

    buf.extend_from_slice(&(pvss.c2s.len() as u32).to_le_bytes());

    write_qfi_bin(&mut buf, &pvss.c1);

    for c2 in &pvss.c2s {
        write_qfi_bin(&mut buf, c2);
    }

    write_field(&mut buf, &pvss.proof.k);
    write_field(&mut buf, &pvss.proof.rho_response);

    Ok(buf)
}

fn deserialize_round2(data: &[u8]) -> Result<(Qfi, Vec<Qfi>, RShProof), Tx25Error> {
    if data.len() < 4 {
        return Err(Tx25Error::InvalidInput("R2 data too short".into()));
    }
    let n = u32::from_le_bytes(
        data[0..4]
            .try_into()
            .map_err(|_| Tx25Error::InvalidInput("bad n bytes".into()))?,
    ) as usize;
    let mut pos = 4;

    let (c1, new_pos) = read_qfi_bin(data, pos)?;
    pos = new_pos;

    let mut c2s = Vec::with_capacity(n);
    for _ in 0..n {
        let (c2, new_pos) = read_qfi_bin(data, pos)?;
        pos = new_pos;
        c2s.push(c2);
    }

    let (k_bytes, new_pos) = read_field(data, pos)?;
    pos = new_pos;
    let (rho_response_bytes, _) = read_field(data, pos)?;

    let proof = RShProof {
        k: k_bytes.to_vec(),
        rho_response: rho_response_bytes.to_vec(),
    };

    Ok((c1, c2s, proof))
}

fn serialize_round3(
    public_share_bytes: &[u8],
    pd: &Qfi,
    proof: &RDecDlProof,
) -> Result<Vec<u8>, Tx25Error> {
    let mut buf = Vec::new();

    write_field(&mut buf, public_share_bytes);

    write_qfi_bin(&mut buf, pd);

    write_qfi_bin(&mut buf, &proof.t1);
    write_qfi_bin(&mut buf, &proof.t2);
    write_field(&mut buf, &proof.z);
    write_field(&mut buf, &proof.e);

    Ok(buf)
}

fn deserialize_round3(data: &[u8]) -> Result<(k256::ProjectivePoint, RDecDlProof, Qfi), Tx25Error> {
    let (point_bytes, pos) = read_field(data, 0)?;

    let repr = k256::CompressedPoint::try_from(point_bytes)
        .map_err(|e| Tx25Error::InvalidInput(format!("invalid point bytes: {e}")))?;
    let point: k256::ProjectivePoint = Option::from(k256::ProjectivePoint::from_bytes(&repr))
        .ok_or_else(|| Tx25Error::InvalidInput("invalid EC point".into()))?;

    let (pd, pos) = read_qfi_bin(data, pos)?;

    let (t1, pos) = read_qfi_bin(data, pos)?;
    let (t2, pos) = read_qfi_bin(data, pos)?;
    let (z_bytes, pos) = read_field(data, pos)?;
    let (e_bytes, _) = read_field(data, pos)?;

    let proof = RDecDlProof {
        t1,
        t2,
        z: z_bytes.to_vec(),
        e: e_bytes.to_vec(),
    };

    Ok((point, proof, pd))
}

#[cfg(test)]
mod tests {
    use elliptic_curve::CurveArithmetic;
    use tecdsa_protocol::{PartyId, StateMachine};

    use super::*;

    fn run_keygen_state_machine(n: usize, t: u16) -> Vec<crate::key_share::Tx25KeyShare> {
        let seed = "90001";

        let parties: Vec<PartyId> = (0..n as u16).map(PartyId).collect();

        let machines: Vec<(PartyId, Tx25KeygenMachine)> = parties
            .iter()
            .map(|&pid| {
                let machine = Tx25KeygenMachine::new(pid, parties.clone(), t, seed, false)
                    .unwrap_or_else(|e| panic!("new() failed for party {pid}: {e}"));
                (pid, machine)
            })
            .collect();

        let orchestrator = tecdsa_testkit::Orchestrator::new(machines, 10);
        let results = orchestrator.run().expect("orchestrator must succeed");

        results
            .into_iter()
            .enumerate()
            .map(|(i, r)| r.unwrap_or_else(|e| panic!("party {i} finish() failed: {e}")))
            .collect()
    }

    #[test]
    fn test_keygen_3_of_2() {
        let shares = run_keygen_state_machine(3, 2);

        let pk0 = shares[0].public_key;
        for share in &shares[1..] {
            assert_eq!(
                pk0, share.public_key,
                "all parties should agree on the joint public key"
            );
        }

        assert_ne!(shares[0].secret_share, shares[1].secret_share);
        assert_ne!(shares[1].secret_share, shares[2].secret_share);

        for share in &shares {
            let expected = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR
                * share.secret_share;
            let my_idx = (share.party_index - 1) as usize;
            assert_eq!(
                share.public_shares[my_idx], expected,
                "public_share should match secret_share * G for party {}",
                share.party_index
            );
        }

        let indices: Vec<u16> = (1..=3).collect();
        let lambdas = tecdsa_vss::lagrange::coefficients::<k256::Secp256k1>(&indices);
        let reconstructed_pk = shares[0].public_shares.iter().zip(lambdas.iter()).fold(
            <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::IDENTITY,
            |acc, (x_j, l_j)| acc + *x_j * l_j,
        );
        assert_eq!(
            pk0, reconstructed_pk,
            "Lagrange reconstruction should match joint PK"
        );
    }

    #[test]
    fn test_keygen_5_of_3() {
        let shares = run_keygen_state_machine(5, 3);

        let pk0 = shares[0].public_key;
        for share in &shares[1..] {
            assert_eq!(pk0, share.public_key);
        }

        for share in &shares {
            let expected = <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::GENERATOR
                * share.secret_share;
            let my_idx = (share.party_index - 1) as usize;
            assert_eq!(share.public_shares[my_idx], expected);
        }

        let indices: Vec<u16> = (1..=5).collect();
        let lambdas = tecdsa_vss::lagrange::coefficients::<k256::Secp256k1>(&indices);
        let reconstructed_pk = shares[0].public_shares.iter().zip(lambdas.iter()).fold(
            <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::IDENTITY,
            |acc, (x_j, l_j)| acc + *x_j * l_j,
        );
        assert_eq!(pk0, reconstructed_pk);

        let subset_indices: Vec<u16> = vec![1, 3, 5];
        let subset_lambdas = tecdsa_vss::lagrange::coefficients::<k256::Secp256k1>(&subset_indices);
        let subset_shares: Vec<k256::ProjectivePoint> = subset_indices
            .iter()
            .map(|&i| shares[0].public_shares[(i - 1) as usize])
            .collect();
        let subset_pk = subset_shares.iter().zip(subset_lambdas.iter()).fold(
            <k256::Secp256k1 as CurveArithmetic>::ProjectivePoint::IDENTITY,
            |acc, (x_j, l_j)| acc + *x_j * l_j,
        );
        assert_eq!(
            pk0, subset_pk,
            "threshold subset should reconstruct same PK"
        );
    }

    #[test]
    fn test_keygen_metadata() {
        let shares = run_keygen_state_machine(3, 2);

        for share in &shares {
            assert_eq!(share.threshold, 2);
            assert_eq!(share.total, 3);
            assert!(!share.cl_setup_seed.is_empty());
        }
        assert_eq!(shares[0].party_index, 1);
        assert_eq!(shares[1].party_index, 2);
        assert_eq!(shares[2].party_index, 3);
    }

    #[test]
    fn keygen_rejects_unknown_party() {
        let seed = "90001";
        let parties: Vec<PartyId> = (0..3u16).map(PartyId).collect();

        let mut machine = Tx25KeygenMachine::new(PartyId(0), parties, 2, seed, false)
            .expect("machine creation should succeed");

        let _out = machine.drain_outgoing();

        let result = machine.handle(PartyId(99), Tx25KeygenMsg::Round1(vec![0u8; 64]));
        let err = result.expect_err("should reject unknown party");
        let msg = format!("{err}");
        assert!(
            msg.contains("unknown party"),
            "error should mention unknown party, got: {msg}"
        );
    }
}
