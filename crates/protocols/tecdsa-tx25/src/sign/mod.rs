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
    clippy::too_many_arguments,
    non_snake_case
)]

pub mod machine;
pub mod msg;
pub mod rounds;

pub use machine::Tx25OnlineSignMachine;
pub use msg::Tx25OnlineSignMsg;

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use tecdsa_curve::{
        zk::ddh::{DdhProof, DdhStatement, DdhWitness},
        TecdsaCurve,
    };
    use tecdsa_protocol::{
        ecdsa::{low_s_normalize, verify_ecdsa, DataToSign, Signature},
        state_machine::Outgoing,
        PartyId, Recipient, StateMachine,
    };

    use super::{
        machine::Tx25OnlineSignMachine,
        msg::{deserialize_online_msg, serialize_online_msg, OnlineRoundMsg, Tx25OnlineSignMsg},
        rounds::{assemble_signature, hash_message_to_scalar, lagrange_coeff, zero_poly_eval},
    };
    use crate::presign::Tx25Presignature;

    fn mock_presignature(
        party_index: u16,
        party_ids: &[u16],
        k_shares: &BTreeMap<u16, k256::Scalar>,
        gamma_shares: &BTreeMap<u16, k256::Scalar>,
        x_shares: &BTreeMap<u16, k256::Scalar>,
        r_point: k256::ProjectivePoint,
        r_x: k256::Scalar,
        threshold: u16,
    ) -> Tx25Presignature {
        let k_i = k_shares[&party_index];

        let mut delta_shares = BTreeMap::new();
        let mut zeta_shares = BTreeMap::new();

        for &pid in party_ids {
            delta_shares.insert(pid, k_i * gamma_shares[&pid]);
            zeta_shares.insert(pid, k_i * x_shares[&pid]);
        }

        let b_points = BTreeMap::new();
        let b_hat_points = BTreeMap::new();

        Tx25Presignature {
            r_point,
            r_x,
            k_share: k_i,
            gamma_i: gamma_shares[&party_index],
            sigma_share: k256::Scalar::ZERO,
            delta_shares,
            zeta_shares,
            b_points,
            b_hat_points,
            party_index,
            threshold,
        }
    }

    #[test]
    fn test_lagrange_coefficients_sum_to_one() {
        let party_ids = vec![1u16, 2, 3];
        let sum: k256::Scalar = party_ids
            .iter()
            .map(|&i| lagrange_coeff(&party_ids, i))
            .sum();
        assert_eq!(
            sum,
            k256::Scalar::ONE,
            "Lagrange coefficients must sum to 1"
        );
    }

    #[test]
    fn test_lagrange_reconstructs_secret() {
        let mut rng = rand::thread_rng();
        let secret = k256::Secp256k1::random_scalar(&mut rng);
        let party_ids = vec![1u16, 2, 3];

        let a1 = k256::Secp256k1::random_scalar(&mut rng);
        let a2 = k256::Secp256k1::random_scalar(&mut rng);

        let shares: BTreeMap<u16, k256::Scalar> = party_ids
            .iter()
            .map(|&pid| {
                let x = k256::Scalar::from(u64::from(pid));
                (pid, secret + a1 * x + a2 * x * x)
            })
            .collect();

        let reconstructed: k256::Scalar = party_ids
            .iter()
            .map(|&i| lagrange_coeff(&party_ids, i) * shares[&i])
            .sum();

        assert_eq!(
            reconstructed, secret,
            "Lagrange must reconstruct the secret"
        );
    }

    #[test]
    fn test_zero_poly_eval_sums_to_zero() {
        let mut rng = rand::thread_rng();
        let party_ids = vec![1u16, 2, 3];
        let evals = zero_poly_eval(3, &party_ids, &mut rng);

        let sum: k256::Scalar = party_ids
            .iter()
            .map(|&i| lagrange_coeff(&party_ids, i) * evals[&i])
            .sum();

        assert_eq!(
            sum,
            k256::Scalar::ZERO,
            "Zero-sharing polynomial evaluations must reconstruct to zero"
        );
    }

    #[test]
    fn test_online_sign_roundtrip() {
        let mut rng = rand::thread_rng();
        let party_ids = vec![1u16, 2, 3];
        let _n = party_ids.len();
        let t = 2u16;

        let x_shares: BTreeMap<u16, k256::Scalar> = party_ids
            .iter()
            .map(|&pid| (pid, k256::Secp256k1::random_scalar(&mut rng)))
            .collect();

        let x: k256::Scalar = party_ids
            .iter()
            .map(|&i| lagrange_coeff(&party_ids, i) * x_shares[&i])
            .sum();

        let g = k256::Secp256k1::generator();
        let public_key = g * x;

        let k_shares: BTreeMap<u16, k256::Scalar> = party_ids
            .iter()
            .map(|&pid| (pid, k256::Secp256k1::random_scalar(&mut rng)))
            .collect();

        let k: k256::Scalar = party_ids
            .iter()
            .map(|&i| lagrange_coeff(&party_ids, i) * k_shares[&i])
            .sum();

        let r_point = g * k;
        let r_affine = r_point.to_affine();
        let r_x = k256::Secp256k1::xcoord_mod_q(&r_affine);

        let gamma_shares = k_shares.clone();

        let message = b"test message for TX25 online sign";

        let presigs: BTreeMap<u16, Tx25Presignature> = party_ids
            .iter()
            .map(|&pid| {
                let presig = mock_presignature(
                    pid,
                    &party_ids,
                    &k_shares,
                    &gamma_shares,
                    &x_shares,
                    r_point,
                    r_x,
                    t,
                );
                (pid, presig)
            })
            .collect();

        let all_parties: Vec<PartyId> = party_ids.iter().map(|&p| PartyId(p)).collect();

        let mut machines: BTreeMap<u16, Tx25OnlineSignMachine> = BTreeMap::new();
        let mut all_outgoing: BTreeMap<u16, Vec<Outgoing<Tx25OnlineSignMsg>>> = BTreeMap::new();

        for &pid in &party_ids {
            let presig = presigs.get(&pid).unwrap().clone();
            let mut machine = Tx25OnlineSignMachine::new(
                PartyId(pid),
                all_parties.clone(),
                presig,
                message,
                public_key,
            )
            .expect("machine creation should succeed");

            let out = machine.drain_outgoing();
            all_outgoing.insert(pid, out);
            machines.insert(pid, machine);
        }

        for &sender in &party_ids {
            let outgoing = all_outgoing.remove(&sender).unwrap();
            for out_msg in outgoing {
                match out_msg.to {
                    Recipient::Party(to) => {
                        let machine = machines.get_mut(&to.0).unwrap();
                        machine
                            .handle(PartyId(sender), out_msg.msg.clone())
                            .expect("handle should succeed");
                    }
                    Recipient::Broadcast => {
                        for &pid in &party_ids {
                            if pid != sender {
                                let machine = machines.get_mut(&pid).unwrap();
                                machine
                                    .handle(PartyId(sender), out_msg.msg.clone())
                                    .expect("handle should succeed");
                            }
                        }
                    }
                }
            }
        }

        for (&pid, machine) in &machines {
            assert!(machine.is_done(), "machine for party {pid} should be done");
        }

        let mut sigs = Vec::new();
        for pid in &party_ids {
            let machine = machines.remove(pid).unwrap();
            let sig = machine.finish().expect("finish should succeed");
            sigs.push(sig);
        }

        for i in 1..sigs.len() {
            assert_eq!(sigs[0].r, sigs[i].r, "r values must match");
            assert_eq!(sigs[0].s, sigs[i].s, "s values must match");
        }
    }

    #[test]
    fn test_assembly_math_directly() {
        let mut rng = rand::thread_rng();
        let party_ids = vec![1u16, 2, 3];
        let g = k256::Secp256k1::generator();

        let x_shares: BTreeMap<u16, k256::Scalar> = party_ids
            .iter()
            .map(|&pid| (pid, k256::Secp256k1::random_scalar(&mut rng)))
            .collect();
        let x: k256::Scalar = party_ids
            .iter()
            .map(|&i| lagrange_coeff(&party_ids, i) * x_shares[&i])
            .sum();
        let public_key = g * x;

        let k_shares: BTreeMap<u16, k256::Scalar> = party_ids
            .iter()
            .map(|&pid| (pid, k256::Secp256k1::random_scalar(&mut rng)))
            .collect();
        let k: k256::Scalar = party_ids
            .iter()
            .map(|&i| lagrange_coeff(&party_ids, i) * k_shares[&i])
            .sum();

        let r_point = g * k;
        let r_x = k256::Secp256k1::xcoord_mod_q(&r_point.to_affine());

        let gamma_shares = k_shares.clone();

        let m = hash_message_to_scalar(b"test");

        let mut all_deltas: BTreeMap<u16, BTreeMap<u16, k256::Scalar>> = BTreeMap::new();
        let mut all_chis: BTreeMap<u16, BTreeMap<u16, k256::Scalar>> = BTreeMap::new();

        for &j in &party_ids {
            let mut deltas_j = BTreeMap::new();
            let mut chis_j = BTreeMap::new();
            for &nu in &party_ids {
                deltas_j.insert(nu, k_shares[&j] * gamma_shares[&nu]);
                chis_j.insert(
                    nu,
                    m * gamma_shares[&j] + r_x * k_shares[&j] * x_shares[&nu],
                );
            }
            all_deltas.insert(j, deltas_j);
            all_chis.insert(j, chis_j);
        }

        let s_raw = assemble_signature(&party_ids, &all_deltas, &all_chis)
            .expect("assembly should succeed");

        let k_inv = k.invert().unwrap();
        let expected_s = (m + r_x * x) * k_inv;

        let s = low_s_normalize::<k256::Secp256k1>(s_raw);
        let expected_s_norm = low_s_normalize::<k256::Secp256k1>(expected_s);
        assert_eq!(s, expected_s_norm, "assembled s must match expected");

        let sig = Signature { r: r_x, s };
        let msg_data = DataToSign::from_digest(m);
        verify_ecdsa::<k256::Secp256k1>(&sig, &public_key, &msg_data)
            .expect("ECDSA verification should pass");
    }

    #[test]
    fn test_serialize_deserialize_roundtrip() {
        let mut rng = rand::thread_rng();

        let mut delta_shares = BTreeMap::new();
        let mut chi_shares = BTreeMap::new();
        for pid in [1u16, 2, 3] {
            delta_shares.insert(pid, k256::Secp256k1::random_scalar(&mut rng));
            chi_shares.insert(pid, k256::Secp256k1::random_scalar(&mut rng));
        }

        let g = k256::Secp256k1::generator();
        let w = k256::Secp256k1::random_scalar(&mut rng);
        let a_scalar = k256::Secp256k1::random_scalar(&mut rng);
        let a = g * a_scalar;
        let b = g * w;
        let c = a * w;

        let stmt = DdhStatement::<k256::Secp256k1> { g, a, b, c };
        let wit = DdhWitness::<k256::Secp256k1> { w };
        let proof = DdhProof::prove(&stmt, &wit, &mut rng);

        let msg = OnlineRoundMsg {
            delta_shares,
            chi_shares,
            d_point: b,
            gamma_point: c,
            ddh_proof: proof,
        };

        let serialized = serialize_online_msg(&msg);
        let deserialized =
            deserialize_online_msg(&serialized).expect("deserialization should succeed");

        assert_eq!(msg.delta_shares.len(), deserialized.delta_shares.len());
        for (&pid, &val) in &msg.delta_shares {
            assert_eq!(val, deserialized.delta_shares[&pid]);
        }
        for (&pid, &val) in &msg.chi_shares {
            assert_eq!(val, deserialized.chi_shares[&pid]);
        }
        assert_eq!(msg.d_point, deserialized.d_point);
        assert_eq!(msg.gamma_point, deserialized.gamma_point);
        assert!(deserialized.ddh_proof.verify(&stmt));
    }

    #[test]
    fn online_sign_rejects_self_message() {
        let mut rng = rand::thread_rng();
        let party_ids = vec![1u16, 2, 3];
        let t = 2u16;

        let x_shares: BTreeMap<u16, k256::Scalar> = party_ids
            .iter()
            .map(|&pid| (pid, k256::Secp256k1::random_scalar(&mut rng)))
            .collect();
        let k_shares: BTreeMap<u16, k256::Scalar> = party_ids
            .iter()
            .map(|&pid| (pid, k256::Secp256k1::random_scalar(&mut rng)))
            .collect();
        let gamma_shares = k_shares.clone();

        let x: k256::Scalar = party_ids
            .iter()
            .map(|&i| lagrange_coeff(&party_ids, i) * x_shares[&i])
            .sum();
        let k: k256::Scalar = party_ids
            .iter()
            .map(|&i| lagrange_coeff(&party_ids, i) * k_shares[&i])
            .sum();
        let g = k256::Secp256k1::generator();
        let public_key = g * x;
        let r_point = g * k;
        let r_affine = r_point.to_affine();
        let r_x = k256::Secp256k1::xcoord_mod_q(&r_affine);

        let presig = mock_presignature(
            1,
            &party_ids,
            &k_shares,
            &gamma_shares,
            &x_shares,
            r_point,
            r_x,
            t,
        );
        let all_parties: Vec<PartyId> = party_ids.iter().map(|&p| PartyId(p)).collect();
        let message = b"test self-message rejection";

        let mut machine =
            Tx25OnlineSignMachine::new(PartyId(1), all_parties, presig, message, public_key)
                .expect("machine creation should succeed");

        let _out = machine.drain_outgoing();

        let result = machine.handle(PartyId(1), Tx25OnlineSignMsg::Online(vec![0u8; 64]));
        let err = result.expect_err("should reject self-message");
        let msg = format!("{err}");
        assert!(
            msg.contains("from self"),
            "error should mention from self, got: {msg}"
        );
    }
}
