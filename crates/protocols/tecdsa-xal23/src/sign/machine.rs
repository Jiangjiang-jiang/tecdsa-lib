#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    non_snake_case
)]

use std::collections::BTreeMap;

use elliptic_curve::{sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField};
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{
    state_machine::Outgoing, DataToSign, IaReport, PartyId, Recipient, Signature, StateMachine,
};

use super::msg::Xal23SignMsg;
use crate::presign::Xal23Presignature;

fn scalar_to_bytes<C: TecdsaCurve>(s: &C::Scalar) -> Vec<u8>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let repr = s.to_repr();
    let slice: &[u8] = repr.as_ref();
    slice.to_vec()
}

fn scalar_from_bytes<C: TecdsaCurve>(bytes: &[u8]) -> tecdsa_core::Result<C::Scalar>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    let mut fb = FieldBytes::<C>::default();
    if bytes.len() != fb.len() {
        return Err(TecdsaError::Other(format!(
            "invalid scalar length: expected {}, got {}",
            fb.len(),
            bytes.len()
        )));
    }
    fb.copy_from_slice(bytes);
    <C::Scalar as PrimeField>::from_repr(fb)
        .into_option()
        .ok_or_else(|| TecdsaError::Other("invalid scalar encoding".into()))
}

pub struct Xal23SignMachine<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    my_id: PartyId,
    signer_parties: Vec<PartyId>,
    presig: Xal23Presignature<C>,
    data: DataToSign<C>,
    own_partial: C::Scalar,
    received: BTreeMap<PartyId, C::Scalar>,
    expected: usize,
    outgoing: Vec<Outgoing<Xal23SignMsg>>,
    output: Option<Signature<C>>,
    done: bool,
}

impl<C: TecdsaCurve> Xal23SignMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    pub fn new(presig: Xal23Presignature<C>, data: DataToSign<C>) -> Self {
        let my_id = presig.my_id;
        let signer_parties = presig.signer_parties.clone();
        let expected = signer_parties.len() - 1;

        let m = *data.digest();
        let s_i = m * presig.k_i + presig.r * presig.sigma_i;

        let outgoing = vec![Outgoing {
            to: Recipient::Broadcast,
            msg: Xal23SignMsg::PartialSig(scalar_to_bytes::<C>(&s_i)),
        }];

        Self {
            my_id,
            signer_parties,
            presig,
            data,
            own_partial: s_i,
            received: BTreeMap::new(),
            expected,
            outgoing,
            output: None,
            done: false,
        }
    }

    fn try_combine(&mut self) -> tecdsa_core::Result<()>
    where
        C::ProjectivePoint:
            elliptic_curve::ops::LinearCombination<[(C::ProjectivePoint, C::Scalar); 2]>,
    {
        if self.received.len() < self.expected {
            return Ok(());
        }

        let mut all_partials = Vec::with_capacity(self.signer_parties.len());
        for &pid in &self.signer_parties {
            let s_i = if pid == self.my_id {
                self.own_partial
            } else {
                *self.received.get(&pid).ok_or_else(|| {
                    TecdsaError::Other(format!("missing partial signature from {pid}"))
                })?
            };
            all_partials.push(super::PartialSignature { s_i });
        }

        let sig = super::combine_signatures(&self.presig, &all_partials, &self.data)?;
        self.output = Some(sig);
        self.done = true;
        Ok(())
    }
}

impl<C: TecdsaCurve> StateMachine for Xal23SignMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
    C::ProjectivePoint:
        elliptic_curve::ops::LinearCombination<[(C::ProjectivePoint, C::Scalar); 2]>,
{
    type Output = Signature<C>;
    type Inbound = Xal23SignMsg;
    type Outbound = Xal23SignMsg;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        if self.done {
            return Err(TecdsaError::Other("sign protocol already finished".into()));
        }
        if from == self.my_id {
            return Err(TecdsaError::Other("cannot handle message from self".into()));
        }
        if !self.signer_parties.contains(&from) {
            return Err(TecdsaError::Other(format!("unknown signing party: {from}")));
        }
        if self.received.contains_key(&from) {
            return Err(TecdsaError::DuplicateMessage(from.0));
        }

        match msg {
            Xal23SignMsg::PartialSig(bytes) => {
                let s_j = scalar_from_bytes::<C>(&bytes)?;
                self.received.insert(from, s_j);
                self.try_combine()?;
            }
        }

        Ok(())
    }

    fn drain_outgoing(&mut self) -> Vec<Outgoing<Self::Outbound>> {
        std::mem::take(&mut self.outgoing)
    }

    fn is_done(&self) -> bool {
        self.done
    }

    fn finish(self) -> tecdsa_core::Result<Self::Output> {
        self.output
            .ok_or_else(|| TecdsaError::Other("sign protocol not complete".into()))
    }

    fn current_round(&self) -> u16 {
        if self.done {
            2
        } else {
            1
        }
    }

    fn ia_report(&self) -> Option<&IaReport> {
        None
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::{key_share::trusted_dealer_keygen, presign::presign_all_with_sec};

    type Curve = k256::Secp256k1;

    const TEST_JL_K: u32 = 544;
    const TEST_JL_P_BITS: u64 = 800;
    const TEST_S: u32 = 8;
    const TEST_T: u32 = 8;

    fn hash_message(msg: &[u8]) -> DataToSign<Curve> {
        let hash = Sha256::digest(msg);
        let mut bytes = k256::FieldBytes::default();
        bytes.copy_from_slice(&hash[..32]);
        let scalar = <k256::Scalar as elliptic_curve::PrimeField>::from_repr(bytes)
            .expect("hash should produce valid scalar");
        DataToSign::from_digest(scalar)
    }

    #[test]
    fn sign_machine_n2() {
        let mut rng = rand::thread_rng();
        let key_shares = trusted_dealer_keygen::<Curve>(2, 2, TEST_JL_P_BITS, TEST_JL_K, &mut rng);
        let signer_indices: Vec<usize> = vec![0, 1];

        let presigs =
            presign_all_with_sec::<Curve>(&key_shares, &signer_indices, TEST_S, TEST_T, &mut rng);

        let data = hash_message(b"sign machine test n=2");

        let mut m0 = Xal23SignMachine::new(presigs[0].clone(), data);
        let mut m1 = Xal23SignMachine::new(presigs[1].clone(), data);

        assert!(!m0.is_done());
        assert!(!m1.is_done());
        assert_eq!(m0.current_round(), 1);

        let out0 = m0.drain_outgoing();
        let out1 = m1.drain_outgoing();
        assert_eq!(out0.len(), 1);
        assert_eq!(out1.len(), 1);

        let pid0 = PartyId(0);
        let pid1 = PartyId(1);

        m1.handle(pid0, out0[0].msg.clone())
            .expect("m1 handle should succeed");
        m0.handle(pid1, out1[0].msg.clone())
            .expect("m0 handle should succeed");

        assert!(m0.is_done());
        assert!(m1.is_done());
        assert_eq!(m0.current_round(), 2);

        let sig0 = m0.finish().expect("finish should succeed");
        let sig1 = m1.finish().expect("finish should succeed");
        assert_eq!(sig0.r, sig1.r);
        assert_eq!(sig0.s, sig1.s);

        tecdsa_protocol::verify_ecdsa(&sig0, &key_shares[0].public_key, &data)
            .expect("ECDSA verification should succeed");
    }

    #[test]
    fn sign_machine_n3() {
        let mut rng = rand::thread_rng();
        let key_shares = trusted_dealer_keygen::<Curve>(3, 2, TEST_JL_P_BITS, TEST_JL_K, &mut rng);
        let signer_indices: Vec<usize> = vec![0, 1, 2];

        let presigs =
            presign_all_with_sec::<Curve>(&key_shares, &signer_indices, TEST_S, TEST_T, &mut rng);

        let data = hash_message(b"sign machine test n=3");

        let mut machines: Vec<Xal23SignMachine<Curve>> = presigs
            .into_iter()
            .map(|p| Xal23SignMachine::new(p, data))
            .collect();

        let pids: Vec<PartyId> = signer_indices.iter().map(|&i| PartyId(i as u16)).collect();

        let all_out: Vec<Vec<Outgoing<Xal23SignMsg>>> =
            machines.iter_mut().map(|m| m.drain_outgoing()).collect();

        for (sender_idx, outs) in all_out.iter().enumerate() {
            for out in outs {
                for (recv_idx, machine) in machines.iter_mut().enumerate() {
                    if recv_idx != sender_idx {
                        machine
                            .handle(pids[sender_idx], out.msg.clone())
                            .expect("handle should succeed");
                    }
                }
            }
        }

        for m in &machines {
            assert!(m.is_done());
        }

        let sigs: Vec<_> = machines
            .into_iter()
            .map(|m| m.finish().expect("finish should succeed"))
            .collect();

        assert_eq!(sigs[0].r, sigs[1].r);
        assert_eq!(sigs[0].r, sigs[2].r);
        assert_eq!(sigs[0].s, sigs[1].s);
        assert_eq!(sigs[0].s, sigs[2].s);

        tecdsa_protocol::verify_ecdsa(&sigs[0], &key_shares[0].public_key, &data)
            .expect("ECDSA verification should succeed");
    }

    #[test]
    fn sign_machine_rejects_duplicate() {
        let mut rng = rand::thread_rng();
        let key_shares = trusted_dealer_keygen::<Curve>(2, 2, TEST_JL_P_BITS, TEST_JL_K, &mut rng);
        let signer_indices: Vec<usize> = vec![0, 1];

        let presigs =
            presign_all_with_sec::<Curve>(&key_shares, &signer_indices, TEST_S, TEST_T, &mut rng);

        let data = hash_message(b"duplicate test");

        let mut m0 = Xal23SignMachine::new(presigs[0].clone(), data);
        let mut m1 = Xal23SignMachine::new(presigs[1].clone(), data);

        let out1 = m1.drain_outgoing();
        let pid1 = PartyId(1);

        m0.handle(pid1, out1[0].msg.clone())
            .expect("first handle ok");
        let err = m0.handle(pid1, out1[0].msg.clone());
        assert!(err.is_err(), "duplicate message should be rejected");
    }

    #[test]
    fn sign_machine_rejects_unknown_party() {
        let mut rng = rand::thread_rng();
        let key_shares = trusted_dealer_keygen::<Curve>(2, 2, TEST_JL_P_BITS, TEST_JL_K, &mut rng);
        let signer_indices: Vec<usize> = vec![0, 1];

        let presigs =
            presign_all_with_sec::<Curve>(&key_shares, &signer_indices, TEST_S, TEST_T, &mut rng);

        let data = hash_message(b"unknown party test");
        let mut m0 = Xal23SignMachine::new(presigs[0].clone(), data);

        let fake_msg = Xal23SignMsg::PartialSig(vec![0u8; 32]);
        let err = m0.handle(PartyId(99), fake_msg);
        assert!(err.is_err(), "unknown party should be rejected");
    }
}
