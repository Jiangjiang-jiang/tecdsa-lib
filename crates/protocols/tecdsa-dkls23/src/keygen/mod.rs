pub mod msg;
mod rounds;

use elliptic_curve::{sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField};
use msg::Dkls23KeygenMsg;
use rand_core::CryptoRngCore;
use rounds::{KeygenConfig, KeygenRound, Round1State};
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_protocol::{state_machine::Outgoing, IaReport, PartyId, StateMachine};

use crate::key_share::Dkls23KeyShare;

pub struct Dkls23KeygenMachine<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    round: KeygenRound<C>,
}

impl<C: TecdsaCurve> Dkls23KeygenMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    #[must_use]
    pub fn new(
        my_id: PartyId,
        all_parties: Vec<PartyId>,
        threshold: u16,
        rng: &mut impl CryptoRngCore,
    ) -> Self {
        let total = all_parties.len() as u16;
        let config = KeygenConfig {
            my_id,
            all_parties,
            threshold,
            total,
        };

        let state = Round1State::<C>::new(config, rng);
        Self {
            round: KeygenRound::Round1(state),
        }
    }
}

impl<C: TecdsaCurve> StateMachine for Dkls23KeygenMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    type Output = Dkls23KeyShare<C>;
    type Inbound = Dkls23KeygenMsg;
    type Outbound = Dkls23KeygenMsg;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        match &mut self.round {
            KeygenRound::Round1(state) => match msg {
                Dkls23KeygenMsg::Round1Broadcast(m) => {
                    state.handle(from, m)?;
                    if state.is_ready() {
                        let old = std::mem::take(&mut self.round);
                        if let KeygenRound::Round1(s) = old {
                            self.round = KeygenRound::Round2(s.advance());
                        }
                    }
                    Ok(())
                }
                _ => Err(TecdsaError::RoundMismatch {
                    expected: 1,
                    got: msg_round(&msg),
                }),
            },
            KeygenRound::Round2(state) => match msg {
                Dkls23KeygenMsg::Round2Broadcast(m) => {
                    state.handle_broadcast(from, m)?;
                    if state.is_ready() {
                        let old = std::mem::take(&mut self.round);
                        if let KeygenRound::Round2(s) = old {
                            self.round = KeygenRound::Done(s.advance().finish()?);
                        }
                    }
                    Ok(())
                }
                Dkls23KeygenMsg::Round2P2p(m) => {
                    state.handle_p2p(from, m)?;
                    if state.is_ready() {
                        let old = std::mem::take(&mut self.round);
                        if let KeygenRound::Round2(s) = old {
                            self.round = KeygenRound::Done(s.advance().finish()?);
                        }
                    }
                    Ok(())
                }
                _ => Err(TecdsaError::RoundMismatch {
                    expected: 2,
                    got: msg_round(&msg),
                }),
            },
            KeygenRound::Round3(_) => {
                Err(TecdsaError::Other(
                    "round 3 does not accept messages".into(),
                ))
            }
            KeygenRound::Done(_) | KeygenRound::Poisoned => {
                Err(TecdsaError::Other("protocol already finished".into()))
            }
        }
    }

    fn drain_outgoing(&mut self) -> Vec<Outgoing<Self::Outbound>> {
        match &mut self.round {
            KeygenRound::Round1(state) => std::mem::take(&mut state.outgoing),
            KeygenRound::Round2(state) => std::mem::take(&mut state.outgoing),
            KeygenRound::Round3(state) => std::mem::take(&mut state.outgoing),
            KeygenRound::Done(_) | KeygenRound::Poisoned => Vec::new(),
        }
    }

    fn is_done(&self) -> bool {
        matches!(self.round, KeygenRound::Done(_))
    }

    fn finish(self) -> tecdsa_core::Result<Self::Output> {
        match self.round {
            KeygenRound::Done(share) => Ok(share),
            _ => Err(TecdsaError::Other("protocol not yet complete".into())),
        }
    }

    fn current_round(&self) -> u16 {
        match &self.round {
            KeygenRound::Round1(_) => 1,
            KeygenRound::Round2(_) => 2,
            KeygenRound::Round3(_) => 3,
            KeygenRound::Done(_) => 4,
            KeygenRound::Poisoned => 0,
        }
    }

    fn ia_report(&self) -> Option<&IaReport> {
        None
    }
}

fn msg_round(msg: &Dkls23KeygenMsg) -> u16 {
    match msg {
        Dkls23KeygenMsg::Round1Broadcast(_) => 1,
        Dkls23KeygenMsg::Round2Broadcast(_) | Dkls23KeygenMsg::Round2P2p(_) => 2,
    }
}

#[cfg(test)]
mod tests {
    use elliptic_curve::{group::GroupEncoding, Field};
    use tecdsa_testkit::Orchestrator;

    use super::*;

    type TestCurve = k256::Secp256k1;

    #[test]
    fn keygen_2_of_3() {
        let mut rng = rand::thread_rng();
        let t = 2u16;
        let n = 3u16;

        let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();

        let mut machines: Vec<(PartyId, Dkls23KeygenMachine<TestCurve>)> = Vec::new();
        for &pid in &all_parties {
            let machine = Dkls23KeygenMachine::new(pid, all_parties.clone(), t, &mut rng);
            machines.push((pid, machine));
        }

        let results = Orchestrator::new(machines, 10)
            .run()
            .expect("orchestrator must succeed");

        let shares: Vec<Dkls23KeyShare<TestCurve>> = results
            .into_iter()
            .map(|r| r.expect("keygen should succeed"))
            .collect();

        let pk0_bytes = shares[0].public_key.to_bytes();
        for (i, share) in shares.iter().enumerate().skip(1) {
            assert_eq!(
                share.public_key.to_bytes(),
                pk0_bytes,
                "party {} and party 0 disagree on public key",
                i
            );
        }

        for share in &shares {
            let j = (share.party_index - 1) as usize;
            let share_g =
                <k256::Secp256k1 as elliptic_curve::CurveArithmetic>::ProjectivePoint::GENERATOR
                    * share.shamir_share;
            assert_eq!(
                share_g.to_bytes(),
                share.verification_shares[j].to_bytes(),
                "party {} share consistency check failed: share_j * G != V_j",
                share.party_index
            );
        }

        for (i, share) in shares.iter().enumerate().skip(1) {
            for (j, vs) in share.verification_shares.iter().enumerate() {
                assert_eq!(
                    vs.to_bytes(),
                    shares[0].verification_shares[j].to_bytes(),
                    "party {i} and party 0 disagree on verification_shares[{j}]"
                );
            }
        }

        let indices: Vec<u16> = shares.iter().map(|s| s.party_index).collect();
        let reconstruction_shares: Vec<_> = shares.iter().map(|s| s.shamir_share).collect();

        let sk = lagrange_interpolate_at_zero::<TestCurve>(
            &indices[..t as usize],
            &reconstruction_shares[..t as usize],
        );
        let pk_reconstructed =
            <k256::Secp256k1 as elliptic_curve::CurveArithmetic>::ProjectivePoint::GENERATOR * sk;
        assert_eq!(
            pk_reconstructed.to_bytes(),
            pk0_bytes,
            "Lagrange reconstruction of first t shares should give the public key"
        );

        let sk2 =
            lagrange_interpolate_at_zero::<TestCurve>(&indices[1..], &reconstruction_shares[1..]);
        let pk_reconstructed2 =
            <k256::Secp256k1 as elliptic_curve::CurveArithmetic>::ProjectivePoint::GENERATOR * sk2;
        assert_eq!(
            pk_reconstructed2.to_bytes(),
            pk0_bytes,
            "Lagrange reconstruction of last t shares should give the public key"
        );
    }

    #[test]
    fn keygen_3_of_5() {
        let mut rng = rand::thread_rng();
        let t = 3u16;
        let n = 5u16;

        let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();

        let mut machines: Vec<(PartyId, Dkls23KeygenMachine<TestCurve>)> = Vec::new();
        for &pid in &all_parties {
            let machine = Dkls23KeygenMachine::new(pid, all_parties.clone(), t, &mut rng);
            machines.push((pid, machine));
        }

        let results = Orchestrator::new(machines, 10)
            .run()
            .expect("orchestrator must succeed");
        let shares: Vec<Dkls23KeyShare<TestCurve>> = results
            .into_iter()
            .map(|r| r.expect("keygen should succeed"))
            .collect();

        let pk0_bytes = shares[0].public_key.to_bytes();
        for (i, share) in shares.iter().enumerate().skip(1) {
            assert_eq!(
                share.public_key.to_bytes(),
                pk0_bytes,
                "party {} disagrees on public key",
                i
            );
        }

        for share in &shares {
            let j = (share.party_index - 1) as usize;
            let share_g =
                <k256::Secp256k1 as elliptic_curve::CurveArithmetic>::ProjectivePoint::GENERATOR
                    * share.shamir_share;
            assert_eq!(
                share_g.to_bytes(),
                share.verification_shares[j].to_bytes(),
                "party {} share consistency check failed",
                share.party_index
            );
        }

        let indices: Vec<u16> = shares.iter().map(|s| s.party_index).collect();
        let reconstruction_shares: Vec<_> = shares.iter().map(|s| s.shamir_share).collect();

        let subset_idx = [indices[0], indices[2], indices[4]];
        let subset_shares = [
            reconstruction_shares[0],
            reconstruction_shares[2],
            reconstruction_shares[4],
        ];
        let sk = lagrange_interpolate_at_zero::<TestCurve>(&subset_idx, &subset_shares);
        let pk_reconstructed =
            <k256::Secp256k1 as elliptic_curve::CurveArithmetic>::ProjectivePoint::GENERATOR * sk;
        assert_eq!(
            pk_reconstructed.to_bytes(),
            pk0_bytes,
            "Lagrange reconstruction of t=3 shares (1,3,5) should give the public key"
        );
    }

    fn lagrange_interpolate_at_zero<C: TecdsaCurve>(
        indices: &[u16],
        shares: &[C::Scalar],
    ) -> C::Scalar
    where
        FieldBytesSize<C>: ModulusSize,
        C::Scalar: PrimeField<Repr = FieldBytes<C>>,
    {
        assert_eq!(indices.len(), shares.len());
        let n = indices.len();
        let mut result = C::Scalar::ZERO;

        for i in 0..n {
            let i_scalar = scalar_from_u16::<C>(indices[i]);
            let mut lambda = C::Scalar::ONE;

            for j in 0..n {
                if i == j {
                    continue;
                }
                let j_scalar = scalar_from_u16::<C>(indices[j]);
                let neg_j = -j_scalar;
                let i_minus_j = i_scalar - j_scalar;
                let inv = i_minus_j
                    .invert()
                    .into_option()
                    .expect("distinct indices must be invertible");
                lambda *= neg_j * inv;
            }

            result += shares[i] * lambda;
        }

        result
    }

    fn scalar_from_u16<C: TecdsaCurve>(val: u16) -> C::Scalar
    where
        FieldBytesSize<C>: ModulusSize,
        C::Scalar: PrimeField<Repr = FieldBytes<C>>,
    {
        let mut repr = FieldBytes::<C>::default();
        let bytes = (val as u64).to_be_bytes();
        let repr_len = repr.len();
        if repr_len >= 8 {
            repr[repr_len - 8..].copy_from_slice(&bytes);
        }
        C::Scalar::from_repr(repr).expect("small u16 value must be a valid scalar")
    }
}
