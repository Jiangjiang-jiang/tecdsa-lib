// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2023 Dfns <https://github.com/LFDT-Lockness/cggmp21>

use elliptic_curve::{sec1::ModulusSize, FieldBytesSize};
use serde::{Deserialize, Serialize};
use tecdsa_curve::TecdsaCurve;

pub use crate::zk::common::{Aux, InvalidProof};

/// Public data that both parties know
#[derive(Debug, Clone, Copy, udigest::Digestable)]
#[udigest(bound = "")]
pub struct Data<'a, C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// L in paper, obtained as g^\lambda
    #[udigest(as = &crate::zk::common::encoding::Point)]
    pub l: &'a C::ProjectivePoint,
    /// M in paper, obtained as g^y X^\lambda
    #[udigest(as = &crate::zk::common::encoding::Point)]
    pub m: &'a C::ProjectivePoint,
    /// X in paper
    #[udigest(as = &crate::zk::common::encoding::Point)]
    pub x: &'a C::ProjectivePoint,
    /// Y in paper, obtained as h^y
    #[udigest(as = &crate::zk::common::encoding::Point)]
    pub y: &'a C::ProjectivePoint,
    /// h in paper
    #[udigest(as = &crate::zk::common::encoding::Point)]
    pub h: &'a C::ProjectivePoint,
}

/// Private data of prover
#[derive(Clone, Copy)]
pub struct PrivateData<'a, C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// y or epsilon in paper, log of Y base h
    pub y: &'a C::Scalar,
    /// lambda in paper, preimage of L
    pub lambda: &'a C::Scalar,
}

/// Prover's first message, obtained by [`interactive::commit`]
#[derive(Debug, Clone, udigest::Digestable)]
#[udigest(bound = "")]
#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Commitment<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    #[udigest(as = crate::zk::common::encoding::Point)]
    #[serde(with = "tecdsa_curve::serde_projective")]
    pub a: C::ProjectivePoint,
    #[udigest(as = crate::zk::common::encoding::Point)]
    #[serde(with = "tecdsa_curve::serde_projective")]
    pub n: C::ProjectivePoint,
    #[udigest(as = crate::zk::common::encoding::Point)]
    #[serde(with = "tecdsa_curve::serde_projective")]
    pub b: C::ProjectivePoint,
}

/// Prover's data accompanying the commitment. Kept as state between rounds in
/// the interactive protocol.
#[derive(Clone)]
pub struct PrivateCommitment<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub alpha: C::Scalar,
    pub m: C::Scalar,
}

/// Verifier's challenge to prover. Can be obtained deterministically by
/// [`non_interactive::challenge`] or randomly by [`interactive::challenge`]
pub type Challenge<C> = <C as elliptic_curve::CurveArithmetic>::Scalar;

/// The ZK proof. Computed by [`interactive::prove`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Proof<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    #[serde(with = "tecdsa_curve::serde_scalar")]
    pub z: C::Scalar,
    #[serde(with = "tecdsa_curve::serde_scalar")]
    pub u: C::Scalar,
}

/// The non-interactive ZK proof. Computed by [`non_interactive::prove`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct NiProof<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub commitment: Commitment<C>,
    pub proof: Proof<C>,
}

/// The interactive version of the ZK proof. Should be completed in 3 rounds:
/// prover commits to data, verifier responds with a random challenge, and
/// prover gives proof with commitment and challenge.
pub mod interactive {
    use elliptic_curve::{sec1::ModulusSize, FieldBytesSize};
    use rand_core::CryptoRngCore;
    use tecdsa_curve::TecdsaCurve;

    use super::*;
    use crate::zk::{
        common::{fail_if_ne, InvalidProof, InvalidProofReason},
        Error,
    };

    /// Create random commitment
    pub fn commit<C: TecdsaCurve>(
        data: Data<C>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Commitment<C>, PrivateCommitment<C>), Error>
    where
        FieldBytesSize<C>: ModulusSize,
    {
        let alpha = C::random_scalar(rng);
        let m = C::random_scalar(rng);

        let a = C::generator() * alpha;
        let n = C::generator() * m + *data.x * alpha;
        let b = *data.h * m;

        let commitment = Commitment { a, n, b };
        let private_commitment = PrivateCommitment { alpha, m };
        Ok((commitment, private_commitment))
    }

    /// Compute proof for given data and prior protocol values
    pub fn prove<C: TecdsaCurve>(
        pdata: PrivateData<C>,
        pcomm: &PrivateCommitment<C>,
        challenge: &Challenge<C>,
    ) -> Result<Proof<C>, Error>
    where
        FieldBytesSize<C>: ModulusSize,
    {
        let z = pcomm.alpha + *challenge * *pdata.lambda;
        let u = pcomm.m + *challenge * *pdata.y;
        Ok(Proof { z, u })
    }

    /// Verify the proof
    pub fn verify<C: TecdsaCurve>(
        data: Data<C>,
        commitment: &Commitment<C>,
        challenge: &Challenge<C>,
        proof: &Proof<C>,
    ) -> Result<(), InvalidProof>
    where
        FieldBytesSize<C>: ModulusSize,
    {
        // Three equality checks
        {
            let lhs = C::generator() * proof.z;
            let rhs = commitment.a + *data.l * *challenge;
            fail_if_ne(InvalidProofReason::EqualityCheck(1), lhs, rhs)?;
        }
        {
            let lhs = C::generator() * proof.u + *data.x * proof.z;
            let rhs = commitment.n + *data.m * *challenge;
            fail_if_ne(InvalidProofReason::EqualityCheck(2), lhs, rhs)?;
        }
        {
            let lhs = *data.h * proof.u;
            let rhs = commitment.b + *data.y * *challenge;
            fail_if_ne(InvalidProofReason::EqualityCheck(3), lhs, rhs)?;
        }

        Ok(())
    }

    /// Generate random challenge
    pub fn challenge<C: TecdsaCurve>(rng: &mut impl CryptoRngCore) -> Challenge<C>
    where
        FieldBytesSize<C>: ModulusSize,
    {
        C::random_scalar(rng)
    }
}

/// The non-interactive version of proof. Completed in one round, for example
/// see the documentation of parent module.
pub mod non_interactive {
    use digest::Digest;
    use elliptic_curve::{sec1::ModulusSize, FieldBytesSize};
    use tecdsa_curve::TecdsaCurve;

    use super::{Challenge, Commitment, Data, NiProof, PrivateData};
    use crate::zk::{Error, InvalidProof};

    /// Compute proof for the given data, producing random commitment and
    /// deriving deterministic challenge.
    ///
    /// Obtained from the above interactive proof via Fiat-Shamir heuristic.
    pub fn prove<C: TecdsaCurve, D: Digest>(
        shared_state: &impl udigest::Digestable,
        data: Data<C>,
        pdata: PrivateData<C>,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Result<NiProof<C>, Error>
    where
        FieldBytesSize<C>: ModulusSize,
    {
        let (commitment, pcomm) = super::interactive::commit(data, rng)?;
        let challenge = challenge::<C, D>(shared_state, data, &commitment);
        let proof = super::interactive::prove::<C>(pdata, &pcomm, &challenge)?;
        Ok(NiProof { commitment, proof })
    }

    /// Verify the proof, deriving challenge independently from same data
    pub fn verify<C: TecdsaCurve, D: Digest>(
        shared_state: &impl udigest::Digestable,
        data: Data<C>,
        proof: &NiProof<C>,
    ) -> Result<(), InvalidProof>
    where
        FieldBytesSize<C>: ModulusSize,
    {
        let challenge = challenge::<C, D>(shared_state, data, &proof.commitment);
        super::interactive::verify::<C>(data, &proof.commitment, &challenge, &proof.proof)
    }

    /// Deterministically compute challenge based on prior known values in protocol
    pub fn challenge<C: TecdsaCurve, D: Digest>(
        shared_state: &impl udigest::Digestable,
        data: Data<C>,
        commitment: &Commitment<C>,
    ) -> Challenge<C>
    where
        FieldBytesSize<C>: ModulusSize,
    {
        let tag = "paillier_zk.dlog_with_el_gamal.ni_challenge";
        let seed = udigest::inline_struct!(tag {
            shared_state,
            data,
            commitment,
        });
        let mut rng = rand_hash::HashRng::<D, _>::from_seed(seed);
        super::interactive::challenge::<C>(&mut rng)
    }
}

#[cfg(test)]
mod test {
    use elliptic_curve::{sec1::ModulusSize, FieldBytesSize};
    use sha2::Digest;
    use tecdsa_curve::TecdsaCurve;

    use crate::zk::common::InvalidProofReason;

    fn run<C: TecdsaCurve, D: Digest>(
        rng: &mut impl rand_core::CryptoRngCore,
        data: super::Data<C>,
        pdata: super::PrivateData<C>,
    ) -> Result<(), crate::zk::common::InvalidProof>
    where
        FieldBytesSize<C>: ModulusSize,
    {
        let shared_state = "shared state";

        let proof = super::non_interactive::prove::<C, D>(&shared_state, data, pdata, rng).unwrap();
        super::non_interactive::verify::<C, D>(&shared_state, data, &proof)
    }

    fn passing_test<C: TecdsaCurve, D: Digest>()
    where
        FieldBytesSize<C>: ModulusSize,
    {
        let mut rng = rand_dev::DevRng::new();

        let pdata = super::PrivateData {
            y: &C::random_scalar(&mut rng),
            lambda: &C::random_scalar(&mut rng),
        };

        let h = C::generator() * C::random_scalar(&mut rng);
        let x = C::generator() * C::random_scalar(&mut rng);

        let data = super::Data {
            l: &(C::generator() * pdata.lambda),
            m: &(C::generator() * pdata.y + x * pdata.lambda),
            x: &x,
            y: &(h * pdata.y),
            h: &h,
        };
        run::<C, D>(&mut rng, data, pdata).expect("proof failed");
    }

    fn failing_check_lambda_<C: TecdsaCurve, D: Digest>()
    where
        FieldBytesSize<C>: ModulusSize,
    {
        // Scenario where the prover P does not know lambda
        let mut rng = rand_dev::DevRng::new();

        let mut pdata = super::PrivateData {
            y: &C::random_scalar(&mut rng),
            lambda: &C::random_scalar(&mut rng),
        };

        let h = C::generator() * C::random_scalar(&mut rng);
        let x = C::generator() * C::random_scalar(&mut rng);

        let data = super::Data {
            l: &(C::generator() * pdata.lambda),
            m: &(C::generator() * pdata.y + x * pdata.lambda),
            x: &x,
            y: &(h * pdata.y),
            h: &h,
        };

        // Replace lambda with another value
        let fake_lambda = C::random_scalar(&mut rng);
        pdata.lambda = &fake_lambda;

        let err = run::<C, D>(&mut rng, data, pdata).expect_err("proof should not pass");
        match err.reason() {
            InvalidProofReason::EqualityCheck(1) => (),
            e => panic!("proof should not fail with {e:?}"),
        }
    }

    fn failing_check_y_<C: TecdsaCurve, D: Digest>()
    where
        FieldBytesSize<C>: ModulusSize,
    {
        // Scenario where the prover P does not know y
        let mut rng = rand_dev::DevRng::new();

        let mut pdata = super::PrivateData {
            y: &C::random_scalar(&mut rng),
            lambda: &C::random_scalar(&mut rng),
        };

        let h = C::generator() * C::random_scalar(&mut rng);
        let x = C::generator() * C::random_scalar(&mut rng);

        let data = super::Data {
            l: &(C::generator() * pdata.lambda),
            m: &(C::generator() * pdata.y + x * pdata.lambda),
            x: &x,
            y: &(h * pdata.y),
            h: &h,
        };

        // Replace y with another value
        let fake_y = C::random_scalar(&mut rng);
        pdata.y = &fake_y;

        let r = run::<C, D>(&mut rng, data, pdata).expect_err("proof should not pass");
        match r.reason() {
            InvalidProofReason::EqualityCheck(2) => (),
            e => panic!("proof should not fail with {e:?}"),
        }
    }

    #[test]
    fn passing_p256() {
        passing_test::<p256::NistP256, sha2::Sha256>()
    }

    #[test]
    fn failing_check_1_p256() {
        failing_check_lambda_::<p256::NistP256, sha2::Sha256>()
    }

    #[test]
    fn failing_check_2_p256() {
        failing_check_y_::<p256::NistP256, sha2::Sha256>()
    }
}
