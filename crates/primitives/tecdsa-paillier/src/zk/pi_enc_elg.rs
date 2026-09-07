// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2023 Dfns <https://github.com/LFDT-Lockness/cggmp21>

use elliptic_curve::{sec1::ModulusSize, FieldBytesSize};
use rug::Integer;
use serde::{Deserialize, Serialize};
use tecdsa_curve::TecdsaCurve;

use crate::scheme::{AnyEncryptionKey, Ciphertext, Nonce, Plaintext};
pub use crate::zk::common::{Aux, InvalidProof};

/// Security parameters for proof. Choosing the values is a tradeoff between
/// security, speed and correctness
#[derive(Debug, Clone, udigest::Digestable, Serialize, Deserialize)]
pub struct SecurityParams {
    /// $\ell$ in paper
    pub l: usize,
    /// $\varepsilon$ in paper, slackness parameter
    pub epsilon: usize,
}

/// Public data that both parties know
#[derive(Debug, Clone, Copy, udigest::Digestable)]
#[udigest(bound = "")]
pub struct Data<'a, C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// $N_0$ in paper
    #[udigest(as = crate::zk::common::encoding::AnyEncryptionKey)]
    pub key: &'a dyn AnyEncryptionKey,
    /// $C$ in paper
    #[udigest(as = &crate::zk::common::encoding::Integer)]
    pub ciphertext: &'a Ciphertext,
    /// $A$ in paper
    #[udigest(as = &crate::zk::common::encoding::Point)]
    pub a: &'a C::ProjectivePoint,
    /// $B$ in paper
    #[udigest(as = &crate::zk::common::encoding::Point)]
    pub b: &'a C::ProjectivePoint,
    /// $X$ in paper
    #[udigest(as = &crate::zk::common::encoding::Point)]
    pub x: &'a C::ProjectivePoint,
}

/// Private data of prover
#[derive(Clone, Copy)]
pub struct PrivateData<'a, C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    /// $x$ in paper
    pub plaintext: &'a Plaintext,
    /// $\rho$ in paper
    pub nonce: &'a Nonce,
    /// $b$ in paper
    pub b: &'a C::Scalar,
}

/// Prover's public commitment
#[derive(Debug, Clone, udigest::Digestable)]
#[udigest(bound = "")]
#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Commitment<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    #[udigest(as = crate::zk::common::encoding::Integer)]
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub s: Integer,
    #[udigest(as = crate::zk::common::encoding::Integer)]
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub t: Integer,
    #[udigest(as = crate::zk::common::encoding::Integer)]
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub d: Integer,
    #[udigest(as = crate::zk::common::encoding::Point)]
    #[serde(with = "tecdsa_curve::serde_projective")]
    pub y: C::ProjectivePoint,
    #[udigest(as = crate::zk::common::encoding::Point)]
    #[serde(with = "tecdsa_curve::serde_projective")]
    pub z: C::ProjectivePoint,
}

/// Prover's secret commitment nonce
#[derive(Clone)]
pub struct PrivateCommitment<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    pub alpha: Integer,
    pub mu: Integer,
    pub r: Integer,
    pub beta: C::Scalar,
    pub gamma: Integer,
}

/// Verifier's challenge to prover. Can be obtained deterministically by
/// [`non_interactive::challenge`] or randomly by [`interactive::challenge`]
pub type Challenge = Integer;

/// Range Proof with El-Gamal commitment. Computed by [`interactive::prove`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Proof<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub z1: Integer,
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub z2: Integer,
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub z3: Integer,
    #[serde(with = "tecdsa_curve::serde_scalar")]
    pub w: C::Scalar,
}

/// The non-interactive ZK proof. Computed by [`non_interactive::prove`].
/// Combines commitment and proof.
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
    use rand_core::{CryptoRngCore, RngCore};
    use rug::Integer;
    use tecdsa_bigint::BigIntExt;
    use tecdsa_curve::TecdsaCurve;

    use super::{
        Aux, Challenge, Commitment, Data, PrivateCommitment, PrivateData, Proof, SecurityParams,
    };
    use crate::zk::{
        common::{fail_if, fail_if_ne, InvalidProof, InvalidProofReason},
        BadExponent, Error,
    };

    /// Create random commitment
    pub fn commit<C: TecdsaCurve>(
        aux: &Aux,
        data: Data<C>,
        pdata: PrivateData<C>,
        security: &SecurityParams,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Commitment<C>, PrivateCommitment<C>), Error>
    where
        FieldBytesSize<C>: ModulusSize,
    {
        let two_to_l_plus_e = Integer::one() << (security.l + security.epsilon);
        let n_j_at_two_to_l = (Integer::one() << security.l) * &aux.rsa_modulo;
        let n_j_at_two_to_l_plus_e = Integer::from(&two_to_l_plus_e * &aux.rsa_modulo);

        let alpha = Integer::from_rng_half_pm(rng, &two_to_l_plus_e);
        let mu = Integer::from_rng_half_pm(rng, &n_j_at_two_to_l);
        let r = Integer::sample_in_mult_group_of(rng, data.key.n());
        let beta = C::random_scalar(rng);
        let gamma = Integer::from_rng_half_pm(rng, &n_j_at_two_to_l_plus_e);

        let s = aux.combine(pdata.plaintext, &mu)?;
        let t = aux.combine(&alpha, &gamma)?;
        let d = data.key.encrypt_with(&alpha, &r)?;
        let y = *data.a * beta + C::generator() * C::scalar_from_integer(&alpha);
        let z = C::generator() * beta;

        Ok((
            Commitment { s, t, d, y, z },
            PrivateCommitment {
                alpha,
                mu,
                r,
                beta,
                gamma,
            },
        ))
    }

    /// Compute proof for given data and prior protocol values
    pub fn prove<C: TecdsaCurve>(
        data: Data<C>,
        pdata: PrivateData<C>,
        private_commitment: &PrivateCommitment<C>,
        challenge: &Challenge,
    ) -> Result<Proof<C>, Error>
    where
        FieldBytesSize<C>: ModulusSize,
    {
        let z1 = Integer::from(&private_commitment.alpha + (challenge * pdata.plaintext));
        let z2 = {
            let nonce_to_challenge_mod_n: Integer = pdata
                .nonce
                .pow_mod_ref(challenge, data.key.n())
                .map(Integer::from)
                .ok_or(BadExponent::undefined())?;
            (&private_commitment.r * nonce_to_challenge_mod_n).modulo(data.key.n())
        };
        let z3 = Integer::from(&private_commitment.gamma + (challenge * &private_commitment.mu));
        let w = private_commitment.beta + (C::scalar_from_integer(challenge) * *pdata.b);
        Ok(Proof { z1, z2, z3, w })
    }

    /// Verify the proof
    pub fn verify<C: TecdsaCurve>(
        aux: &Aux,
        data: Data<C>,
        commitment: &Commitment<C>,
        security: &SecurityParams,
        challenge: &Challenge,
        proof: &Proof<C>,
    ) -> Result<(), InvalidProof>
    where
        FieldBytesSize<C>: ModulusSize,
    {
        // Verify that inputs are in expected domains:
        fail_if(
            InvalidProofReason::RangeCheck(1),
            data.ciphertext.in_mult_group_of(data.key.nn()),
        )?;
        fail_if(
            InvalidProofReason::RangeCheck(2),
            aux.is_in_mult_group(&commitment.s),
        )?;
        fail_if(
            InvalidProofReason::RangeCheck(3),
            aux.is_in_mult_group(&commitment.t),
        )?;
        fail_if(
            InvalidProofReason::RangeCheck(4),
            commitment.d.in_mult_group_of(data.key.nn()),
        )?;

        // Verify statement
        {
            let lhs = data
                .key
                .encrypt_with(&proof.z1, &proof.z2)
                .map_err(|_| InvalidProofReason::PaillierEnc)?;
            let rhs = {
                let e_at_c = data
                    .key
                    .omul(challenge, data.ciphertext)
                    .map_err(|_| InvalidProofReason::PaillierOp)?;
                data.key
                    .oadd(&commitment.d, &e_at_c)
                    .map_err(|_| InvalidProofReason::PaillierOp)?
            };
            fail_if_ne(InvalidProofReason::EqualityCheck(5), lhs, rhs)?;
        }
        {
            let lhs = *data.a * proof.w + C::generator() * C::scalar_from_integer(&proof.z1);
            let rhs = commitment.y + *data.x * C::scalar_from_integer(challenge);
            fail_if_ne(InvalidProofReason::EqualityCheck(6), lhs, rhs)?;
        }
        {
            let lhs = C::generator() * proof.w;
            let rhs = commitment.z + *data.b * C::scalar_from_integer(challenge);
            fail_if_ne(InvalidProofReason::EqualityCheck(7), lhs, rhs)?;
        }
        {
            let lhs = aux.combine(&proof.z1, &proof.z3)?;
            let rhs = {
                let s_to_e = aux.pow_mod(&commitment.s, challenge)?;
                (&commitment.t * s_to_e).modulo(&aux.rsa_modulo)
            };
            fail_if_ne(InvalidProofReason::EqualityCheck(8), lhs, rhs)?;
        }

        fail_if(
            InvalidProofReason::RangeCheck(9),
            proof
                .z1
                .is_in_half_pm(&(Integer::one() << (security.l + security.epsilon))),
        )?;

        Ok(())
    }

    /// Generate random challenge
    ///
    /// `security` parameter is used to generate challenge in correct range
    pub fn challenge<C: TecdsaCurve>(rng: &mut impl RngCore) -> Challenge
    where
        FieldBytesSize<C>: ModulusSize,
    {
        Integer::from_rng_half_pm(rng, &C::order())
    }
}

/// The non-interactive version of proof. Completed in one round, for example
/// see the documentation of parent module.
pub mod non_interactive {
    use digest::Digest;
    use elliptic_curve::{sec1::ModulusSize, FieldBytesSize};
    use tecdsa_curve::TecdsaCurve;

    use super::{Aux, Challenge, Commitment, Data, NiProof, PrivateData, SecurityParams};
    use crate::zk::{Error, InvalidProof};

    /// Compute proof for the given data, producing random commitment and
    /// deriving deterministic challenge.
    ///
    /// Obtained from the above interactive proof via Fiat-Shamir heuristic.
    pub fn prove<C: TecdsaCurve, D: Digest>(
        shared_state: &impl udigest::Digestable,
        aux: &Aux,
        data: Data<C>,
        pdata: PrivateData<C>,
        security: &SecurityParams,
        rng: &mut impl rand_core::CryptoRngCore,
    ) -> Result<NiProof<C>, Error>
    where
        FieldBytesSize<C>: ModulusSize,
    {
        let (commitment, pcomm) = super::interactive::commit(aux, data, pdata, security, rng)?;
        let challenge = challenge::<C, D>(shared_state, aux, data, &commitment, security);
        let proof = super::interactive::prove(data, pdata, &pcomm, &challenge)?;
        Ok(NiProof { commitment, proof })
    }

    /// Verify the proof, deriving challenge independently from same data
    pub fn verify<C: TecdsaCurve, D: Digest>(
        shared_state: &impl udigest::Digestable,
        aux: &Aux,
        data: Data<C>,
        proof: &NiProof<C>,
        security: &SecurityParams,
    ) -> Result<(), InvalidProof>
    where
        FieldBytesSize<C>: ModulusSize,
    {
        let challenge = challenge::<C, D>(shared_state, aux, data, &proof.commitment, security);
        super::interactive::verify(
            aux,
            data,
            &proof.commitment,
            security,
            &challenge,
            &proof.proof,
        )
    }

    /// Deterministically compute challenge based on prior known values in protocol
    pub fn challenge<C: TecdsaCurve, D: Digest>(
        shared_state: &impl udigest::Digestable,
        aux: &Aux,
        data: Data<C>,
        commitment: &Commitment<C>,
        security: &SecurityParams,
    ) -> Challenge
    where
        FieldBytesSize<C>: ModulusSize,
    {
        let tag = "paillier_zk.encryption_in_range_with_el_gamal.ni_challenge";
        let seed = udigest::inline_struct!(tag {
            shared_state,
            aux: aux.digest_public_data(),
            security,
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
    use rug::Integer;
    use sha2::Digest;
    use tecdsa_bigint::BigIntExt;
    use tecdsa_curve::TecdsaCurve;

    use crate::zk::common::InvalidProofReason;

    fn run_with<C: TecdsaCurve, D: Digest>(
        mut rng: &mut impl rand_core::CryptoRngCore,
        security: super::SecurityParams,
        plaintext: Integer,
    ) -> Result<(), crate::zk::common::InvalidProof>
    where
        FieldBytesSize<C>: ModulusSize,
    {
        let aux = crate::zk::common::test::aux(&mut rng);

        let private_key = crate::zk::common::test::random_key(&mut rng).unwrap();
        let a = C::random_scalar(rng);
        let pdata = super::PrivateData {
            plaintext: &plaintext,
            nonce: &Integer::sample_in_mult_group_of(rng, private_key.n()),
            b: &C::random_scalar(rng),
        };

        let data = super::Data {
            key: private_key.encryption_key(),
            ciphertext: &private_key
                .encrypt_with(pdata.plaintext, pdata.nonce)
                .unwrap(),
            a: &(C::generator() * a),
            b: &(C::generator() * *pdata.b),
            x: &(C::generator() * (a * *pdata.b + C::scalar_from_integer(pdata.plaintext))),
        };

        let shared_state = "shared state";
        let proof =
            super::non_interactive::prove::<C, D>(&shared_state, &aux, data, pdata, &security, rng)
                .unwrap();
        super::non_interactive::verify::<C, D>(&shared_state, &aux, data, &proof, &security)
    }

    fn passing_test<C: TecdsaCurve, D: Digest>()
    where
        FieldBytesSize<C>: ModulusSize,
    {
        let mut rng = rand_dev::DevRng::new();
        let security = super::SecurityParams {
            l: 256,
            epsilon: 512,
        };
        let plaintext = Integer::from_rng_half_pm(&mut rng, &(Integer::one() << security.l));
        run_with::<C, D>(&mut rng, security, plaintext).expect("proof failed");
    }

    fn failing_test<C: TecdsaCurve, D: Digest>()
    where
        FieldBytesSize<C>: ModulusSize,
    {
        let mut rng = rand_dev::DevRng::new();
        let security = super::SecurityParams {
            l: 256,
            epsilon: 512,
        };
        let plaintext = (Integer::one() << (security.l + security.epsilon - 1)) + 1;
        let r = run_with::<C, D>(&mut rng, security, plaintext).expect_err("proof should not pass");
        match r.reason() {
            InvalidProofReason::RangeCheck(9) => (),
            e => panic!("proof should not fail with: {e:?}"),
        }
    }

    #[test]
    fn passing_p256() {
        passing_test::<p256::NistP256, sha2::Sha256>()
    }
    #[test]
    fn failing_p256_add() {
        failing_test::<p256::NistP256, sha2::Sha256>()
    }
}
