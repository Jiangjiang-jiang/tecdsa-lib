// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2023 Dfns <https://github.com/LFDT-Lockness/cggmp21>

use generic_ec::{Curve, Point};
use rug::Integer;
use serde::{Deserialize, Serialize};

use crate::scheme::{AnyEncryptionKey, Ciphertext, Nonce};
pub use crate::zk::common::{Aux, InvalidProof};

/// Security parameters for proof. Choosing the values is a tradeoff between
/// speed and chance of rejecting a valid proof or accepting an invalid proof
#[derive(Debug, Clone, udigest::Digestable, Serialize, Deserialize)]
pub struct SecurityParams {
    /// l in paper, bit size of +-x
    pub l_x: usize,
    /// l' in paper, bit size of +-y
    pub l_y: usize,
    /// Epsilon in paper, slackness parameter
    pub epsilon: usize,
}

/// Public data that both parties know
#[derive(Debug, Clone, Copy, udigest::Digestable)]
#[udigest(bound = "")]
pub struct Data<'a, C: Curve> {
    /// Nj in the spec, public key that C was encrypted on
    #[udigest(as = crate::zk::common::encoding::AnyEncryptionKey)]
    pub key_j: &'a dyn AnyEncryptionKey,
    /// Ni in the spec, public key that y -> Y was encrypted on
    #[udigest(as = crate::zk::common::encoding::AnyEncryptionKey)]
    pub key_i: &'a dyn AnyEncryptionKey,
    /// C in the spec, some data encrypted on Nj
    #[udigest(as = &crate::zk::common::encoding::Integer)]
    pub c: &'a Ciphertext,
    /// D in the spec, result of affine transformation of C with x and y
    #[udigest(as = &crate::zk::common::encoding::Integer)]
    pub d: &'a Integer,
    /// Y in the spec, y encrypted on Ni
    #[udigest(as = &crate::zk::common::encoding::Integer)]
    pub y: &'a Ciphertext,
    /// X in the spec, obtained as `x G`
    pub x: &'a Point<C>,
}

/// Private data of prover
#[derive(Clone, Copy)]
pub struct PrivateData<'a> {
    /// x in the spec, preimage of X
    pub x: &'a Integer,
    /// y in the spec, preimage of Y
    pub y: &'a Integer,
    /// rho in the spec, nonce in encryption of y for additive action
    pub nonce: &'a Nonce,
    /// rho_y in the spec, nonce in encryption of y to obtain Y
    pub nonce_y: &'a Nonce,
}

/// Prover's first message, obtained by [`interactive::commit`]
#[derive(Debug, Clone, udigest::Digestable)]
#[udigest(bound = "")]
#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Commitment<C: Curve> {
    #[udigest(as = crate::zk::common::encoding::Integer)]
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub a: Integer,
    pub b_x: Point<C>,
    #[udigest(as = crate::zk::common::encoding::Integer)]
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub b_y: Integer,
    #[udigest(as = crate::zk::common::encoding::Integer)]
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub e: Integer,
    #[udigest(as = crate::zk::common::encoding::Integer)]
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub s: Integer,
    #[udigest(as = crate::zk::common::encoding::Integer)]
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub f: Integer,
    #[udigest(as = crate::zk::common::encoding::Integer)]
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub t: Integer,
}

/// Prover's data accompanying the commitment. Kept as state between rounds in
/// the interactive protocol.
#[derive(Clone)]
pub struct PrivateCommitment {
    pub alpha: Integer,
    pub beta: Integer,
    pub r: Integer,
    pub r_y: Integer,
    pub gamma: Integer,
    pub delta: Integer,
    pub m: Integer,
    pub mu: Integer,
}

/// Verifier's challenge to prover. Can be obtained deterministically by
/// [`non_interactive::challenge`] or randomly by [`interactive::challenge`]
pub type Challenge = Integer;

/// The ZK proof. Computed by [`interactive::prove`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub z1: Integer,
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub z2: Integer,
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub z3: Integer,
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub z4: Integer,
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub w: Integer,
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub w_y: Integer,
}

/// The non-interactive ZK proof. Computed by [`non_interactive::prove`].
/// Combines commitment and proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct NiProof<C: Curve> {
    pub commitment: Commitment<C>,
    pub proof: Proof,
}

/// The interactive version of the ZK proof. Should be completed in 3 rounds:
/// prover commits to data, verifier responds with a random challenge, and
/// prover gives proof with commitment and challenge.
pub mod interactive {
    use generic_ec::{Curve, Point};
    use rand_core::RngCore;
    use rug::Integer;
    use tecdsa_bigint::BigIntExt;

    use super::*;
    use crate::zk::{
        common::{fail_if, fail_if_ne, IntegerExt, InvalidProof, InvalidProofReason},
        Error,
    };

    /// Create random commitment
    pub fn commit<C: Curve, R: RngCore>(
        aux: &Aux,
        data: Data<C>,
        pdata: PrivateData,
        security: &SecurityParams,
        mut rng: R,
    ) -> Result<(Commitment<C>, PrivateCommitment), Error> {
        let two_to_l = Integer::one() << security.l_x;
        let two_to_l_e = Integer::one() << (security.l_x + security.epsilon);
        let two_to_l_prime_e = Integer::one() << (security.l_y + security.epsilon);
        let hat_n_at_two_to_l_e = Integer::from(&aux.rsa_modulo * &two_to_l_e);
        let hat_n_at_two_to_l = Integer::from(&aux.rsa_modulo * &two_to_l);

        let alpha = Integer::from_rng_half_pm(&mut rng, &two_to_l_e);
        let beta = Integer::from_rng_half_pm(&mut rng, &two_to_l_prime_e);
        let r = Integer::sample_in_mult_group_of(&mut rng, data.key_j.n());
        let r_y = Integer::sample_in_mult_group_of(&mut rng, data.key_i.n());
        let gamma = Integer::from_rng_half_pm(&mut rng, &hat_n_at_two_to_l_e);
        let delta = Integer::from_rng_half_pm(&mut rng, &hat_n_at_two_to_l_e);
        let m = Integer::from_rng_half_pm(&mut rng, &hat_n_at_two_to_l);
        let mu = Integer::from_rng_half_pm(&mut rng, &hat_n_at_two_to_l);

        let commitment = Commitment {
            a: {
                let beta_enc_key0 = data.key_j.encrypt_with(&beta, &r)?;
                let alpha_at_c = data.key_j.omul(&alpha, data.c)?;
                data.key_j.oadd(&alpha_at_c, &beta_enc_key0)?
            },
            b_x: Point::<C>::generator() * alpha.to_scalar(),
            b_y: data.key_i.encrypt_with(&beta, &r_y)?,
            e: aux.combine(&alpha, &gamma)?,
            s: aux.combine(pdata.x, &m)?,
            f: aux.combine(&beta, &delta)?,
            t: aux.combine(pdata.y, &mu)?,
        };
        let private_commitment = PrivateCommitment {
            alpha,
            beta,
            r,
            r_y,
            gamma,
            m,
            delta,
            mu,
        };
        Ok((commitment, private_commitment))
    }

    /// Compute proof for given data and prior protocol values
    pub fn prove<C: Curve>(
        data: Data<C>,
        pdata: PrivateData,
        pcomm: &PrivateCommitment,
        challenge: &Challenge,
    ) -> Result<Proof, Error> {
        Ok(Proof {
            z1: Integer::from(&pcomm.alpha + challenge * pdata.x),
            z2: Integer::from(&pcomm.beta + challenge * pdata.y),
            z3: Integer::from(&pcomm.gamma + challenge * &pcomm.m),
            z4: Integer::from(&pcomm.delta + challenge * &pcomm.mu),
            w: data
                .key_j
                .n()
                .combine(&pcomm.r, &Integer::one(), pdata.nonce, challenge)
                .ok_or_else(crate::zk::BadExponent::undefined)?,
            // TODO: this can be optimized as prover knows key_i factorization
            w_y: data
                .key_i
                .n()
                .combine(&pcomm.r_y, &Integer::one(), pdata.nonce_y, challenge)
                .ok_or_else(crate::zk::BadExponent::undefined)?,
        })
    }

    /// Verify the proof
    pub fn verify<C: Curve>(
        aux: &Aux,
        data: Data<C>,
        commitment: &Commitment<C>,
        security: &SecurityParams,
        challenge: &Challenge,
        proof: &Proof,
    ) -> Result<(), InvalidProof> {
        // Verify public data
        fail_if(
            InvalidProofReason::RangeCheck(1),
            data.c.in_mult_group_of(data.key_j.nn()),
        )?;
        fail_if(
            InvalidProofReason::RangeCheck(2),
            data.d.in_mult_group_of(data.key_j.nn()),
        )?;
        fail_if(
            InvalidProofReason::RangeCheck(3),
            data.y.in_mult_group_of(data.key_i.nn()),
        )?;
        // Verify commitment
        fail_if(
            InvalidProofReason::RangeCheck(4),
            commitment.a.in_mult_group_of(data.key_j.nn()),
        )?;
        fail_if(
            InvalidProofReason::RangeCheck(5),
            commitment.b_y.in_mult_group_of(data.key_i.nn()),
        )?;
        fail_if(
            InvalidProofReason::RangeCheck(6),
            aux.is_in_mult_group(&commitment.e),
        )?;
        fail_if(
            InvalidProofReason::RangeCheck(7),
            aux.is_in_mult_group(&commitment.s),
        )?;
        fail_if(
            InvalidProofReason::RangeCheck(8),
            aux.is_in_mult_group(&commitment.f),
        )?;
        fail_if(
            InvalidProofReason::RangeCheck(9),
            aux.is_in_mult_group(&commitment.t),
        )?;

        // Verify statement
        {
            let lhs = {
                let z1_at_c = data
                    .key_j
                    .omul(&proof.z1, data.c)
                    .map_err(|_| InvalidProofReason::PaillierOp)?;
                let enc = data
                    .key_j
                    .encrypt_with(&proof.z2, &proof.w)
                    .map_err(|_| InvalidProofReason::PaillierEnc)?;
                data.key_j
                    .oadd(&z1_at_c, &enc)
                    .map_err(|_| InvalidProofReason::PaillierOp)?
            };
            let rhs = {
                let e_at_d = data
                    .key_j
                    .omul(challenge, data.d)
                    .map_err(|_| InvalidProofReason::PaillierOp)?;
                data.key_j
                    .oadd(&commitment.a, &e_at_d)
                    .map_err(|_| InvalidProofReason::PaillierOp)?
            };
            fail_if_ne(InvalidProofReason::EqualityCheck(10), lhs, rhs)?;
        }
        {
            let lhs = Point::<C>::generator() * proof.z1.to_scalar();
            let rhs = commitment.b_x + data.x * challenge.to_scalar();
            fail_if_ne(InvalidProofReason::EqualityCheck(11), lhs, rhs)?;
        }
        {
            let lhs = data
                .key_i
                .encrypt_with(&proof.z2, &proof.w_y)
                .map_err(|_| InvalidProofReason::PaillierEnc)?;
            let rhs = {
                let e_at_y = data
                    .key_i
                    .omul(challenge, data.y)
                    .map_err(|_| InvalidProofReason::PaillierOp)?;
                data.key_i
                    .oadd(&commitment.b_y, &e_at_y)
                    .map_err(|_| InvalidProofReason::PaillierOp)?
            };
            fail_if_ne(InvalidProofReason::EqualityCheck(12), lhs, rhs)?;
        }
        {
            let lhs = aux.combine(&proof.z1, &proof.z3)?;
            let s_to_e = aux.pow_mod(&commitment.s, challenge)?;
            let rhs = (&commitment.e * s_to_e).modulo(&aux.rsa_modulo);
            fail_if_ne(InvalidProofReason::EqualityCheck(13), lhs, rhs)?;
        }
        {
            let lhs = aux.combine(&proof.z2, &proof.z4)?;
            let t_to_e = aux.pow_mod(&commitment.t, challenge)?;
            let rhs = (&commitment.f * t_to_e).modulo(&aux.rsa_modulo);
            fail_if_ne(InvalidProofReason::EqualityCheck(14), lhs, rhs)?;
        }
        fail_if(
            InvalidProofReason::RangeCheck(15),
            proof
                .z1
                .is_in_half_pm(&(Integer::one() << (security.l_x + security.epsilon))),
        )?;
        fail_if(
            InvalidProofReason::RangeCheck(16),
            proof
                .z2
                .is_in_half_pm(&(Integer::one() << (security.l_y + security.epsilon))),
        )?;
        Ok(())
    }

    /// Generate random challenge
    pub fn challenge<C: Curve>(rng: &mut impl rand_core::RngCore) -> Integer {
        let q = Integer::curve_order::<C>();
        Integer::from_rng_half_pm(rng, &q)
    }
}

/// The non-interactive version of proof. Completed in one round, for example
/// see the documentation of parent module.
pub mod non_interactive {
    use digest::Digest;
    use generic_ec::Curve;

    use super::{Aux, Challenge, Commitment, Data, NiProof, PrivateData, SecurityParams};
    use crate::zk::{Error, InvalidProof};

    /// Compute proof for the given data, producing random commitment and
    /// deriving determenistic challenge.
    ///
    /// Obtained from the above interactive proof via Fiat-Shamir heuristic.
    pub fn prove<C: Curve, D: Digest>(
        shared_state: &impl udigest::Digestable,
        aux: &Aux,
        data: Data<C>,
        pdata: PrivateData,
        security: &SecurityParams,
        rng: &mut impl rand_core::RngCore,
    ) -> Result<NiProof<C>, Error> {
        let (commitment, pcomm) = super::interactive::commit(aux, data, pdata, security, rng)?;
        let challenge = challenge::<C, D>(shared_state, aux, data, &commitment, security);
        let proof = super::interactive::prove(data, pdata, &pcomm, &challenge)?;
        Ok(NiProof { commitment, proof })
    }

    /// Verify the proof, deriving challenge independently from same data
    pub fn verify<C: Curve, D: Digest>(
        shared_state: &impl udigest::Digestable,
        aux: &Aux,
        data: Data<C>,
        security: &SecurityParams,
        proof: &NiProof<C>,
    ) -> Result<(), InvalidProof> {
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
    pub fn challenge<C: Curve, D: Digest>(
        shared_state: &impl udigest::Digestable,
        aux: &Aux,
        data: Data<C>,
        commitment: &Commitment<C>,
        security: &SecurityParams,
    ) -> Challenge {
        let tag = "paillier_zk.paillier_affine_operation_in_range.ni_challenge";
        let aux = aux.digest_public_data();
        let seed = udigest::inline_struct!(tag {
            shared_state,
            aux,
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
    use generic_ec::{Curve, Point};
    use rug::Integer;
    use sha2::Digest;
    use tecdsa_bigint::BigIntExt;

    use crate::zk::common::{test::random_key, IntegerExt, InvalidProofReason};

    fn run<R: rand_core::RngCore + rand_core::CryptoRng, C: Curve, D: Digest>(
        rng: &mut R,
        security: super::SecurityParams,
        x: Integer,
        y: Integer,
    ) -> Result<(), crate::zk::common::InvalidProof> {
        let dk0 = random_key(rng).unwrap();
        let dk1 = random_key(rng).unwrap();
        let ek0 = dk0.encryption_key().clone();
        let ek1 = dk1.encryption_key().clone();

        let (c, _) = {
            let plaintext = Integer::from_rng_half_pm(rng, ek0.n());
            ek0.encrypt_with_random(rng, &plaintext).unwrap()
        };

        let (y_enc_ek1, rho_y) = ek1.encrypt_with_random(rng, &y).unwrap();

        let (y_enc_ek0, rho) = ek0.encrypt_with_random(rng, &y).unwrap();
        let x_at_c = ek0.omul(&x, &c).unwrap();
        let d = ek0.oadd(&x_at_c, &y_enc_ek0).unwrap();

        let data = super::Data {
            key_j: &ek0,
            key_i: &ek1,
            c: &c,
            d: &d,
            y: &y_enc_ek1,
            x: &(x.to_scalar::<C>() * Point::generator()),
        };
        let pdata = super::PrivateData {
            x: &x,
            y: &y,
            nonce: &rho,
            nonce_y: &rho_y,
        };

        let aux = crate::zk::common::test::aux(rng);

        let shared_state = "shared state";

        let proof =
            super::non_interactive::prove::<C, D>(&shared_state, &aux, data, pdata, &security, rng)
                .unwrap();
        super::non_interactive::verify::<C, D>(&shared_state, &aux, data, &security, &proof)
    }

    fn passing_test<C: Curve, D: Digest>() {
        let mut rng = rand_dev::DevRng::new();
        let security = super::SecurityParams {
            l_x: 256,
            l_y: 1280,
            epsilon: 512,
        };
        let x = Integer::from_rng_half_pm(&mut rng, &(Integer::one() << security.l_x));
        let y = Integer::from_rng_half_pm(&mut rng, &(Integer::one() << security.l_y));
        run::<_, C, D>(&mut rng, security, x, y).expect("proof failed");
    }

    fn failing_on_additive<C: Curve, D: Digest>() {
        let mut rng = rand_dev::DevRng::new();
        let security = super::SecurityParams {
            l_x: 256,
            l_y: 1280,
            epsilon: 512,
        };
        let x = Integer::from_rng_half_pm(&mut rng, &(Integer::one() << security.l_x));
        let y = (Integer::one() << (security.l_y + security.epsilon - 1)) + 1;
        let r = run::<_, C, D>(&mut rng, security, x, y).expect_err("proof should not pass");
        match r.reason() {
            InvalidProofReason::RangeCheck(16) => (),
            e => panic!("proof should not fail with: {e:?}"),
        }
    }

    fn failing_on_multiplicative<C: Curve, D: Digest>() {
        let mut rng = rand_dev::DevRng::new();
        let security = super::SecurityParams {
            l_x: 256,
            l_y: 1280,
            epsilon: 512,
        };
        let x = (Integer::one() << (security.l_x + security.epsilon - 1)) + 1;
        let y = Integer::from_rng_half_pm(&mut rng, &(Integer::one() << security.l_y));
        let r = run::<_, C, D>(&mut rng, security, x, y).expect_err("proof should not pass");
        match r.reason() {
            InvalidProofReason::RangeCheck(15) => (),
            e => panic!("proof should not fail with: {e:?}"),
        }
    }

    #[test]
    fn passing_p256() {
        passing_test::<generic_ec::curves::Secp256r1, sha2::Sha256>()
    }
    #[test]
    fn failing_p256_add() {
        failing_on_additive::<generic_ec::curves::Secp256r1, sha2::Sha256>()
    }
    #[test]
    fn failing_p256_mul() {
        failing_on_multiplicative::<generic_ec::curves::Secp256r1, sha2::Sha256>()
    }

    #[test]
    fn passing_million() {
        passing_test::<crate::zk::curve::C, sha2::Sha256>()
    }
    #[test]
    fn failing_million_add() {
        failing_on_additive::<crate::zk::curve::C, sha2::Sha256>()
    }
    #[test]
    fn failing_million_mul() {
        failing_on_multiplicative::<crate::zk::curve::C, sha2::Sha256>()
    }
}
