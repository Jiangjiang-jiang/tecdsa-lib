// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2023 Dfns <https://github.com/LFDT-Lockness/cggmp21>

use rug::Integer;
use serde::{Deserialize, Serialize};

/// Public data that both parties know: the Paillier-Blum modulus
#[derive(Debug, Clone, Copy, udigest::Digestable)]
pub struct Data<'a> {
    #[udigest(as = &crate::zk::common::encoding::Integer)]
    pub n: &'a Integer,
}

/// Private data of prover
#[derive(Clone, Copy)]
pub struct PrivateData<'a> {
    pub p: &'a Integer,
    pub q: &'a Integer,
}

/// Prover's first message, obtained by [`interactive::commit`]
#[derive(Debug, Clone, udigest::Digestable, Serialize, Deserialize)]
pub struct Commitment {
    #[udigest(as = crate::zk::common::encoding::Integer)]
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub w: Integer,
}

/// Verifier's challenge to prover. Can be obtained deterministically by
/// [`non_interactive::challenge`] or randomly by [`interactive::challenge`]
///
/// Consists of `M` singular challenges
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Challenge<const M: usize> {
    pub ys: [Integer; M],
}

/// A part of proof. Having enough of those guarantees security
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofPoint {
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub x: Integer,
    pub a: bool,
    pub b: bool,
    #[serde(with = "tecdsa_bigint::int_wire")]
    pub z: Integer,
}

/// The ZK proof. Computed by [`interactive::prove`].
/// Consists of M proofs for each challenge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof<const M: usize> {
    // A trick to serialize arbitrary size arrays
    #[serde(with = "serde_with::As::<[serde_with::Same; M]>")]
    pub points: [ProofPoint; M],
}

/// The non-interactive ZK proof. Computed by [`non_interactive::prove`].
/// Combines commitment and proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NiProof<const M: usize> {
    pub commitment: Commitment,
    pub proof: Proof<M>,
}

/// The interactive version of the ZK proof. Should be completed in 3 rounds:
/// prover commits to data, verifier responds with a random challenge, and
/// prover gives proof with commitment and challenge.
pub mod interactive {
    use rand_core::RngCore;
    use rug::Integer;
    use tecdsa_bigint::BigIntExt;

    use super::{Challenge, Commitment, Data, PrivateData, Proof, ProofPoint};
    use crate::zk::{
        common::fail_if, BadExponent, Error, ErrorReason, InvalidProof, InvalidProofReason,
    };

    /// Create random commitment
    pub fn commit<R: RngCore>(Data { n }: Data, rng: &mut R) -> Commitment {
        Commitment {
            w: Integer::sample_neg_jacobi(rng, n),
        }
    }

    /// Compute proof for given data and prior protocol values
    pub fn prove<const M: usize>(
        Data { n }: Data,
        PrivateData { p, q }: PrivateData,
        Commitment { ref w }: &Commitment,
        challenge: &Challenge<M>,
    ) -> Result<Proof<M>, Error> {
        let blum_sqrt = |x: Integer| x.blum_sqrt(p, q, n);
        let phi = Integer::from(p - 1) * Integer::from(q - 1);
        let n_inverse = Integer::from(n.invert_ref(&phi).ok_or(ErrorReason::Invert)?);

        // The M challenge points are independent: each needs one N^-1-th root
        // and two Blum square roots, all on the same fixed modulus.
        // We do an extra allocation as workaround while `array::try_map` is not stable
        let points: Vec<ProofPoint> = tecdsa_bigint::par::try_map(&challenge.ys, |y| {
            let z = Integer::from(
                y.pow_mod_ref(&n_inverse, n)
                    .ok_or(BadExponent::undefined())?,
            );
            let (a, b, y_) = y.find_residue(w, p, q, n).ok_or(ErrorReason::FindResidue)?;
            let x = blum_sqrt(blum_sqrt(y_));
            Ok::<_, ErrorReason>(ProofPoint { x, a, b, z })
        })?;
        let points = points
            .try_into()
            .map_err(|_: Vec<ProofPoint>| ErrorReason::Length)?;
        Ok(Proof { points })
    }

    /// Verify the proof. If this succeeds, the relation Rmod holds with chance
    /// `1/2^M`
    ///
    /// Rng is used for primality checking of input data
    pub fn verify<const M: usize, R: RngCore>(
        data: Data,
        commitment: &Commitment,
        challenge: &Challenge<M>,
        proof: &Proof<M>,
        _rng: &mut R,
    ) -> Result<(), InvalidProof> {
        // rug's `is_probably_prime` (unlike the old fast-paillier trait method it
        // replaces) doesn't take an rng; `_rng` is kept for API compatibility.
        if data.n.is_probably_prime(25) != rug::integer::IsPrime::No {
            return Err(InvalidProofReason::ModulusIsPrime.into());
        }
        if data.n.is_even() {
            return Err(InvalidProofReason::ModulusIsEven.into());
        }
        fail_if(
            InvalidProofReason::RangeCheck(1),
            commitment.w.in_mult_group_of(data.n),
        )?;

        // The M point checks are independent; each is dominated by one
        // `z^N mod N` exponentiation.
        let pairs: Vec<(&ProofPoint, &Integer)> =
            proof.points.iter().zip(challenge.ys.iter()).collect();
        tecdsa_bigint::par::try_for_each(&pairs, |&(point, y)| {
            fail_if(
                InvalidProofReason::RangeCheck(2),
                point.x.in_mult_group_of(data.n),
            )?;
            fail_if(
                InvalidProofReason::RangeCheck(3),
                point.z.in_mult_group_of(data.n),
            )?;
            if Integer::from(
                point
                    .z
                    .pow_mod_ref(data.n, data.n)
                    .ok_or(InvalidProofReason::ModPow)?,
            ) != *y
            {
                return Err(InvalidProofReason::IncorrectNthRoot.into());
            }
            let y = if point.a {
                Integer::from(data.n - y)
            } else {
                y.clone()
            };
            let y = if point.b {
                (y * &commitment.w).modulo(data.n)
            } else {
                y
            };
            if Integer::from(
                point
                    .x
                    .pow_mod_ref(&4.into(), data.n)
                    .ok_or(InvalidProofReason::ModPow)?,
            ) != y
            {
                return Err(InvalidProofReason::IncorrectFourthRoot.into());
            }
            Ok::<(), InvalidProof>(())
        })
    }

    /// Generate random challenge
    ///
    /// `data` parameter is used to generate challenge in correct range
    pub fn challenge<const M: usize, R: RngCore>(Data { n }: Data, rng: &mut R) -> Challenge<M> {
        let ys = [(); M].map(|()| Integer::sample_in_mult_group_of(rng, n));
        Challenge { ys }
    }
}

/// The non-interactive version of proof. Completed in one round, for example
/// see the documentation of parent module.
pub mod non_interactive {
    use digest::Digest;

    use super::{Challenge, Commitment, Data, NiProof, PrivateData};
    use crate::zk::{Error, InvalidProof};

    /// Compute proof for the given data, producing random commitment and
    /// deriving determenistic challenge.
    ///
    /// Obtained from the above interactive proof via Fiat-Shamir heuristic.
    pub fn prove<const M: usize, D: Digest>(
        shared_state: &impl udigest::Digestable,
        data: Data,
        pdata: PrivateData,
        rng: &mut impl rand_core::RngCore,
    ) -> Result<NiProof<M>, Error> {
        let commitment = super::interactive::commit(data, rng);
        let challenge = challenge::<M, D>(shared_state, data, &commitment);
        let proof = super::interactive::prove(data, pdata, &commitment, &challenge)?;
        Ok(NiProof { commitment, proof })
    }

    /// Verify the proof, deriving challenge independently from same data
    ///
    /// Rng is used for primality checking of input data
    pub fn verify<const M: usize, D: Digest>(
        shared_state: &impl udigest::Digestable,
        data: Data,
        proof: &NiProof<M>,
        rng: &mut impl rand_core::RngCore,
    ) -> Result<(), InvalidProof> {
        let challenge = challenge::<M, D>(shared_state, data, &proof.commitment);
        super::interactive::verify(data, &proof.commitment, &challenge, &proof.proof, rng)
    }

    /// Deterministically compute challenge based on prior known values in protocol
    pub fn challenge<const M: usize, D: Digest>(
        shared_state: &impl udigest::Digestable,
        data: Data,
        commitment: &Commitment,
    ) -> Challenge<M> {
        let tag = "paillier_zk.blum_modulus.ni_challenge";
        let seed = udigest::inline_struct!(tag {
            shared_state,
            data,
            commitment,
        });
        let mut rng = rand_hash::HashRng::<D, _>::from_seed(seed);

        super::interactive::challenge(data, &mut rng)
    }
}

#[cfg(test)]
mod test {
    use rug::Complete;
    use tecdsa_bigint::BigIntExt;

    use crate::zk::common::test::generate_blum_prime;

    type D = sha2::Sha256;

    #[test]
    fn passing() {
        let mut rng = rand_dev::DevRng::new();
        let p = generate_blum_prime(&mut rng, 256);
        let q = generate_blum_prime(&mut rng, 256);
        let n = (&p * &q).complete();
        let data = super::Data { n: &n };
        let pdata = super::PrivateData { p: &p, q: &q };
        let shared_state = "shared state";
        let proof =
            super::non_interactive::prove::<65, D>(&shared_state, data, pdata, &mut rng).unwrap();
        let r = super::non_interactive::verify::<65, D>(&shared_state, data, &proof, &mut rng);
        match r {
            Ok(()) => (),
            Err(e) => panic!("{e:?}"),
        }
    }

    #[test]
    fn failing() {
        let mut rng = rand_dev::DevRng::new();
        let p = generate_blum_prime(&mut rng, 256);
        let q = loop {
            // non blum prime
            let q = rug::Integer::generate_prime(&mut rng, 256);
            if q.mod_u(4) == 1 {
                break q;
            }
        };
        let n = (&p * &q).complete();
        let data = super::Data { n: &n };
        let pdata = super::PrivateData { p: &p, q: &q };
        let shared_state = "shared state";
        let proof =
            super::non_interactive::prove::<65, D>(&shared_state, data, pdata, &mut rng).unwrap();
        let r = super::non_interactive::verify::<65, D>(&shared_state, data, &proof, &mut rng);
        if r.is_ok() {
            panic!("proof should not pass");
        }
    }
}
