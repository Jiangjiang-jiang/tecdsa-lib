// SPDX-License-Identifier: MIT OR Apache-2.0
//! GGN16 threshold key generation protocol.
//!
//! A 2-round protocol where `n` parties produce a shared ECDSA key using a
//! pre-existing threshold Paillier setup (trusted dealer).  Each party
//! contributes an additive secret share `x_i` and proves via a PdlSlack proof
//! that its Paillier encryption `alpha_i = E(x_i)` encrypts the discrete log
//! of its public contribution `y_i = x_i * G`.
//!
//! ## Protocol Rounds
//!
//! 1. **Commitment:** each party broadcasts a hash commitment to `y_i`.
//! 2. **Decommit + Encrypt + Prove:** each party broadcasts the decommitment,
//!    `alpha_i`, and a PdlSlack proof.
//!
//! After Round 2, each party computes `alpha = sum(alpha_i)` (homomorphic) and
//! `y = sum(y_i)` as the joint public key.
//!
//! Reference: Gennaro, Goldfeder, Narayanan. "Threshold-Optimal DSA/ECDSA
//! Signatures and an Application to Bitcoin Wallet Security." ACNS 2016,
//! Section 4.2.

pub mod msg;
mod rounds;

use elliptic_curve::{sec1::ModulusSize, FieldBytes, FieldBytesSize, PrimeField};
use msg::Ggn16KeygenMsg;
use rand_core::CryptoRngCore;
use rounds::{KeygenConfig, KeygenRound, Round1State};
use tecdsa_core::TecdsaError;
use tecdsa_curve::TecdsaCurve;
use tecdsa_paillier::{
    backend::Integer,
    threshold::{DecryptionShare, ThresholdSetup},
};
use tecdsa_protocol::{state_machine::Outgoing, IaReport, PartyId, StateMachine};

use crate::key_share::Ggn16KeyShare;

/// GGN16 threshold key generation state machine.
///
/// Drives a single party through the 2-round keygen protocol. Create one
/// instance per party via [`Ggn16KeygenMachine::new`], then feed messages
/// through the [`StateMachine`] trait.
pub struct Ggn16KeygenMachine<C: TecdsaCurve>
where
    FieldBytesSize<C>: ModulusSize,
{
    round: KeygenRound<C>,
    /// RNG stored for the Round 1 -> Round 2 transition (proof generation).
    rng_seed: [u8; 32],
}

impl<C: TecdsaCurve> Ggn16KeygenMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    /// Create a new GGN16 keygen state machine.
    ///
    /// # Arguments
    ///
    /// * `my_id` - This party's identifier.
    /// * `all_parties` - All party identifiers (including self), in consistent order.
    /// * `threshold` - Reconstruction threshold `t`: `t` parties needed to sign.
    /// * `threshold_setup` - Shared Paillier public parameters from the trusted dealer.
    /// * `decryption_share` - This party's threshold Paillier decryption share.
    /// * `h1`, `h2`, `N_tilde` - Ring-Pedersen auxiliary parameters for ZK proofs.
    /// * `rng` - Cryptographic RNG for secret generation.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        my_id: PartyId,
        all_parties: Vec<PartyId>,
        threshold: u16,
        threshold_setup: ThresholdSetup,
        decryption_share: DecryptionShare,
        h1: Integer,
        h2: Integer,
        n_tilde: Integer,
        rng: &mut impl CryptoRngCore,
    ) -> Self {
        let total = all_parties.len() as u16;
        let config = KeygenConfig {
            my_id,
            all_parties,
            threshold,
            total,
            threshold_setup,
            decryption_share,
            h1,
            h2,
            N_tilde: n_tilde,
        };

        // Save RNG seed for later proof generation
        let mut rng_seed = [0u8; 32];
        rng.fill_bytes(&mut rng_seed);

        let state = Round1State::<C>::new(config, rng);
        Self {
            round: KeygenRound::Round1(state),
            rng_seed,
        }
    }
}

impl<C: TecdsaCurve> StateMachine for Ggn16KeygenMachine<C>
where
    FieldBytesSize<C>: ModulusSize,
    C::Scalar: PrimeField<Repr = FieldBytes<C>>,
{
    type Output = Ggn16KeyShare<C>;
    type Inbound = Ggn16KeygenMsg<C>;
    type Outbound = Ggn16KeygenMsg<C>;

    fn handle(&mut self, from: PartyId, msg: Self::Inbound) -> tecdsa_core::Result<()> {
        match &mut self.round {
            KeygenRound::Round1(state) => match msg {
                Ggn16KeygenMsg::Round1(m) => {
                    state.handle(from, m)?;
                    if state.is_ready() {
                        let old = std::mem::take(&mut self.round);
                        if let KeygenRound::Round1(s) = old {
                            let mut rng =
                                <rand::rngs::StdRng as rand::SeedableRng>::from_seed(self.rng_seed);
                            self.round = KeygenRound::Round2(s.advance(&mut rng));
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
                Ggn16KeygenMsg::Round2(m) => {
                    state.handle(from, m)?;
                    if state.is_ready() {
                        let old = std::mem::take(&mut self.round);
                        if let KeygenRound::Round2(s) = old {
                            self.round = KeygenRound::Done(s.finish()?);
                        }
                    }
                    Ok(())
                }
                _ => Err(TecdsaError::RoundMismatch {
                    expected: 2,
                    got: msg_round(&msg),
                }),
            },
            KeygenRound::Done(_) | KeygenRound::Poisoned => {
                Err(TecdsaError::Other("protocol already finished".into()))
            }
        }
    }

    fn drain_outgoing(&mut self) -> Vec<Outgoing<Self::Outbound>> {
        match &mut self.round {
            KeygenRound::Round1(state) => std::mem::take(&mut state.outgoing),
            KeygenRound::Round2(state) => std::mem::take(&mut state.outgoing),
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
            KeygenRound::Done(_) => 3,
            KeygenRound::Poisoned => 0,
        }
    }

    fn ia_report(&self) -> Option<&IaReport> {
        None
    }
}

/// Extract the round number from a message variant (for error reporting).
fn msg_round<C: TecdsaCurve>(msg: &Ggn16KeygenMsg<C>) -> u16
where
    FieldBytesSize<C>: ModulusSize,
{
    match msg {
        Ggn16KeygenMsg::Round1(_) => 1,
        Ggn16KeygenMsg::Round2(_) => 2,
    }
}

#[cfg(test)]
mod tests {
    use elliptic_curve::group::GroupEncoding;
    use tecdsa_paillier::{
        threshold::{combine_partials, partial_decrypt, DecryptionShare, ThresholdSetup},
        BigIntExt,
    };
    use tecdsa_testkit::Orchestrator;

    use super::*;

    type TestCurve = k256::Secp256k1;

    /// Trusted dealer setup using small safe primes (256-bit) for fast tests.
    ///
    /// Mirrors `trusted_dealer_setup` from tecdsa_paillier::threshold but
    /// uses `DecryptionKey::from_primes` with small primes instead of the
    /// expensive `DecryptionKey::generate`.
    fn fast_trusted_dealer_setup(
        corruption_threshold: u16,
        total: u16,
        rng: &mut impl CryptoRngCore,
    ) -> (ThresholdSetup, Vec<DecryptionShare>) {
        let p = Integer::generate_safe_prime(rng, 512);
        let q = Integer::generate_safe_prime(rng, 512);
        let dk = tecdsa_paillier::DecryptionKey::from_primes(p.clone(), q.clone())
            .expect("valid safe primes");
        let ek = dk.encryption_key().clone();
        let n = ek.n().clone();

        let p_minus_1 = p - Integer::one();
        let q_minus_1 = q - Integer::one();
        let lambda = p_minus_1.lcm(&q_minus_1);

        let beta = loop {
            let candidate = n.sample_below_ref(rng);
            if candidate.cmp0().is_gt() && Integer::from(candidate.gcd_ref(&n)).is_one() {
                break candidate;
            }
        };

        let d = lambda * beta;
        let theta = Integer::from(d.modulo_ref(&n));

        // delta = n!
        let mut delta = Integer::one();
        for i in 2..=total as u32 {
            delta *= Integer::from(i);
        }

        // Shamir share d over Z with coefficient modulus M = N * delta
        let m = n * &delta;
        let mut coeffs = vec![d];
        for _ in 0..corruption_threshold {
            coeffs.push(m.sample_below_ref(rng));
        }
        let mut shares = Vec::with_capacity(total as usize);
        for i in 1..=total {
            let x = Integer::from(i as u32);
            let mut val = Integer::zero();
            let mut x_pow = Integer::one();
            for coeff in &coeffs {
                val += coeff * &x_pow;
                x_pow *= &x;
            }
            shares.push(DecryptionShare { index: i, d_i: val });
        }

        let setup = ThresholdSetup {
            ek,
            theta,
            n: total,
            corruption_threshold,
            delta,
        };

        (setup, shares)
    }

    /// Generate Ring-Pedersen parameters (N_tilde, h1, h2) for tests.
    fn generate_ring_pedersen(rng: &mut impl CryptoRngCore) -> (Integer, Integer, Integer) {
        let p = Integer::generate_safe_prime(rng, 256);
        let q = Integer::generate_safe_prime(rng, 256);
        let n_tilde = p * q;

        let h1 = Integer::sample_in_mult_group_of(rng, &n_tilde);
        let xhi_bound = Integer::two_pow(256);
        let xhi = xhi_bound.sample_below_ref(rng);
        let h1_xhi = Integer::from(
            h1.pow_mod_ref(&xhi, &n_tilde)
                .expect("pow_mod must succeed"),
        );
        let h2 = h1_xhi
            .invert(&n_tilde)
            .expect("h1^xhi must be invertible mod N_tilde");

        (n_tilde, h1, h2)
    }

    #[test]
    fn keygen_3_party() {
        let mut rng = rand::thread_rng();
        let t = 2u16; // reconstruction threshold: need 2 to sign
        let n = 3u16; // total parties

        // Step 1: Trusted dealer setup for threshold Paillier (fast, small primes)
        // trusted_dealer_setup takes corruption threshold (polynomial degree)
        let corruption_t = t - 1;
        let (setup, dec_shares) = fast_trusted_dealer_setup(corruption_t, n, &mut rng);

        // Step 2: Generate shared Ring-Pedersen parameters
        let (n_tilde, h1, h2) = generate_ring_pedersen(&mut rng);

        // Step 3: Create party IDs
        let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();

        // Step 4: Create keygen machines
        let mut machines: Vec<(PartyId, Ggn16KeygenMachine<TestCurve>)> = Vec::new();
        for (i, dec_share) in dec_shares.into_iter().enumerate() {
            let pid = all_parties[i];
            let machine = Ggn16KeygenMachine::new(
                pid,
                all_parties.clone(),
                t,
                setup.clone(),
                dec_share,
                h1.clone(),
                h2.clone(),
                n_tilde.clone(),
                &mut rng,
            );
            machines.push((pid, machine));
        }

        // Step 5: Run the protocol via the orchestrator
        let results = Orchestrator::new(machines, 10)
            .run()
            .expect("orchestrator must succeed");

        // Step 6: Verify all parties completed successfully
        let shares: Vec<Ggn16KeyShare<TestCurve>> = results
            .into_iter()
            .map(|r| r.expect("keygen should succeed"))
            .collect();

        // Step 7: Verify all parties agree on the public key
        let pk0_bytes = shares[0].public_key.to_bytes();
        for (i, share) in shares.iter().enumerate().skip(1) {
            assert_eq!(
                share.public_key.to_bytes(),
                pk0_bytes,
                "party {} and party 0 disagree on public key",
                i
            );
        }

        // Step 8: Verify all parties agree on alpha (global ciphertext)
        for (i, share) in shares.iter().enumerate().skip(1) {
            assert_eq!(
                share.alpha, shares[0].alpha,
                "party {} and party 0 disagree on alpha",
                i
            );
        }

        // Step 9: Verify alpha decrypts to sum(x_i) using threshold decryption.
        //
        // Important: Paillier encryption operates over integers, not mod q.
        // The decrypted value is sum(x_i) as integers, while scalar addition
        // wraps mod q.  We must compare against the integer sum.
        let mut sum_x_integer = Integer::zero();
        for share in &shares {
            let x_repr = share.secret_share.to_repr();
            sum_x_integer += Integer::from_bytes_msf(x_repr.as_ref());
        }

        // Partial decrypt alpha with all parties
        let partials: Vec<_> = shares
            .iter()
            .map(|s| partial_decrypt(&s.alpha, &s.decryption_share, &s.threshold_setup))
            .collect();

        // Combine t+1 partial decryptions
        let decrypted =
            combine_partials(&partials[0..(t as usize)], &setup).expect("combine should succeed");

        // The decrypted value should equal the integer sum of x_i values.
        assert_eq!(
            decrypted, sum_x_integer,
            "threshold decryption of alpha should equal integer sum of secret shares"
        );

        // Step 10: Verify that sum(x_i) * G equals the public key (scalar sum mod q)
        let mut sum_x_scalar = <TestCurve as elliptic_curve::CurveArithmetic>::Scalar::ZERO;
        for share in &shares {
            sum_x_scalar += share.secret_share;
        }
        let computed_pk =
            <k256::Secp256k1 as elliptic_curve::CurveArithmetic>::ProjectivePoint::GENERATOR
                * sum_x_scalar;
        assert_eq!(
            computed_pk.to_bytes(),
            pk0_bytes,
            "sum(x_i) * G should equal the agreed public key"
        );

        // Step 11: Verify public_shares are consistent
        assert_eq!(
            shares[0].public_shares.len(),
            n as usize,
            "should have n public shares"
        );
        for (i, share) in shares.iter().enumerate() {
            // Each party's public share y_i should be x_i * G
            let expected_y_i =
                <k256::Secp256k1 as elliptic_curve::CurveArithmetic>::ProjectivePoint::GENERATOR
                    * share.secret_share;
            assert_eq!(
                share.public_shares[(share.party_index - 1) as usize].to_bytes(),
                expected_y_i.to_bytes(),
                "party {i} public share should be x_i * G"
            );
        }
    }

    /// Verify that our fast_trusted_dealer_setup produces a working
    /// threshold scheme by encrypting known values, adding, and decrypting.
    #[test]
    fn fast_setup_sanity_check() {
        let mut rng = rand::thread_rng();
        let t = 1u16;
        let n = 3u16;

        let (setup, shares) = fast_trusted_dealer_setup(t, n, &mut rng);

        // Test 1: simple value
        let msg = Integer::from(42i32);
        let (ct, _nonce) = setup
            .ek
            .encrypt_with_random(&mut rng, &msg)
            .expect("encrypt should succeed");
        let partials: Vec<_> = shares
            .iter()
            .map(|s| partial_decrypt(&ct, s, &setup))
            .collect();
        let result = combine_partials(&partials[0..2], &setup).expect("combine should succeed");
        assert_eq!(result, msg, "threshold decryption should recover plaintext");

        // Test 2: encrypt 3 values, add them, decrypt the sum
        let a = Integer::from(100i32);
        let b = Integer::from(200i32);
        let c = Integer::from(300i32);
        let (ct_a, _) = setup.ek.encrypt_with_random(&mut rng, &a).expect("enc a");
        let (ct_b, _) = setup.ek.encrypt_with_random(&mut rng, &b).expect("enc b");
        let (ct_c, _) = setup.ek.encrypt_with_random(&mut rng, &c).expect("enc c");

        let ct_sum = setup.ek.oadd(&ct_a, &ct_b).expect("oadd a+b");
        let ct_sum = setup.ek.oadd(&ct_sum, &ct_c).expect("oadd +c");

        let partials: Vec<_> = shares
            .iter()
            .map(|s| partial_decrypt(&ct_sum, s, &setup))
            .collect();
        let result = combine_partials(&partials[0..2], &setup).expect("combine sum");
        assert_eq!(
            result,
            Integer::from(600i32),
            "threshold decryption of sum should be 600"
        );

        // Test 3: encrypt large values (like EC scalars)
        let x1 = Integer::from_bytes_msf(&[0xFFu8; 32]);
        let x2 = Integer::from_bytes_msf(&[0xAAu8; 32]);
        let (ct_x1, _) = setup.ek.encrypt_with_random(&mut rng, &x1).expect("enc x1");
        let (ct_x2, _) = setup.ek.encrypt_with_random(&mut rng, &x2).expect("enc x2");
        let ct_xsum = setup.ek.oadd(&ct_x1, &ct_x2).expect("oadd x");

        let partials: Vec<_> = shares
            .iter()
            .map(|s| partial_decrypt(&ct_xsum, s, &setup))
            .collect();
        let result = combine_partials(&partials[0..2], &setup).expect("combine xsum");
        let expected = x1 + x2;
        assert_eq!(result, expected, "threshold decryption of large sum");
    }

    #[test]
    fn keygen_2_of_2() {
        let mut rng = rand::thread_rng();
        let t = 2u16; // reconstruction threshold: both parties needed
        let n = 2u16;

        // trusted_dealer_setup takes corruption threshold (polynomial degree)
        let corruption_t = t - 1;
        let (setup, dec_shares) = fast_trusted_dealer_setup(corruption_t, n, &mut rng);
        let (n_tilde, h1, h2) = generate_ring_pedersen(&mut rng);
        let all_parties: Vec<PartyId> = (1..=n).map(PartyId).collect();

        let mut machines: Vec<(PartyId, Ggn16KeygenMachine<TestCurve>)> = Vec::new();
        for (i, dec_share) in dec_shares.into_iter().enumerate() {
            let pid = all_parties[i];
            let machine = Ggn16KeygenMachine::new(
                pid,
                all_parties.clone(),
                t,
                setup.clone(),
                dec_share,
                h1.clone(),
                h2.clone(),
                n_tilde.clone(),
                &mut rng,
            );
            machines.push((pid, machine));
        }

        let results = Orchestrator::new(machines, 10)
            .run()
            .expect("orchestrator must succeed");
        let shares: Vec<Ggn16KeyShare<TestCurve>> = results
            .into_iter()
            .map(|r| r.expect("keygen should succeed"))
            .collect();

        // Verify agreement on public key
        assert_eq!(
            shares[0].public_key.to_bytes(),
            shares[1].public_key.to_bytes(),
            "both parties should agree on public key"
        );

        // Verify alpha decrypts correctly (compare against integer sum, not scalar sum)
        let partials: Vec<_> = shares
            .iter()
            .map(|s| partial_decrypt(&s.alpha, &s.decryption_share, &s.threshold_setup))
            .collect();
        let decrypted = combine_partials(&partials, &setup).expect("combine should succeed");

        let mut sum_x_integer = Integer::zero();
        for share in &shares {
            let x_repr = share.secret_share.to_repr();
            sum_x_integer += Integer::from_bytes_msf(x_repr.as_ref());
        }

        assert_eq!(
            decrypted, sum_x_integer,
            "threshold decryption of alpha should equal integer sum of secret shares"
        );
    }
}
