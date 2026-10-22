// SPDX-License-Identifier: MIT OR Apache-2.0
//! Linearly Homomorphic Encryption (LHE) abstraction and generic HE-based MtA.
//!
//! **Status:** planned abstraction, not yet implemented by any primitive crate.
//! The following encryption families are intended to implement [`LheScheme`]:
//! - **Paillier** (`tecdsa-paillier`) -- used by GG18, CGGMP20, LN18
//! - **CL** (`tecdsa-class-group`) -- used by WMY23, TX25, JTX25
//! - **Joye-Libert** (`tecdsa-joye-libert`) -- used by XAL23
//!
//! All three share the same MtA protocol pattern:
//! 1. Alice encrypts `a` under her key → sends ciphertext
//! 2. Bob homomorphically computes `Enc(a*b - beta)` → sends result
//! 3. Alice decrypts → gets `alpha`; guarantee: `alpha + beta = a*b mod q`
//!
//! The [`he_mta`] module provides this protocol generically over any
//! [`LheScheme`], so the MtA logic is written once and reused across
//! Paillier, CL, and JL instantiations.

/// A linearly homomorphic encryption scheme.
///
/// Provides encrypt, decrypt, and homomorphic operations over a
/// message space $\mathbb{Z}_q$. Messages and scalars are passed as
/// decimal strings, a leftover from when the CL and Paillier backends used
/// different big-integer types; both are `rug::Integer` now.
pub trait LheScheme: 'static {
    /// Encryption context / setup parameters.
    type Setup;

    /// Public encryption key.
    type PublicKey;

    /// Secret decryption key.
    type SecretKey;

    /// Ciphertext type.
    type Ciphertext: Clone + Send;

    /// Error type.
    type Error: std::error::Error + Send + Sync;

    /// Encrypt a plaintext (decimal string) under the public key.
    fn encrypt(
        setup: &mut Self::Setup,
        pk: &Self::PublicKey,
        plaintext: &str,
    ) -> Result<Self::Ciphertext, Self::Error>;

    /// Decrypt a ciphertext using the secret key. Returns decimal string.
    fn decrypt(
        setup: &mut Self::Setup,
        sk: &Self::SecretKey,
        ct: &Self::Ciphertext,
    ) -> Result<String, Self::Error>;

    /// Homomorphic addition: $\text{Enc}(a) \oplus \text{Enc}(b) = \text{Enc}(a + b)$.
    fn homo_add(
        setup: &mut Self::Setup,
        c1: &Self::Ciphertext,
        c2: &Self::Ciphertext,
    ) -> Result<Self::Ciphertext, Self::Error>;

    /// Homomorphic scalar multiplication: $s \otimes \text{Enc}(m) = \text{Enc}(s \cdot m)$.
    fn homo_scalar_mul(
        setup: &mut Self::Setup,
        scalar: &str,
        ct: &Self::Ciphertext,
    ) -> Result<Self::Ciphertext, Self::Error>;
}

/// Generic HE-based MtA (Multiplicative-to-Additive share conversion).
///
/// Given any [`LheScheme`], this module provides the 2-step MtA protocol:
///
/// ```text
/// Alice(a, pk, sk)                    Bob(b)
///   c_a = Enc(pk, a)         →
///                             ←     c_alpha = b ⊗ c_a ⊕ Enc(pk, -beta)
///   alpha = Dec(sk, c_alpha)         Bob keeps beta
///   // alpha + beta = a*b mod q
/// ```
///
/// The "with check" variant (MtAwc) adds an EC point verification:
/// Alice checks $g^\alpha \cdot g^\beta \stackrel{?}{=} (g^b)^a$.
pub mod he_mta {
    use super::LheScheme;

    /// Alice's state after step 1 (kept between rounds).
    pub struct AliceState<L: LheScheme> {
        /// The plaintext `a` (decimal string, for the check variant).
        pub a_decimal: String,
        /// The ciphertext `Enc(pk, a)` (to send to Bob).
        pub ciphertext: L::Ciphertext,
    }

    /// Bob's output from his step.
    pub struct BobOutput<L: LheScheme> {
        /// The ciphertext `Enc(pk, a*b - beta)` (to send back to Alice).
        pub c_alpha: L::Ciphertext,
        /// Bob's additive share `beta` (decimal string, kept secret).
        pub beta_decimal: String,
    }

    /// Alice step 1: encrypt her secret `a`.
    ///
    /// Returns `(state, ciphertext_to_send_to_bob)`.
    pub fn alice_step1<L: LheScheme>(
        setup: &mut L::Setup,
        pk: &L::PublicKey,
        a_decimal: &str,
    ) -> Result<AliceState<L>, L::Error> {
        let ciphertext = L::encrypt(setup, pk, a_decimal)?;
        Ok(AliceState {
            a_decimal: a_decimal.to_string(),
            ciphertext,
        })
    }

    /// Bob's step: given Alice's ciphertext, compute his share and
    /// the response ciphertext.
    ///
    /// `neg_beta_decimal` is the negation of Bob's random share mod q,
    /// which Bob must sample externally and provide as "-beta mod q".
    pub fn bob_step<L: LheScheme>(
        setup: &mut L::Setup,
        pk_alice: &L::PublicKey,
        c_a: &L::Ciphertext,
        b_decimal: &str,
        neg_beta_decimal: &str,
    ) -> Result<BobOutput<L>, L::Error> {
        // c_alpha = b ⊗ c_a ⊕ Enc(pk, -beta)
        let b_times_ca = L::homo_scalar_mul(setup, b_decimal, c_a)?;
        let enc_neg_beta = L::encrypt(setup, pk_alice, neg_beta_decimal)?;
        let c_alpha = L::homo_add(setup, &b_times_ca, &enc_neg_beta)?;

        Ok(BobOutput {
            c_alpha,
            beta_decimal: neg_beta_decimal.to_string(),
        })
    }

    /// Alice step 2: decrypt to get her additive share `alpha`.
    ///
    /// Returns `alpha` as a decimal string. Guarantees: `alpha + beta = a*b mod q`.
    pub fn alice_step2<L: LheScheme>(
        setup: &mut L::Setup,
        sk: &L::SecretKey,
        c_alpha: &L::Ciphertext,
    ) -> Result<String, L::Error> {
        L::decrypt(setup, sk, c_alpha)
    }
}
