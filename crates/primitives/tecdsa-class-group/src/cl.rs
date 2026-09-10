#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
// SPDX-License-Identifier: MIT OR Apache-2.0
//! CL-HSM encryption: key generation, encryption, decryption, and
//! homomorphic operations.
//!
//! The main entry point is [`ClSetup`], which initialises a CL-HSMqk scheme
//! and provides access to the class group context, random-number generator, and
//! scheme parameters.

use std::{borrow::Borrow, sync::Arc};

use rug::{ops::Pow, Complete, Integer};

pub use self::{Ciphertext as ClCiphertext, PublicKey as ClPublicKey, SecretKey as ClSecretKey};
pub use crate::class_group::{
    error::{parse_int_auto, ClassGroupError},
    qfi::{ClassGroup, FixedBaseComb, QFI, QFI as Qfi},
    rand::RandGen,
};

/// Error type for class-group operations.
#[derive(Debug, thiserror::Error)]
pub enum ClError {
    /// An error originating from class group operations
    #[error("class group: {0}")]
    ClassGroup(#[from] ClassGroupError),

    /// Invalid parameter supplied to a class-group operation.
    #[error("invalid parameter: {0}")]
    InvalidParam(String),
}

/// Result alias for class-group operations.
pub type ClResult<T> = Result<T, ClError>;

/// Initialised CL-HSMqk class-group scheme.
///
/// The heavy, immutable scheme data ([`CL_HSMqk`], which embeds the fixed-base
/// comb table for `h` — ~256 class-group elements) is held behind an [`Arc`],
/// so cloning a `ClSetup` only bumps the refcount and copies the small mutable
/// PRNG state, rather than deep-copying the comb table. This matters because
/// benchmarks and per-party protocol setup clone the setup many times.
#[derive(Clone)]
pub struct ClSetup {
    rng: RandGen,
    cl: Arc<CL_HSMqk>,
}

impl std::fmt::Debug for ClSetup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClSetup").finish_non_exhaustive()
    }
}

/// The secp256k1 curve order `q` as a decimal string.
pub const SECP256K1_ORDER: &str =
    "115792089237316195423570985008687907852837564279074904382605163141518161494337";

/// A 1572-bit prime `p` for 128-bit security CL-HSMqk with secp256k1.
///
/// Satisfies: p ≡ 3 (mod 4), p prime, Legendre(q, p) = -1.
/// Gives |Delta_K| = |p * q| = 1828 bits (lambda = 914).
/// Matches the security level in Trout (eprint 2020/196) and WMY23 (|Delta_q| = 1860).
pub const SECP256K1_CL_PRIME_128BIT: &str =
    "165427457039117011823074561613444035351792492968921911807749264167080539287954032009049341053817071909297408790078970165320482418378310001089994560969562298297850775105757501192300518402392755866330857379154546192687115362055161787245008991873302392117599634534192225466830770950397155986355417462441267574549737435039212228475528923355314428234034516940321913098953375361830573701543197780605487019385455259679887245284016137256968388198675036060069434723034369192376576943";

impl ClSetup {
    /// Creates a new CL-HSMqk setup for secp256k1 using the
    /// known-good class-group prime from test vectors.
    ///
    /// This uses `q = secp256k1 order`, `k = 1`, and a prime `p`
    /// satisfying the required congruence and Kronecker-symbol
    /// constraints for a fundamental discriminant `Delta_K = -p*q`.
    ///
    /// `seed` seeds the internal PRNG for deterministic testing.
    /// In production, pass a cryptographically random seed.
    ///
    /// Takes anything convertible into an [`Integer`], so a literal seed needs
    /// no wrapping: both `new_secp256k1(12345u64)` and
    /// `new_secp256k1(&seed_integer)` work. Setup is a one-time cost dominated
    /// by prime generation, so the clone `&Integer` incurs is irrelevant here;
    /// the arithmetic methods below still take `&Integer` to avoid it.
    pub fn new_secp256k1(seed: impl Into<Integer>) -> ClResult<Self> {
        // For secp256k1, q ≡ 1 (mod 4), so we need p ≡ 3 (mod 4) and p prime,
        // with Legendre(q, p) = -1, to make Delta_K = -p*q fundamental.
        //
        // p = 7 satisfies: 7 ≡ 3 (mod 4), 7*q ≡ 3 (mod 4) => -7*q ≡ 1 (mod 4),
        // and q mod 7 = 3 which is a QNR mod 7, so Legendre(q, 7) = -1.
        //
        // NOTE: This gives a tiny discriminant (insecure!) suitable only for
        // fast testing. Use `new_secp256k1_128bit` for 128-bit security.
        Self::new_custom(parse_int_auto(SECP256K1_ORDER)?, 1, 7u64, seed)
    }

    /// Creates a CL-HSMqk setup for secp256k1 with 128-bit security.
    ///
    /// Uses a 1572-bit prime p giving |Delta_K| = 1828 bits, matching
    /// the standard 128-bit security level (lambda = 914) from
    /// <https://eprint.iacr.org/2020/196>.
    ///
    /// This matches the security parameters used by:
    /// - WMY23 (|Delta_q| = 1860)
    /// - Trout (SecurityLevel::OneHundredTwentyEightBit, lambda = 914)
    pub fn new_secp256k1_128bit(seed: impl Into<Integer>) -> ClResult<Self> {
        Self::new_custom(
            parse_int_auto(SECP256K1_ORDER)?,
            1,
            parse_int_auto(SECP256K1_CL_PRIME_128BIT)?,
            seed,
        )
    }

    /// Creates a CL-HSMqk setup with custom parameters.
    ///
    /// - `q`: the prime order of the plaintext group.
    /// - `k`: the power parameter (plaintext space is `Z/q^k`).
    /// - `p`: the class-group prime.
    /// - `seed`: PRNG seed.
    pub fn new_custom(
        q: impl Into<Integer>,
        k: u32,
        p: impl Into<Integer>,
        seed: impl Into<Integer>,
    ) -> ClResult<Self> {
        let mut randgen = RandGen::new();
        randgen.set_seed(&seed.into());

        let cl = CL_HSMqk::new(&q.into(), k as usize, &p.into(), Params::default())?;

        Ok(Self {
            rng: randgen,
            cl: Arc::new(cl),
        })
    }

    // ── Accessors ──────────────────────────────────────────────────────

    /// Returns a mutable reference to the PRNG.
    pub fn rng(&mut self) -> &mut RandGen {
        &mut self.rng
    }

    /// Returns a reference to the CL-HSMqk scheme instance.
    #[must_use]
    pub fn cl(&self) -> &CL_HSMqk {
        &self.cl
    }

    // ── Key generation ─────────────────────────────────────────────────

    /// Generates a fresh CL-HSMqk key pair.
    pub fn keygen(&mut self) -> ClResult<(SecretKey, PublicKey)> {
        let sk = self.cl.keygen_secret(&mut self.rng);
        let pk = self.cl.keygen_public(&sk);
        Ok((sk, pk))
    }

    // ── Encryption / Decryption ────────────────────────────────────────

    /// Encrypts a plaintext.
    pub fn encrypt(&mut self, pk: &PublicKey, m: &Integer) -> ClResult<Ciphertext> {
        Ok(self.cl.encrypt(
            pk,
            &Cleartext::from_mpz(&self.cl, m.clone())?,
            &mut self.rng,
        ))
    }

    /// Encrypts with explicit randomness (deterministic encryption).
    pub fn encrypt_with_r(&self, pk: &PublicKey, m: &Integer, r: &Integer) -> ClResult<Ciphertext> {
        Ok(self
            .cl
            .encrypt_with_randomness(pk, &Cleartext::from_mpz(&self.cl, m.clone())?, r))
    }

    /// Decrypts a ciphertext, returning the plaintext.
    pub fn decrypt(&self, sk: &SecretKey, ct: &Ciphertext) -> ClResult<Integer> {
        Ok(self.cl.decrypt(sk, ct).as_mpz().clone())
    }

    // ── Homomorphic operations ─────────────────────────────────────────

    /// Homomorphic addition: `Enc(a) + Enc(b) = Enc(a + b mod q^k)`.
    pub fn add_ciphertexts(
        &mut self,
        pk: &PublicKey,
        ca: &Ciphertext,
        cb: &Ciphertext,
    ) -> ClResult<Ciphertext> {
        Ok(self.cl.add_ciphertexts(pk, ca, cb, &mut self.rng))
    }

    /// Homomorphic scalar multiplication: `s * Enc(m) = Enc(s * m mod q^k)`.
    pub fn scal_ciphertext(
        &mut self,
        pk: &PublicKey,
        ct: &Ciphertext,
        s: &Integer,
    ) -> ClResult<Ciphertext> {
        Ok(self.cl.scal_ciphertexts(pk, ct, s, &mut self.rng))
    }

    // ── Subgroup operations ────────────────────────────────────────────

    /// Computes `h^e` (power of the hidden-order generator).
    pub fn power_of_h(&self, e: &Integer) -> ClResult<Qfi> {
        Ok(self.cl.power_of_h(e))
    }

    /// Computes `f^m` in the cyclic subgroup `F` (the message subgroup).
    pub fn power_of_f(&self, m: &Integer) -> ClResult<Qfi> {
        Ok(self.cl.power_of_f(m))
    }

    /// Discrete log of `fm = f^m` in `F`, returning `m`.
    #[allow(non_snake_case)]
    pub fn dlog_in_F(&self, fm: &Qfi) -> ClResult<Integer> {
        Ok(self.cl.dlog_in_F(fm))
    }

    /// QFI exponentiation in `Cl(Delta)`: `f^n`.
    pub fn exp(&self, f: &Qfi, n: &Integer) -> ClResult<Qfi> {
        let cl_delta = self.cl.cl_delta();
        Ok(cl_delta.exp(f, n))
    }

    /// Export secret key as an `Integer`.
    pub fn sk_to_integer(&self, sk: &SecretKey) -> Integer {
        sk.as_mpz().clone()
    }

    /// Import secret key from an `Integer`.
    pub fn sk_from_integer(&self, v: &Integer) -> ClResult<SecretKey> {
        Ok(SecretKey::from_mpz(&self.cl, v.clone())?)
    }

    /// Secret key bound.
    pub fn secretkey_bound(&self) -> &Integer {
        self.cl.secretkey_bound()
    }

    // ── Class-group QFI utilities ──────────────────────────────────────

    /// Composes two QFI elements in `Cl(Delta)`: `f1 * f2`.
    pub fn compose(&self, f1: &Qfi, f2: &Qfi) -> ClResult<Qfi> {
        let cl_delta = self.cl.cl_delta();
        Ok(cl_delta.compose(f1, f2))
    }

    /// Simultaneous multi-exponentiation `∏ bases[i]^exps[i]` in `Cl(Δ)`.
    /// `exps` is signed (`Integer` carries a sign), so a negative exponent
    /// naturally inverts its base. Shares one squaring chain across all bases
    /// (see [`ClassGroup::multiexp`]); far cheaper than folding `n` independent
    /// [`exp`](Self::exp) results with [`compose`](Self::compose).
    pub fn multiexp(&self, bases: &[impl Borrow<Qfi>], exps: &[Integer]) -> ClResult<Qfi> {
        Ok(self.cl.cl_delta().multiexp(bases, exps))
    }

    /// `pk^e` using the public key's fixed-base comb when possible. The comb
    /// is built lazily on `pk` and reused, so the O(n) per-peer Schnorr
    /// verifies that raise the *same* `pk` to a response `z` amortise one
    /// table build instead of doing `n` bare variable-base exps. Falls back
    /// to a bare exp for the compact variant (where `pk ∈ Cl(Δ_K)`) or for
    /// exponents beyond the comb's range.
    pub fn pk_pow(&self, pk: &PublicKey, e: &Integer) -> ClResult<Qfi> {
        if !self.cl.compact_variant {
            let comb = pk.comb(&self.cl);
            if e.significant_bits() as usize <= comb.max_bits() {
                return Ok(self.cl.cl_delta.exp_comb(comb, e));
            }
        }
        Ok(self.cl.cl_delta.exp(pk.elt(), e))
    }

    /// Returns the identity element of `Cl(Delta)`.
    pub fn identity(&self) -> ClResult<Qfi> {
        let cl_delta = self.cl.cl_delta();
        Ok(cl_delta.identity())
    }

    /// Returns the ciphertext components `(c1, c2)`.
    pub fn ct_components(&self, ct: &Ciphertext) -> ClResult<(Qfi, Qfi)> {
        let c1 = ct.c1().clone();
        let c2 = ct.c2().clone();
        Ok((c1, c2))
    }

    /// Builds a ciphertext from QFI components `(c1, c2)`.
    pub fn ct_from_components(&self, c1: &Qfi, c2: &Qfi) -> ClResult<Ciphertext> {
        Ok(Ciphertext::new(c1.clone(), c2.clone()))
    }

    /// Constructs a public key from a QFI element.
    pub fn pk_from_qfi(&self, qfi: &Qfi) -> ClResult<PublicKey> {
        Ok(PublicKey::from_qfi(&self.cl, qfi.clone())?)
    }
}

/// Number of comb blocks for fixed-base precomputation (table size `2^COMB_BLOCKS`).
const COMB_BLOCKS: usize = 8;

/// Genus of a form: the pair of genus characters, each `-1` or `1`.
pub type Genus = (i32, i32);

/// Tunable parameters for an instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// Statistical-distance parameter controlling the secret/randomness bound:
    /// the bound is `classnumber_upper_bound(Δ_K) · 2^(distance-2)`, giving a
    /// sampling distribution within `2^(-distance)` statistical distance of
    /// uniform over the (unknown) group order.
    pub distance: usize,
    /// Use the compact variant (store/transmit `pk`/`c1` in `Cl(Δ_K)`).
    pub compact_variant: bool,
}

impl Default for Params {
    fn default() -> Self {
        Params {
            distance: 42,
            compact_variant: false,
        }
    }
}

/// A CL-HSM_qk instance (public parameters and derived data).
#[derive(Clone, Debug)]
pub struct CL_HSMqk {
    pub(crate) q: Integer,
    pub(crate) k: usize,
    pub(crate) p: Integer,
    pub(crate) m: Integer, // M = q^k
    pub(crate) delta_k: Integer,
    pub(crate) delta: Integer,
    pub(crate) cl_delta_k: ClassGroup,
    pub(crate) cl_delta: ClassGroup,
    pub(crate) cl_g: ClassGroup,
    pub(crate) h: QFI,
    pub(crate) h_comb: FixedBaseComb,
    /// Compact-variant generator `γ = π(h)^M ∈ Cl(Δ_K)`.
    pub(crate) gamma: QFI,
    pub(crate) compact_variant: bool,
    pub(crate) large_message_variant: bool,
    pub(crate) secretkey_bound: Integer,
    pub(crate) cleartext_bound: Integer,
    pub(crate) encrypt_randomness_bound: Integer,
    pub(crate) lambda_distance: usize,
}

const MR_REPS: u32 = 30;

impl CL_HSMqk {
    // --- constructors ------------------------------------------------------

    /// Build an instance from explicit `q`, `k`, `p`.
    ///
    /// Requires: `q` an odd prime; `p` equal to `1` or an odd prime;
    /// `p·q ≡ 3 (mod 4)`; and (when `p ≠ 1`) Kronecker `(p | q) = -1`.
    pub fn new(
        q: &Integer,
        k: usize,
        p: &Integer,
        params: Params,
    ) -> Result<CL_HSMqk, ClassGroupError> {
        if k == 0 {
            return Err(ClassGroupError::InvalidParameter("k must be >= 1".into()));
        }
        if q.is_even() || q.is_probably_prime(MR_REPS) == rug::integer::IsPrime::No {
            return Err(ClassGroupError::InvalidParameter(
                "q must be an odd prime".into(),
            ));
        }
        let p_is_one = *p == 1u64;
        if !p_is_one && (p.is_even() || p.is_probably_prime(MR_REPS) == rug::integer::IsPrime::No) {
            return Err(ClassGroupError::InvalidParameter(
                "p must be 1 or an odd prime".into(),
            ));
        }
        let pq = (p * q).complete();
        if pq.modulo_ref(&Integer::from(4u64)).complete() != 3u64 {
            return Err(ClassGroupError::InvalidParameter(
                "must have p·q ≡ 3 (mod 4)".into(),
            ));
        }
        if !p_is_one && p.kronecker(q) != -1 {
            return Err(ClassGroupError::InvalidParameter(
                "must have Kronecker (p|q) = -1".into(),
            ));
        }

        // Δ_K = -p·q ;  Δ = q^{2k}·Δ_K = -p·q^{2k+1}
        let delta_k = -pq;
        let m = q.clone().pow(k as u32); // M = q^k
        let q2k = q.clone().pow(2 * k as u32);
        let delta = (&q2k * &delta_k).complete();

        let cl_delta_k = ClassGroup::new(delta_k.clone());
        let cl_delta = ClassGroup::new(delta.clone());
        let cl_g = cl_delta.clone();

        // Hard-subgroup generator: smallest split prime form, squared (→ the
        // principal genus / squares subgroup), raised to M = q^k (→ H).
        let h = build_h(&cl_delta, &m, q, p);

        // Large-message regime ⇔ f^m forms are not reduced ⇔ q^{2k} > (1-Δ_K)/4.
        let c_f = (Integer::from(1u64) - &delta_k) >> 2u32;
        let large_message_variant = q2k > c_f;

        // Bounds.
        let cleartext_bound = m.clone();
        let cn_bound = classnumber_upper_bound(&delta_k);
        let dist = params.distance.max(2);
        let secretkey_bound = cn_bound << (dist - 2) as u32;
        let encrypt_randomness_bound = secretkey_bound.clone();

        // Fixed-base comb for h. Sized to also cover unbounded ZK responses
        // z = a + e·sk (a ~ secretkey_bound, e ~ q, sk ~ secretkey_bound), so the
        // Schnorr verify checks `power_of_h(z)` stay on the comb instead of
        // falling back to a bare exp. The comb's table size is fixed (2^blocks);
        // only the per-block length grows, so the extra cost is marginal.
        let exp_bits = (secretkey_bound.significant_bits() + q.significant_bits() + 2) as usize;
        let h_comb = cl_delta.precompute_comb(&h, exp_bits, COMB_BLOCKS);

        // Compact-variant generator γ = π(h)^M ∈ Cl(Δ_K).
        let pi_h = {
            let mut g = h.to_maximal_order(&m, &delta_k);
            cl_delta_k.reduce(&mut g);
            g
        };
        let gamma = cl_delta_k.exp(&pi_h, &m);

        Ok(CL_HSMqk {
            q: q.clone(),
            k,
            p: p.clone(),
            m,
            delta_k,
            delta,
            cl_delta_k,
            cl_delta,
            cl_g,
            h,
            h_comb,
            gamma,
            compact_variant: params.compact_variant,
            large_message_variant,
            secretkey_bound,
            cleartext_bound,
            encrypt_randomness_bound,
            lambda_distance: params.distance,
        })
    }

    pub fn with_random_p(
        q: &Integer,
        k: usize,
        delta_k_nbits: usize,
        rng: &mut RandGen,
        params: Params,
    ) -> Result<CL_HSMqk, ClassGroupError> {
        if q.is_even() || q.is_probably_prime(MR_REPS) == rug::integer::IsPrime::No {
            return Err(ClassGroupError::InvalidParameter(
                "q must be an odd prime".into(),
            ));
        }
        let qbits = q.significant_bits() as usize;
        let p = if delta_k_nbits <= qbits + 1 {
            // q is already large enough: use p = 1 if possible.
            if q.modulo_ref(&Integer::from(4u64)).complete() == 3u64 {
                Integer::from(1u64)
            } else {
                smallest_aux_prime(q)
            }
        } else {
            gen_aux_prime(q, delta_k_nbits - qbits, rng)
        };
        Self::new(q, k, &p, params)
    }

    pub fn with_random_q(
        q_nbits: usize,
        k: usize,
        delta_k_nbits: usize,
        rng: &mut RandGen,
        params: Params,
    ) -> Result<CL_HSMqk, ClassGroupError> {
        let q = rng.random_prime(q_nbits);
        Self::with_random_p(&q, k, delta_k_nbits, rng, params)
    }

    pub fn with_compact_variant(&self, compact_variant: bool) -> CL_HSMqk {
        let mut c = self.clone();
        c.compact_variant = compact_variant;
        c
    }

    // --- accessors ---------------------------------------------------------

    pub fn q(&self) -> &Integer {
        &self.q
    }
    pub fn k(&self) -> usize {
        self.k
    }
    pub fn p(&self) -> &Integer {
        &self.p
    }
    pub fn m(&self) -> &Integer {
        &self.m
    }
    pub fn cl_delta_k(&self) -> &ClassGroup {
        &self.cl_delta_k
    }
    pub fn cl_delta(&self) -> &ClassGroup {
        &self.cl_delta
    }
    pub fn cl_g(&self) -> &ClassGroup {
        &self.cl_g
    }
    pub fn delta_k(&self) -> &Integer {
        &self.delta_k
    }
    pub fn delta(&self) -> &Integer {
        &self.delta
    }
    pub fn h(&self) -> &QFI {
        &self.h
    }
    pub fn compact_variant(&self) -> bool {
        self.compact_variant
    }
    pub fn large_message_variant(&self) -> bool {
        self.large_message_variant
    }
    pub fn secretkey_bound(&self) -> &Integer {
        &self.secretkey_bound
    }
    pub fn cleartext_bound(&self) -> &Integer {
        &self.cleartext_bound
    }
    pub fn encrypt_randomness_bound(&self) -> &Integer {
        &self.encrypt_randomness_bound
    }
    pub fn lambda_distance(&self) -> usize {
        self.lambda_distance
    }

    // --- subgroup ops ------------------------------------------------------

    /// `h^n` in `Cl(Δ)`.                                           
    ///                                                             
    /// Uses the fixed-base comb table for `h` when `n` fits its precomputed
    /// range (secret-key / randomness sized). For a larger exponent — e.g. an
    /// unbounded Schnorr response `z = a + e·sk` — it falls back to the general
    /// variable-base [`exp`](ClassGroup::exp), because the comb would otherwise
    /// silently drop `n`'s high bits.
    pub fn power_of_h(&self, n: &Integer) -> QFI {
        if n.cmp0().is_lt() {
            return self.cl_delta.inverse(&self.power_of_h(&Integer::from(-n)));
        }
        if n.significant_bits() as usize <= self.h_comb.max_bits() {
            self.cl_delta.exp_comb(&self.h_comb, n)
        } else {
            self.cl_delta.exp(&self.h, n)
        }
    }

    /// `f^m`, computed via the Theorem-5 isomorphism (no group exponentiation).
    pub fn power_of_f(&self, m: &Integer) -> QFI {
        let mm = m.modulo_ref(&self.m).complete();
        if mm.is_zero() {
            return self.cl_delta.identity();
        }
        let t = self.ring_param_from_exponent(&mm);
        self.form_from_ring_param(&t)
    }

    /// Discrete log of `fm = f^m` in `F`, returning `m ∈ [0, q^k)`.
    ///
    /// Handles both regimes. In the small-message regime (`q^{2k} ≤ (1-Δ_K)/4`)
    /// the reduced form already exposes the `(q^{2j}, u·q^j, ·)` shape. In the
    /// large-message regime the reduced `f^m` no longer does, so for `k = 1` we
    /// recover `m` from the principal-ideal generator of `f^m`'s go-up image
    /// (see [`Self::dlog_in_F_large_k1`]).
    pub fn dlog_in_F(&self, fm: &QFI) -> Integer {
        if *fm.a() == 1 {
            return Integer::new();
        }
        if self.large_message_variant {
            assert_eq!(
                self.k, 1,
                "large-message dlog_in_F is implemented for k = 1 only \
                 (use small-message parameters for k > 1)"
            );
            return self.dlog_in_F_large_k1(fm);
        }
        if self.k == 1 {
            // reduced form is (q², q·u, ·) with u ≡ m^{-1} (mod q); m = u^{-1}.
            let u = fm.b().clone().div_exact(&self.q);
            return u
                .invert_ref(&self.q)
                .map(Integer::from)
                .expect("dlog: form not in F")
                .modulo(&self.q);
        }
        self.dlog_in_F_general(fm)
    }

    /// Lift a form of discriminant `Δ_K` to the corresponding class of `Δ`
    /// (the ideal "go-down" map of HJPT98/CL09): keep `a`, scale `b` by the
    /// conductor `M = q^k` and `c` by `M²`, then reduce in `Cl(Δ)`.
    pub fn from_cl_delta_k_to_cl_delta(&self, f: &mut QFI) {
        let mut lifted = f.lift(&self.m);
        self.cl_delta.reduce(&mut lifted);
        *f = lifted;
    }

    /// Go-up surjection `π: Cl(Δ) → Cl(Δ_K)` (HJPT98 Alg. 3 / CL09 Alg. 2).
    pub fn to_cl_delta_k(&self, f: &QFI) -> QFI {
        let mut g = f.to_maximal_order(&self.m, &self.delta_k);
        self.cl_delta_k.reduce(&mut g);
        g
    }

    /// Compact-variant lift `ψ: Cl(Δ_K) → Cl(Δ)`, `ψ(ω) = (go-down ω)^M`.
    fn psi(&self, omega: &QFI) -> QFI {
        let mut lifted = omega.clone();
        self.from_cl_delta_k_to_cl_delta(&mut lifted);
        self.cl_delta.exp(&lifted, &self.m)
    }

    /// The class group in which `c1` and `pk` live (`Cl(Δ_K)` compact, else `Cl(Δ)`).
    fn c1_group(&self) -> &ClassGroup {
        if self.compact_variant {
            &self.cl_delta_k
        } else {
            &self.cl_delta
        }
    }

    /// `c1 = generator^r`.
    fn enc_c1(&self, r: &Integer) -> QFI {
        if self.compact_variant {
            self.cl_delta_k.exp(&self.gamma, r)
        } else {
            self.power_of_h(r)
        }
    }

    /// The `Cl(Δ)` factor multiplied into `c2` next to `f^m`: `pk^r`, lifted by
    /// `ψ` in the compact variant.
    fn enc_mask(&self, pk: &PublicKey, r: &Integer) -> QFI {
        if self.compact_variant {
            self.psi(&self.cl_delta_k.exp(pk.elt(), r))
        } else {
            self.cl_delta.exp_comb(pk.comb(self), r)
        }
    }

    /// Genus characters `((v|p), (v|q))` for a value `v` represented by `f`
    /// and coprime to `p·q`. `(1, 1)` means the principal genus (a square).
    pub fn genus(&self, f: &QFI) -> Genus {
        let pq = (&self.p * &self.q).complete();
        let one = Integer::from(1u64);
        let candidates = [
            f.a().clone(),
            f.c().clone(),
            (f.a() + f.b()).complete() + f.c(), // f(1,1) = a+b+c
        ];
        let v = candidates
            .into_iter()
            .find(|c| c.gcd_ref(&pq).complete() == one)
            .expect("no represented value coprime to p·q");
        (v.kronecker(&self.p), v.kronecker(&self.q))
    }

    // --- crypto ------------------------------------------------------------

    pub fn keygen_secret(&self, rng: &mut RandGen) -> SecretKey {
        SecretKey::random(self, rng)
    }
    pub fn keygen_public(&self, sk: &SecretKey) -> PublicKey {
        PublicKey::from_secret(self, sk)
    }

    pub fn encrypt(&self, pk: &PublicKey, m: &Cleartext, rng: &mut RandGen) -> Ciphertext {
        let r = rng.random_mpz(&self.encrypt_randomness_bound);
        self.encrypt_with_randomness(pk, m, &r)
    }

    pub fn encrypt_with_randomness(
        &self,
        pk: &PublicKey,
        m: &Cleartext,
        r: &Integer,
    ) -> Ciphertext {
        let c1 = self.enc_c1(r);
        let c2 = self
            .cl_delta
            .compose(&self.power_of_f(m.as_mpz()), &self.enc_mask(pk, r));
        Ciphertext::new(c1, c2)
    }

    pub fn decrypt(&self, sk: &SecretKey, c: &Ciphertext) -> Cleartext {
        // a = c2 · (c1^sk)^{-1}, lifting c1^sk by ψ in the compact variant.
        let c1sk = self.c1_group().exp(c.c1(), sk.as_mpz());
        let factor = if self.compact_variant {
            self.psi(&c1sk)
        } else {
            c1sk
        };
        let a = self
            .cl_delta
            .compose(c.c2(), &self.cl_delta.inverse(&factor));
        Cleartext(self.dlog_in_F(&a))
    }

    pub fn add_ciphertexts(
        &self,
        pk: &PublicKey,
        ca: &Ciphertext,
        cb: &Ciphertext,
        rng: &mut RandGen,
    ) -> Ciphertext {
        let r = rng.random_mpz(&self.encrypt_randomness_bound);
        self.add_ciphertexts_with_randomness(pk, ca, cb, &r)
    }

    pub fn add_ciphertexts_with_randomness(
        &self,
        pk: &PublicKey,
        ca: &Ciphertext,
        cb: &Ciphertext,
        r: &Integer,
    ) -> Ciphertext {
        let g1 = self.c1_group();
        let d = &self.cl_delta;
        let c1 = g1.compose(&g1.compose(ca.c1(), cb.c1()), &self.enc_c1(r));
        let c2 = d.compose(&d.compose(ca.c2(), cb.c2()), &self.enc_mask(pk, r));
        Ciphertext::new(c1, c2)
    }

    pub fn add_cleartexts(&self, ma: &Cleartext, mb: &Cleartext) -> Cleartext {
        Cleartext((ma.as_mpz() + mb.as_mpz()).complete().modulo(&self.m))
    }

    pub fn scal_ciphertexts(
        &self,
        pk: &PublicKey,
        c: &Ciphertext,
        s: &Integer,
        rng: &mut RandGen,
    ) -> Ciphertext {
        let r = rng.random_mpz(&self.encrypt_randomness_bound);
        self.scal_ciphertexts_with_randomness(pk, c, s, &r)
    }

    pub fn scal_ciphertexts_with_randomness(
        &self,
        pk: &PublicKey,
        c: &Ciphertext,
        s: &Integer,
        r: &Integer,
    ) -> Ciphertext {
        let g1 = self.c1_group();
        let d = &self.cl_delta;
        let c1 = g1.compose(&g1.exp(c.c1(), s), &self.enc_c1(r));
        let c2 = d.compose(&d.exp(c.c2(), s), &self.enc_mask(pk, r));
        Ciphertext::new(c1, c2)
    }

    pub fn scal_cleartexts(&self, m: &Cleartext, s: &Integer) -> Cleartext {
        Cleartext((m.as_mpz() * s).complete().modulo(&self.m))
    }

    /// `addscal(ca, cb, s)` decrypts to `m_a + s·m_b (mod M)`.
    pub fn addscal_ciphertexts(
        &self,
        pk: &PublicKey,
        ca: &Ciphertext,
        cb: &Ciphertext,
        s: &Integer,
        rng: &mut RandGen,
    ) -> Ciphertext {
        let r = rng.random_mpz(&self.encrypt_randomness_bound);
        self.addscal_ciphertexts_with_randomness(pk, ca, cb, s, &r)
    }

    pub fn addscal_ciphertexts_with_randomness(
        &self,
        pk: &PublicKey,
        ca: &Ciphertext,
        cb: &Ciphertext,
        s: &Integer,
        r: &Integer,
    ) -> Ciphertext {
        let g1 = self.c1_group();
        let d = &self.cl_delta;
        let c1 = g1.compose(&g1.compose(ca.c1(), &g1.exp(cb.c1(), s)), &self.enc_c1(r));
        let c2 = d.compose(
            &d.compose(ca.c2(), &d.exp(cb.c2(), s)),
            &self.enc_mask(pk, r),
        );
        Ciphertext::new(c1, c2)
    }

    // --- internal helpers --------------------------------------------------

    /// Map exponent `m` to the ring parameter `t` with `(1+√Δ_K)^m ≅ 1+t√Δ_K`
    /// in `G_{q^k}`, via Lucas sequences (`P=1`, `Q=(1-Δ_K)/4`).
    fn ring_param_from_exponent(&self, m: &Integer) -> Integer {
        let n = &self.m; // modulus q^k
        let p_param = Integer::from(1u64);
        let q_param = (Integer::from(1u64) - &self.delta_k) >> 2u32; // (1-Δ_K)/4
        let (u_l, v_l) = lucas_uv(&p_param, &q_param, m, n, &self.delta_k);
        (&u_l * &v_l.invert(n).expect("V_m invertible mod q^k"))
            .complete()
            .modulo(n)
    }

    /// Theorem-5 map `1 + t√Δ_K  ↦  (q^{2j}, u·q^j, (u² - q^{2(k-j)}Δ_K)/4)`.
    fn form_from_ring_param(&self, t: &Integer) -> QFI {
        if t.is_zero() {
            return self.cl_delta.identity();
        }
        let v = val_q(t, &self.q);
        let j = self.k - v;
        let qj = self.q.clone().pow(j as u32);
        let qv = self.q.clone().pow(v as u32);
        let two_qj = (&qj << 1u32).complete();
        let w = t.clone().div_exact(&qv); // t / q^v, coprime to q
                                          // u ≡ w^{-1} (mod q^j), lifted to its odd representative in (-q^j, q^j].
                                          // (u must be odd so that b = u·q^j has the same parity as Δ.)
        let inv = w.modulo(&qj).invert(&qj).expect("w invertible mod q^j");
        let u_pos = if inv.is_odd() { inv } else { inv + &qj };
        let u = center(u_pos, &two_qj, &qj);
        let a = (&qj * &qj).complete(); // q^{2j}
        let b = &u * qj;
        let c = (u.square() - qv.square() * &self.delta_k).div_exact(&Integer::from(4u64));
        let mut form = QFI::from_abc(a, b, c);
        self.cl_delta.reduce(&mut form);
        form
    }

    /// `dlog_in_F` for `k > 1` (BICYCL Algorithm 13): recover the ring parameter
    /// `t` with `1 + t√Δ_K ≅ (1+√Δ_K)^m`, then peel the base-`q` digits of `m`
    /// in the ring `Z[√Δ_K]/q^k` (each step costs only a power-`q`, not a
    /// power-`q^{k-i}`).
    fn dlog_in_F_general(&self, fm: &QFI) -> Integer {
        let n = &self.m; // N = q^k
        let dk = self.delta_k.modulo_ref(n).complete(); // Δ_K mod N

        // 1. Recover the ring parameter t of f^m from the reduced form
        //    fm = (q^{2j}, u·q^j, ·).
        let val = val_q(fm.a(), &self.q); // a = q^{2j}
        let j = val / 2;
        let qj = self.q.clone().pow(j as u32);
        let v = self.k - j;
        let qv = self.q.clone().pow(v as u32);
        let u = fm.b().clone().div_exact(&qj);
        let t0 = (qv * u.invert(&qj).expect("u invertible mod q^j")).modulo(n);

        // 2. Digit recovery: cur = 1 + t0√Δ_K, alpha = 1 + √Δ_K.
        let mut cur = (Integer::from(1u64), t0);
        let mut alpha = (Integer::from(1u64), Integer::from(1u64));
        let mut m_acc = Integer::new();
        let mut qi = Integer::from(1u64); // q^i
        for _ in 0..self.k {
            // normalize cur to 1 + tc√Δ_K: tc = f · e^{-1} (mod N)
            let e_inv = cur
                .0
                .invert_ref(n)
                .map(Integer::from)
                .expect("e invertible mod q^k");
            let tc = (&cur.1 * e_inv).modulo(n);
            let mi = tc.div_exact(&qi).modulo(&self.q); // m_i = (tc / q^i) mod q
                                                        // cur ← cur · alpha^{-m_i}
            let a_mi = ring_pow(&alpha, &mi, &dk, n);
            let a_mi_inv = ring_inv(&a_mi, &dk, n);
            cur = ring_mul(&cur, &a_mi_inv, &dk, n);
            // alpha ← alpha^q
            alpha = ring_pow(&alpha, &self.q, &dk, n);
            m_acc += mi * &qi;
            qi *= &self.q;
        }
        m_acc
    }

    /// Large-message discrete log in `F` for `k = 1` (the `Δ = q²·Δ_K` regime,
    /// where a reduced `f^m` no longer has the revealing `(q², q·m⁻¹, ·)` shape).
    ///
    /// `f^m ∈ F = ker(π: Cl(Δ) → Cl(Δ_K))`, so its go-up image
    /// [`to_maximal_order`](QFI::to_maximal_order) is the *principal* class of
    /// `Cl(Δ_K)`. Reducing that (unreduced) principal form to the identity
    /// recovers the generator `γ` of its ideal. Because `Δ_K = -p·q ≡ 0 (mod q)`,
    /// the reduction `O_K/q ≅ (Z/q)[ε]/(ε²)` is the dual numbers (`ε = √Δ_K`),
    /// where `(½(1+ε))^m ≡ 2⁻ᵐ(1 + m·ε)`; the `F`-isomorphism therefore sends
    /// `f^m ↦ 1 + m·ε`, so `m` is the `ε`-coordinate of the normalized `γ`.
    fn dlog_in_F_large_k1(&self, fm: &QFI) -> Integer {
        let q = &self.q;
        // Go up to Cl(Δ_K): an unreduced principal form (A, B′, C′).
        let g = fm.to_maximal_order(q, &self.delta_k);
        // Reduce to the identity, tracking the generator's *numerator*
        // N = γ·∏(2cᵢ) = e + f·√Δ_K (the ∏2cᵢ denominator cancels below). The
        // F-isomorphism sends f^m ↦ 1 + m·ε (ε = √Δ_K), so with γ normalized to
        // 1 + m·ε we have m = (√Δ_K-coord)/(rational-coord) of γ, and the
        // calibration sign gives m = −f·e⁻¹ (mod q).
        let (e, f) = reduce_track_generator(&g, q);
        if !e.is_zero() {
            // Fast path (e ≢ 0 mod q, i.e. no bᵢ ≡ 0 mod q — always so for
            // cryptographic q).
            return (-f * e.invert(q).expect("γ rational part invertible")).modulo(q);
        }
        // Edge (only reachable for tiny q): some bᵢ ≡ 0 mod q collapsed e to 0
        // mod q. Recompute the numerator over Z exactly, then strip the common
        // q-power before inverting (γ's rational part is a unit, so its q-adic
        // valuation equals that of the cancelled denominator).
        let (e, f) = reduce_track_generator_exact(&g, &self.delta_k);
        let v = val_q(&e, q);
        let qv = q.clone().pow(v as u32);
        let er = e.div_exact(&qv);
        let fr = f.div_exact(&qv);
        (-fr * er.invert(q).expect("γ rational part a unit")).modulo(q)
    }
}

/// Reduce a principal form `(a,b,c)` of negative discriminant to the identity,
/// returning (mod `q`) the *numerator* `e + f·√Δ_K = γ·∏(2cᵢ)` of the generator
/// `γ` of its ideal `[a, (b+√Δ_K)/2]`. Writing `𝔞_orig = γ·𝔞_current` (so `γ = 1`
/// initially and `γ` is the generator once `𝔞_current = O_K`), each ρ-step
/// `(a,b,c) → (c, …)` multiplies `γ` by `(b+√Δ_K)/(2c)`; normalization only
/// rewrites the basis and leaves `γ` fixed. We track `γ·∏(2cᵢ)` (multiply by the
/// numerator `(b+√Δ_K)` only, no division), since the `∏(2cᵢ)` factor cancels in
/// the caller's `f/e` ratio. `Δ_K ≡ 0 (mod q)` ⇒ the `√Δ_K`-square term vanishes.
fn reduce_track_generator(g: &QFI, q: &Integer) -> (Integer, Integer) {
    let (mut a, mut b, mut c) = (g.a().clone(), g.b().clone(), g.c().clone());
    let (mut e, mut f) = (Integer::from(1u64), Integer::new()); // numerator = 1 = (1, 0)
    normalize(&mut a, &mut b, &mut c); // ideal (hence γ) unchanged
    while a > c {
        // (e + f·√Δ_K)·(b + √Δ_K) = (e·b + f·Δ_K) + (e + f·b)·√Δ_K;  Δ_K ≡ 0.
        let nf = (&e + (&f * &b).complete()).modulo(q);
        e = (e * &b).modulo(q);
        f = nf;
        rho(&mut a, &mut b, &mut c);
    }
    (e, f)
}

/// Exact-integer variant of [`reduce_track_generator`] (no reduction mod `q`),
/// used only for the tiny-`q` edge where the mod-`q` numerator collapses to 0.
fn reduce_track_generator_exact(g: &QFI, delta_k: &Integer) -> (Integer, Integer) {
    let (mut a, mut b, mut c) = (g.a().clone(), g.b().clone(), g.c().clone());
    let (mut e, mut f) = (Integer::from(1u64), Integer::new());
    normalize(&mut a, &mut b, &mut c);
    while a > c {
        let ne = (&e * &b).complete() + (&f * delta_k).complete(); // e·b + f·Δ_K
        let nf = e + f * &b; // e + f·b
        e = ne;
        f = nf;
        rho(&mut a, &mut b, &mut c);
    }
    (e, f)
}

/// Normalize a form: `b ← b (mod 2a)` centered into `(−a, a]` (Long §5.2.1).
fn normalize(a: &mut Integer, b: &mut Integer, c: &mut Integer) {
    let two_a = (&*a << 1u32).complete();
    let r = (&*a - &*b).complete().div_rem_floor(two_a.clone()).0; // r = ⌊(a − b)/2a⌋
    *c += &r * (&*b + (&*a * &r).complete()); // c += r·(b + a·r)
    *b += two_a * r; // b += 2a·r
}

/// One ρ-reduction step: `(a,b,c) → (c, 2sc − b, a + s(sc − b))`,
/// `s = ⌊(c + b)/2c⌋`.
fn rho(a: &mut Integer, b: &mut Integer, c: &mut Integer) {
    let s = (&*c + &*b)
        .complete()
        .div_rem_floor((&*c << 1u32).complete())
        .0;
    let sc = (&s * &*c).complete();
    let new_c = &*a + (&s * (&sc - &*b).complete());
    let new_b = (sc << 1u32) - &*b;
    *a = c.clone();
    *b = new_b;
    *c = new_c;
}

// ---- ring arithmetic in Z[√Δ_K] / N  (elements (e, f) = e + f·√Δ_K) ----------

fn ring_mul(
    x: &(Integer, Integer),
    y: &(Integer, Integer),
    dk: &Integer,
    n: &Integer,
) -> (Integer, Integer) {
    let e = ((&x.0 * &y.0).complete() + (&x.1 * &y.1).complete() * dk).modulo(n);
    let f = ((&x.0 * &y.1).complete() + (&x.1 * &y.0).complete()).modulo(n);
    (e, f)
}

fn ring_inv(x: &(Integer, Integer), dk: &Integer, n: &Integer) -> (Integer, Integer) {
    // (e + f√Δ)^{-1} = (e - f√Δ) / (e² - f²Δ)
    let norm = ((&x.0 * &x.0).complete() - (&x.1 * &x.1).complete() * dk).modulo(n);
    let inv = norm.invert(n).expect("ring element not invertible mod q^k");
    let e = (&x.0 * &inv).complete().modulo(n);
    let f = (-(inv * &x.1)).modulo(n);
    (e, f)
}

fn ring_pow(
    x: &(Integer, Integer),
    exp: &Integer,
    dk: &Integer,
    n: &Integer,
) -> (Integer, Integer) {
    let mut result = (Integer::from(1u64), Integer::new()); // 1
    if exp.is_zero() {
        return result;
    }
    let mut base = (x.0.clone(), x.1.clone());
    for i in 0..exp.significant_bits() {
        if exp.get_bit(i) {
            result = ring_mul(&result, &base, dk, n);
        }
        base = ring_mul(&base, &base, dk, n);
    }
    result
}

// ---- module-private number theory ------------------------------------------

/// `q`-adic valuation of `x` (number of times `q` divides `x`).
fn val_q(x: &Integer, q: &Integer) -> usize {
    if x.is_zero() {
        return 0;
    }
    let mut v = 0;
    let mut t = x.clone();
    while t.is_divisible(q) {
        t = t.div_exact(q);
        v += 1;
    }
    v
}

/// Centered representative of `x ∈ [0, modulus)` into `(-half, half]`,
/// where `modulus = 2·half`.
fn center(x: Integer, modulus: &Integer, half: &Integer) -> Integer {
    if &x > half {
        (&x - modulus).complete()
    } else {
        x
    }
}

/// Lucas sequences `(U_n, V_n)` modulo `modn`, parameters `(P, Q)`, with
/// `D = P² - 4Q` supplied as `d_param`.
///
/// `modn` must be odd and greater than two, as `q^k` is for odd prime `q`.
fn lucas_uv(
    p_param: &Integer,
    q_param: &Integer,
    n: &Integer,
    modn: &Integer,
    d_param: &Integer,
) -> (Integer, Integer) {
    debug_assert!(modn.is_odd() && *modn > 2u32, "modulus must be odd and > 2");

    if n.is_zero() {
        return (Integer::new(), Integer::from(2u64));
    }

    // `x / 2 mod modn` for `x` in `[0, modn)`: `x + modn` is even when `x` is
    // odd, so this is a conditional add and a shift rather than a multiply by
    // `2^{-1} mod modn`.
    let half = |mut x: Integer| {
        if x.is_odd() {
            x += modn;
        }
        x >> 1u32
    };

    let pr = p_param.clone().modulo(modn);
    let qr = q_param.clone().modulo(modn);
    let dr = d_param.clone().modulo(modn);

    let mut u = Integer::from(1u64); // U_1
    let mut v = pr.clone(); // V_1
    let mut qpow = qr.clone(); // Q^1

    for i in (0..n.significant_bits() - 1).rev() {
        // Double: (U_m, V_m, Q^m) -> (U_2m, V_2m, Q^2m).
        let u2 = (u * &v).modulo(modn);
        let v2 = (v.square() - &qpow - &qpow).modulo(modn);
        qpow = qpow.square().modulo(modn);

        if n.get_bit(i) {
            // Increment to (U_2m+1, V_2m+1, Q^2m+1):
            //   U = (P·U_2m + V_2m) / 2
            //   V = (D·U_2m + P·V_2m) / 2
            u = half((v2.clone() + &pr * &u2).modulo(modn));
            v = half((v2 * &pr + &dr * &u2).modulo(modn));
            qpow = (qpow * &qr).modulo(modn);
        } else {
            u = u2;
            v = v2;
        }
    }
    (u, v)
}

/// Analytic upper bound on `h(Δ_K)`: `⌈(1/π)·ln|Δ_K|·√|Δ_K|⌉`.
/// Uses `ln|Δ_K| ≤ nbits·ln 2` and upper-bound rationals for `ln 2`, `1/π`,
/// so the result is a genuine upper bound. ([Cohen, p.295]; CL15 App. B.3.)
fn classnumber_upper_bound(delta_k: &Integer) -> Integer {
    let abs = delta_k.clone().abs();
    let nbits = abs.significant_bits() as u64;
    let s = abs.sqrt_ref().complete();
    let sqrt_ceil = if (&s * &s).complete() == abs {
        s
    } else {
        s + 1u32
    };
    // ln 2 < 0.6931472, 1/π < 0.3183099  (scaled by 10^7 each → denom 10^14)
    let numer = Integer::from(nbits)
        * Integer::from(6_931_472u64)
        * Integer::from(3_183_099u64)
        * &sqrt_ceil;
    let denom = Integer::from(100_000_000_000_000u64);
    let (q, r) = numer.div_rem_floor(denom);
    if r.is_zero() {
        q
    } else {
        q + 1u32
    }
}

/// Smallest prime `p` with `p·q ≡ 3 (mod 4)` and `(p|q) = -1`.
fn smallest_aux_prime(q: &Integer) -> Integer {
    let four = Integer::from(4u64);
    let mut p = Integer::from(3u64);
    loop {
        if p.is_probably_prime(MR_REPS) != rug::integer::IsPrime::No
            && (&p * q).complete().modulo(&four) == 3u64
            && p.kronecker(q) == -1
        {
            return p;
        }
        p = p.next_prime();
    }
}

/// A random `pbits`-bit prime `p` with `p·q ≡ 3 (mod 4)` and `(p|q) = -1`.
fn gen_aux_prime(q: &Integer, pbits: usize, rng: &mut RandGen) -> Integer {
    let four = Integer::from(4u64);
    loop {
        let p = rng.random_prime(pbits);
        if (&p * q).complete().modulo(&four) == 3u64 && p.kronecker(q) == -1 {
            return p;
        }
    }
}

/// Hard-subgroup generator `h = (r²)^M` where `r` is the smallest split prime
/// form and `M = q^k`.
fn build_h(cl: &ClassGroup, m: &Integer, q: &Integer, p: &Integer) -> QFI {
    let mut l = Integer::from(2u64);
    loop {
        if &l != q && &l != p && cl.discriminant().kronecker(&l) == 1 {
            let r = cl.prime_form(&l);
            let r2 = cl.square(&r);
            return cl.exp(&r2, m);
        }
        l = l.next_prime();
    }
}

// ---- key / text / ciphertext types ----------------------------------------

/// A secret key (an integer in `[0, secretkey_bound)`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretKey(Integer);

impl SecretKey {
    pub fn random(c: &CL_HSMqk, rng: &mut RandGen) -> Self {
        SecretKey(rng.random_mpz(&c.secretkey_bound))
    }
    pub fn from_mpz(c: &CL_HSMqk, v: Integer) -> Result<Self, ClassGroupError> {
        if v.cmp0().is_lt() || v >= c.secretkey_bound {
            return Err(ClassGroupError::OutOfBounds(
                "secret key out of range".into(),
            ));
        }
        Ok(SecretKey(v))
    }
    pub fn as_mpz(&self) -> &Integer {
        &self.0
    }
}
impl core::ops::Deref for SecretKey {
    type Target = Integer;
    fn deref(&self) -> &Integer {
        &self.0
    }
}

/// A cleartext (an integer in `[0, M)` with `M = q^k`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cleartext(Integer);

impl Cleartext {
    pub fn random(c: &CL_HSMqk, rng: &mut RandGen) -> Self {
        Cleartext(rng.random_mpz(&c.cleartext_bound))
    }
    pub fn from_mpz(c: &CL_HSMqk, v: Integer) -> Result<Self, ClassGroupError> {
        if v.cmp0().is_lt() || v >= c.cleartext_bound {
            return Err(ClassGroupError::OutOfBounds(
                "cleartext out of range".into(),
            ));
        }
        Ok(Cleartext(v))
    }
    pub fn as_mpz(&self) -> &Integer {
        &self.0
    }
}
impl core::ops::Deref for Cleartext {
    type Target = Integer;
    fn deref(&self) -> &Integer {
        &self.0
    }
}

/// A public key (an element `h^sk` of the class group).
///
/// A fixed-base comb table for fast `pk^r` is built lazily on first use and
/// cached, so key generation stays cheap while repeated encryptions amortise
/// the one-time table build.
#[derive(Clone, Debug)]
pub struct PublicKey {
    elt: QFI,
    comb: std::sync::OnceLock<FixedBaseComb>,
}

impl PublicKey {
    pub fn from_secret(c: &CL_HSMqk, sk: &SecretKey) -> Self {
        let elt = if c.compact_variant {
            c.cl_delta_k.exp(&c.gamma, sk.as_mpz())
        } else {
            c.power_of_h(sk.as_mpz())
        };
        PublicKey {
            elt,
            comb: std::sync::OnceLock::new(),
        }
    }
    pub fn from_qfi(c: &CL_HSMqk, f: QFI) -> Result<Self, ClassGroupError> {
        let _ = c;
        Ok(PublicKey {
            elt: f,
            comb: std::sync::OnceLock::new(),
        })
    }
    pub fn elt(&self) -> &QFI {
        &self.elt
    }

    pub fn comb(&self, c: &CL_HSMqk) -> &FixedBaseComb {
        self.comb.get_or_init(|| {
            // Cover both encryption randomness `r` (~secretkey_bound) and the
            // unbounded ZK responses `z = a + e·sk` (~secretkey_bound + q), so
            // `pk^z` in Schnorr verifies uses this fixed-base comb instead of a
            // bare exp. Same table size (2^blocks); only block length grows.
            let exp_bits =
                (c.secretkey_bound.significant_bits() + c.q.significant_bits() + 2) as usize;
            c.cl_delta.precompute_comb(&self.elt, exp_bits, COMB_BLOCKS)
        })
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.elt == other.elt
    }
}
impl Eq for PublicKey {}

/// A ciphertext `(c1, c2)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ciphertext {
    c1: QFI,
    c2: QFI,
}

impl Ciphertext {
    pub fn new(c1: QFI, c2: QFI) -> Self {
        Ciphertext { c1, c2 }
    }
    pub fn c1(&self) -> &QFI {
        &self.c1
    }
    pub fn c2(&self) -> &QFI {
        &self.c2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A small fixed CL instance (q=50 bits, k=1, |DeltaK|~150 bits) seeded for
    /// reproducibility, mirroring the smallest case in the C++ test suite.
    fn small_instance() -> (CL_HSMqk, RandGen) {
        let mut rng = RandGen::with_seed(&Integer::from(20240602u64));
        let c = CL_HSMqk::with_random_q(50, 1, 150, &mut rng, Params::default()).unwrap();
        (c, rng)
    }

    fn check_encryption_roundtrip(c: &CL_HSMqk, rng: &mut RandGen, iters: usize) {
        let sk = c.keygen_secret(rng);
        let pk = c.keygen_public(&sk);
        for _ in 0..iters {
            let m = Cleartext::random(c, rng);
            let ct = c.encrypt(&pk, &m, rng);
            let dec = c.decrypt(&sk, &ct);
            assert_eq!(dec.as_mpz(), m.as_mpz(), "decrypt(encrypt(m)) != m");
        }
    }

    fn check_homomorphic(c: &CL_HSMqk, rng: &mut RandGen, iters: usize) {
        let sk = c.keygen_secret(rng);
        let pk = c.keygen_public(&sk);
        for _ in 0..iters {
            let ma = Cleartext::random(c, rng);
            let mb = Cleartext::random(c, rng);
            let s = rng.random_mpz(c.cleartext_bound());

            let ca = c.encrypt(&pk, &ma, rng);
            let cb = c.encrypt(&pk, &mb, rng);

            // additive homomorphism
            let csum = c.add_ciphertexts(&pk, &ca, &cb, rng);
            let expect_sum = c.add_cleartexts(&ma, &mb);
            assert_eq!(c.decrypt(&sk, &csum).as_mpz(), expect_sum.as_mpz());

            // scalar homomorphism
            let cscal = c.scal_ciphertexts(&pk, &ca, &s, rng);
            let expect_scal = c.scal_cleartexts(&ma, &s);
            assert_eq!(c.decrypt(&sk, &cscal).as_mpz(), expect_scal.as_mpz());

            // ca + s*cb
            let caddscal = c.addscal_ciphertexts(&pk, &ca, &cb, &s, rng);
            let expect = c.add_cleartexts(&ma, &c.scal_cleartexts(&mb, &s));
            assert_eq!(c.decrypt(&sk, &caddscal).as_mpz(), expect.as_mpz());
        }
    }

    #[test]
    fn encryption_roundtrip_and_homomorphism() {
        let (c, mut rng) = small_instance();
        check_encryption_roundtrip(&c, &mut rng, 20);
        check_homomorphic(&c, &mut rng, 10);

        // compact variant
        let cc = c.with_compact_variant(true);
        check_encryption_roundtrip(&cc, &mut rng, 20);
        check_homomorphic(&cc, &mut rng, 10);
    }

    #[test]
    fn large_k_roundtrip() {
        // k > 1 exercises the Lucas-chain power_of_f and the dlog_in_F loop.
        let mut rng = RandGen::with_seed(&Integer::from(777u64));
        let c = CL_HSMqk::with_random_q(5, 15, 150, &mut rng, Params::default()).unwrap();
        check_encryption_roundtrip(&c, &mut rng, 20);
        check_homomorphic(&c, &mut rng, 8);
        let cc = c.with_compact_variant(true);
        check_encryption_roundtrip(&cc, &mut rng, 10);
    }

    #[test]
    fn large_message_variant_roundtrip() {
        // q large relative to DeltaK triggers the large-message variant.
        let mut rng = RandGen::with_seed(&Integer::from(13131u64));
        let c = CL_HSMqk::with_random_q(100, 1, 150, &mut rng, Params::default()).unwrap();
        assert!(c.large_message_variant());
        check_encryption_roundtrip(&c, &mut rng, 15);
        check_homomorphic(&c, &mut rng, 8);
    }

    #[test]
    fn explicit_message_value() {
        let (c, mut rng) = small_instance();
        let sk = c.keygen_secret(&mut rng);
        let pk = c.keygen_public(&sk);
        let m = Cleartext::from_mpz(&c, Integer::from(14u64)).unwrap();
        let ct = c.encrypt(&pk, &m, &mut rng);
        assert_eq!(c.decrypt(&sk, &ct).as_mpz(), &Integer::from(14u64));
    }

    #[test]
    #[ignore = "perf micro-benchmark: pk-comb routing; run with --ignored --nocapture"]
    fn pk_pow_comb_vs_bare_timing() {
        use std::time::Instant;
        let mut setup = ClSetup::new_secp256k1_128bit(42u64).expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");
        // Response-sized exponent z = a + e·sk: ~secretkey_bound + ~28 bytes of
        // challenge, staying within the (enlarged) comb range.
        let z = {
            let (s2, _) = setup.keygen().expect("k2");
            let body = setup.sk_to_integer(&s2);
            let ext = Integer::from(0xABu64) << (28 * 8 + body.significant_bits());
            ext + body
        };
        let elt = pk.elt().clone();
        const N: u32 = 20; // simulate reuse across an n-peer verify loop
        let t0 = Instant::now();
        for _ in 0..N {
            let _ = setup.pk_pow(&pk, &z).expect("comb");
        }
        let t_comb = t0.elapsed() / N;
        let t1 = Instant::now();
        for _ in 0..N {
            let _ = setup.exp(&elt, &z).expect("bare");
        }
        let t_bare = t1.elapsed() / N;
        println!(
            "pk^z ({}-bit) amortised over {N} reuses: comb={t_comb:?} bare={t_bare:?} speedup={:.2}x",
            z.significant_bits(),
            t_bare.as_secs_f64() / t_comb.as_secs_f64()
        );
    }
}
