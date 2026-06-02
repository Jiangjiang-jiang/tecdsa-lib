// SPDX-License-Identifier: GPL-3.0-or-later
//! Safe glue layer over [`bicycl_rs`] for class-group operations.
//!
//! The main entry point is [`ClSetup`], which initialises a CL-HSMqk scheme
//! and provides access to the BICYCL context, random-number generator, and
//! scheme parameters.

use bicycl_rs::{
    ClHsmqk, ClHsmqkCiphertext, ClHsmqkPublicKey, ClHsmqkSecretKey, ClassGroup, Context, Qfi,
    RandGen,
};
use num_bigint::BigUint;
use num_traits::Num;

/// Error type for class-group operations.
#[derive(Debug, thiserror::Error)]
pub enum ClError {
    /// An error originating from the BICYCL C library.
    #[error("bicycl: {0}")]
    Bicycl(#[from] bicycl_rs::Error),

    /// Invalid parameter supplied to a class-group operation.
    #[error("invalid parameter: {0}")]
    InvalidParam(String),
}

/// Result alias for class-group operations.
pub type ClResult<T> = Result<T, ClError>;

/// Initialised CL-HSMqk class-group scheme.
///
/// This struct owns the BICYCL [`Context`], [`RandGen`], and [`ClHsmqk`]
/// scheme instance.  All encryption/decryption operations flow through it.
///
/// # Thread safety
///
/// Since bicycl-rs v0.2.2, `ClSetup` is `Send` (can be moved between
/// threads) but `!Sync` (cannot be shared via `&T` across threads).
/// All operations on a single `ClSetup` must be serialized.
pub struct ClSetup {
    ctx: Context,
    rng: RandGen,
    cl: ClHsmqk,
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
    /// known-good class-group prime from BICYCL test vectors.
    ///
    /// This uses `q = secp256k1 order`, `k = 1`, and a prime `p`
    /// satisfying the required congruence and Kronecker-symbol
    /// constraints for a fundamental discriminant `Delta_K = -p*q`.
    ///
    /// `seed_decimal` seeds the internal PRNG for deterministic testing.
    /// In production, pass a cryptographically random seed.
    ///
    /// # Errors
    ///
    /// Returns an error if the BICYCL library fails to initialise.
    pub fn new_secp256k1(seed_decimal: &str) -> ClResult<Self> {
        // For secp256k1, q ≡ 1 (mod 4), so we need p ≡ 3 (mod 4) and p prime,
        // with Legendre(q, p) = -1, to make Delta_K = -p*q fundamental.
        //
        // p = 7 satisfies: 7 ≡ 3 (mod 4), 7*q ≡ 3 (mod 4) => -7*q ≡ 1 (mod 4),
        // and q mod 7 = 3 which is a QNR mod 7, so Legendre(q, 7) = -1.
        //
        // NOTE: This gives a tiny discriminant (insecure!) suitable only for
        // fast testing. Use `new_secp256k1_128bit` for 128-bit security.
        let p_decimal = "7";
        Self::new_custom(SECP256K1_ORDER, 1, p_decimal, seed_decimal)
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
    pub fn new_secp256k1_128bit(seed_decimal: &str) -> ClResult<Self> {
        Self::new_custom(SECP256K1_ORDER, 1, SECP256K1_CL_PRIME_128BIT, seed_decimal)
    }

    /// Creates a CL-HSMqk setup with custom parameters.
    ///
    /// - `q_decimal`: the prime order of the plaintext group.
    /// - `k`: the power parameter (plaintext space is `Z/q^k`).
    /// - `p_decimal`: the class-group prime.
    /// - `seed_decimal`: PRNG seed (decimal string).
    ///
    /// # Errors
    ///
    /// Returns an error if the BICYCL library fails to initialise.
    pub fn new_custom(
        q_decimal: &str,
        k: u32,
        p_decimal: &str,
        seed_decimal: &str,
    ) -> ClResult<Self> {
        let ctx = Context::new()?;
        let rng = ctx.randgen_from_seed_decimal(seed_decimal)?;
        let cl = ctx.cl_hsmqk(q_decimal, k, p_decimal)?;
        Ok(Self { ctx, rng, cl })
    }

    // ── Accessors ──────────────────────────────────────────────────────

    /// Returns a reference to the BICYCL context.
    #[must_use]
    pub fn ctx(&self) -> &Context {
        &self.ctx
    }

    /// Returns a mutable reference to the BICYCL PRNG.
    pub fn rng(&mut self) -> &mut RandGen {
        &mut self.rng
    }

    /// Returns a reference to the CL-HSMqk scheme instance.
    #[must_use]
    pub fn cl(&self) -> &ClHsmqk {
        &self.cl
    }

    // ── Key generation ─────────────────────────────────────────────────

    /// Generates a fresh CL-HSMqk key pair.
    ///
    /// # Errors
    ///
    /// Returns an error if the BICYCL library fails.
    pub fn keygen(&mut self) -> ClResult<(ClHsmqkSecretKey, ClHsmqkPublicKey)> {
        Ok(self.cl.keygen(&self.ctx, &mut self.rng)?)
    }

    // ── Encryption / Decryption ────────────────────────────────────────

    /// Encrypts a plaintext given as a decimal string.
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails.
    pub fn encrypt(
        &mut self,
        pk: &ClHsmqkPublicKey,
        message_decimal: &str,
    ) -> ClResult<ClHsmqkCiphertext> {
        Ok(self
            .cl
            .encrypt_decimal(&self.ctx, pk, &mut self.rng, message_decimal)?)
    }

    /// Encrypts with explicit randomness (deterministic encryption).
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails.
    pub fn encrypt_with_r(
        &self,
        pk: &ClHsmqkPublicKey,
        message_decimal: &str,
        r_decimal: &str,
    ) -> ClResult<ClHsmqkCiphertext> {
        Ok(self
            .cl
            .encrypt_decimal_with_r(&self.ctx, pk, message_decimal, r_decimal)?)
    }

    /// Decrypts a ciphertext, returning the plaintext as a decimal string.
    ///
    /// # Errors
    ///
    /// Returns an error if decryption fails.
    pub fn decrypt(&self, sk: &ClHsmqkSecretKey, ct: &ClHsmqkCiphertext) -> ClResult<String> {
        Ok(self.cl.decrypt_decimal(&self.ctx, sk, ct)?)
    }

    // ── Homomorphic operations ─────────────────────────────────────────

    /// Homomorphic addition: `Enc(a) + Enc(b) = Enc(a + b mod q^k)`.
    ///
    /// # Errors
    ///
    /// Returns an error if the BICYCL library fails.
    pub fn add_ciphertexts(
        &mut self,
        pk: &ClHsmqkPublicKey,
        ca: &ClHsmqkCiphertext,
        cb: &ClHsmqkCiphertext,
    ) -> ClResult<ClHsmqkCiphertext> {
        Ok(self
            .cl
            .add_ciphertexts(&self.ctx, pk, &mut self.rng, ca, cb)?)
    }

    /// Homomorphic scalar multiplication: `s * Enc(m) = Enc(s * m mod q^k)`.
    ///
    /// # Errors
    ///
    /// Returns an error if the BICYCL library fails.
    pub fn scal_ciphertext(
        &mut self,
        pk: &ClHsmqkPublicKey,
        ct: &ClHsmqkCiphertext,
        scalar_decimal: &str,
    ) -> ClResult<ClHsmqkCiphertext> {
        Ok(self
            .cl
            .scal_ciphertext_decimal(&self.ctx, pk, &mut self.rng, ct, scalar_decimal)?)
    }

    // ── Subgroup operations ────────────────────────────────────────────

    /// Computes `h^e` (power of the hidden-order generator).
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn power_of_h(&self, e_decimal: &str) -> ClResult<Qfi> {
        Ok(self.cl.power_of_h_decimal(&self.ctx, e_decimal)?)
    }

    /// Computes `f^m` in the cyclic subgroup `F` (the message subgroup).
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn power_of_f(&self, m_decimal: &str) -> ClResult<Qfi> {
        Ok(self.cl.power_of_f_decimal(&self.ctx, m_decimal)?)
    }

    /// Solves the discrete logarithm in subgroup `F`: given `f^m`,
    /// returns `m` as a decimal string.
    ///
    /// # Errors
    ///
    /// Returns an error if the `DLog` computation fails.
    #[allow(non_snake_case)]
    pub fn dlog_in_F(&self, fm: &Qfi) -> ClResult<String> {
        Ok(self.cl.dlog_in_F(&self.ctx, fm)?)
    }

    // ── Bytes-based API ───────────────────────────────────────────────

    /// Encrypts a plaintext given as big-endian bytes.
    ///
    /// The bytes are interpreted as an unsigned big-endian integer and
    /// converted to a decimal string for the underlying BICYCL call.
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails.
    pub fn encrypt_bytes(
        &mut self,
        pk: &ClHsmqkPublicKey,
        plaintext_bytes: &[u8],
    ) -> ClResult<ClHsmqkCiphertext> {
        Ok(self
            .cl
            .encrypt_bytes(&self.ctx, pk, &mut self.rng, plaintext_bytes)?)
    }

    /// Decrypts a ciphertext, returning the plaintext as big-endian bytes.
    pub fn decrypt_bytes(
        &self,
        sk: &ClHsmqkSecretKey,
        ct: &ClHsmqkCiphertext,
    ) -> ClResult<Vec<u8>> {
        Ok(self.cl.decrypt_bytes(&self.ctx, sk, ct)?)
    }

    /// Homomorphic scalar multiplication with a bytes scalar.
    pub fn scal_ciphertext_bytes(
        &mut self,
        pk: &ClHsmqkPublicKey,
        ct: &ClHsmqkCiphertext,
        scalar_bytes: &[u8],
    ) -> ClResult<ClHsmqkCiphertext> {
        Ok(self
            .cl
            .scal_ciphertext_bytes(&self.ctx, pk, &mut self.rng, ct, scalar_bytes)?)
    }

    /// Computes `f^m` in the cyclic subgroup `F`, with `m` as big-endian bytes.
    pub fn power_of_f_bytes(&self, m_bytes: &[u8]) -> ClResult<Qfi> {
        Ok(self.cl.power_of_f_bytes(&self.ctx, m_bytes)?)
    }

    /// Computes `h^e` with `e` as big-endian bytes.
    pub fn power_of_h_bytes(&self, e_bytes: &[u8]) -> ClResult<Qfi> {
        Ok(self.cl.power_of_h_bytes(&self.ctx, e_bytes)?)
    }

    /// Discrete log in subgroup F, result as big-endian bytes.
    #[allow(non_snake_case)]
    pub fn dlog_in_F_bytes(&self, fm: &Qfi) -> ClResult<Vec<u8>> {
        Ok(self.cl.dlog_in_F_bytes(&self.ctx, fm)?)
    }

    /// QFI exponentiation in `Cl(Delta)`: `f^n` with `n` as big-endian bytes.
    pub fn exp_bytes(&self, f: &Qfi, n: &[u8]) -> ClResult<Qfi> {
        let cl_delta = self.cl.Cl_Delta(&self.ctx)?;
        Ok(cl_delta.nupow_bytes(&self.ctx, f, n)?)
    }

    /// Deterministic encryption with explicit randomness, bytes-based.
    ///
    /// Both `msg` and `r` are big-endian unsigned bytes.
    pub fn encrypt_with_r_bytes(
        &self,
        pk: &ClHsmqkPublicKey,
        msg: &[u8],
        r: &[u8],
    ) -> ClResult<ClHsmqkCiphertext> {
        Ok(self.cl.encrypt_bytes_with_r(&self.ctx, pk, msg, r)?)
    }

    /// Export secret key as big-endian bytes.
    pub fn sk_to_bytes(&self, sk: &ClHsmqkSecretKey) -> ClResult<Vec<u8>> {
        Ok(sk.to_bytes(&self.ctx)?)
    }

    /// Import secret key from big-endian bytes.
    pub fn sk_from_bytes(&self, bytes: &[u8]) -> ClResult<ClHsmqkSecretKey> {
        Ok(ClHsmqkSecretKey::from_bytes(&self.ctx, &self.cl, bytes)?)
    }

    /// Curve order `q` as big-endian bytes.
    pub fn q_bytes(&self) -> ClResult<Vec<u8>> {
        Ok(self.cl.q_bytes(&self.ctx)?)
    }

    /// Discriminant `DeltaK` as big-endian bytes.
    #[allow(non_snake_case)]
    pub fn DeltaK_bytes(&self) -> ClResult<Vec<u8>> {
        Ok(self.cl.DeltaK_bytes(&self.ctx)?)
    }

    /// Secret key bound as big-endian bytes.
    pub fn secretkey_bound_bytes(&self) -> ClResult<Vec<u8>> {
        Ok(self.cl.secretkey_bound_bytes(&self.ctx)?)
    }

    /// Conductor `M = q^k` as big-endian bytes.
    #[allow(non_snake_case)]
    pub fn M_bytes(&self) -> ClResult<Vec<u8>> {
        Ok(self.cl.M_bytes(&self.ctx)?)
    }

    /// QFI lift with conductor as bytes.
    ///
    /// Maps an element in-place from the order of conductor `M` to the
    /// maximal order.  `conductor` is `M` as big-endian unsigned bytes.
    pub fn lift_bytes(&self, qfi: &mut Qfi, conductor: &[u8]) -> ClResult<()> {
        Ok(qfi.lift_bytes(&self.ctx, conductor)?)
    }

    /// QFI to maximal order with bytes parameters.
    ///
    /// Maps an element in-place from `Cl(Delta)` to `Cl(DeltaK)`.
    /// `conductor` is `M`, `delta_k` is `DeltaK`, both as big-endian
    /// unsigned bytes.  `to_neg` controls sign conventions.
    pub fn to_maximal_order_bytes(
        &self,
        qfi: &mut Qfi,
        conductor: &[u8],
        delta_k: &[u8],
        to_neg: bool,
    ) -> ClResult<()> {
        Ok(qfi.to_maximal_order_bytes(&self.ctx, conductor, delta_k, to_neg)?)
    }

    /// Add-and-scalar-multiply: `Enc(a + b*s mod q^k)`, with scalar as
    /// big-endian bytes.
    pub fn addscal_ciphertexts_bytes(
        &mut self,
        pk: &ClHsmqkPublicKey,
        ca: &ClHsmqkCiphertext,
        cb: &ClHsmqkCiphertext,
        scalar: &[u8],
    ) -> ClResult<ClHsmqkCiphertext> {
        Ok(self
            .cl
            .addscal_ciphertexts_bytes(&self.ctx, pk, &mut self.rng, ca, cb, scalar)?)
    }

    /// Negate a QFI element: returns `-f` in the class group.
    pub fn neg_qfi(&self, f: &Qfi) -> ClResult<Qfi> {
        Ok(f.neg(&self.ctx)?)
    }

    /// Returns the generator `h` of the hidden-order subgroup.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn h(&self) -> ClResult<Qfi> {
        Ok(self.cl.h(&self.ctx)?)
    }

    /// Returns the class group `Cl(Delta)` over the order of conductor `M`.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    #[allow(non_snake_case)]
    pub fn Cl_Delta(&self) -> ClResult<ClassGroup> {
        Ok(self.cl.Cl_Delta(&self.ctx)?)
    }

    /// Returns the class group `Cl(DeltaK)` over the maximal order.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    #[allow(non_snake_case)]
    pub fn Cl_DeltaK(&self) -> ClResult<ClassGroup> {
        Ok(self.cl.Cl_DeltaK(&self.ctx)?)
    }

    /// Returns the prime `q` (subgroup order) as a decimal string.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn q_decimal(&self) -> ClResult<String> {
        Ok(self.cl.q_decimal(&self.ctx)?)
    }

    /// Returns the conductor `M = q^k` as a decimal string.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    #[allow(non_snake_case)]
    pub fn M_decimal(&self) -> ClResult<String> {
        Ok(self.cl.M_decimal(&self.ctx)?)
    }

    /// Returns the maximal-order discriminant `DeltaK` as a decimal string.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    #[allow(non_snake_case)]
    pub fn DeltaK_decimal(&self) -> ClResult<String> {
        Ok(self.cl.DeltaK_decimal(&self.ctx)?)
    }

    /// Returns the upper bound on secret-key values as a decimal string.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn secretkey_bound_decimal(&self) -> ClResult<String> {
        Ok(self.cl.secretkey_bound_decimal(&self.ctx)?)
    }

    // ── Class-group QFI utilities ──────────────────────────────────────

    /// Composes two QFI elements in `Cl(Delta)`: `f1 * f2`.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn compose(&self, f1: &Qfi, f2: &Qfi) -> ClResult<Qfi> {
        let cl_delta = self.cl.Cl_Delta(&self.ctx)?;
        Ok(cl_delta.nucomp(&self.ctx, f1, f2)?)
    }

    /// Exponentiates a QFI element: `f^n`.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn exp(&self, f: &Qfi, n_decimal: &str) -> ClResult<Qfi> {
        let cl_delta = self.cl.Cl_Delta(&self.ctx)?;
        Ok(cl_delta.nupow_decimal(&self.ctx, f, n_decimal)?)
    }

    /// Returns the identity element of `Cl(Delta)`.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn identity(&self) -> ClResult<Qfi> {
        let cl_delta = self.cl.Cl_Delta(&self.ctx)?;
        Ok(cl_delta.one(&self.ctx)?)
    }

    /// Returns the ciphertext components `(c1, c2)`.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn ct_components(&self, ct: &ClHsmqkCiphertext) -> ClResult<(Qfi, Qfi)> {
        let c1 = ct.c1(&self.ctx)?;
        let c2 = ct.c2(&self.ctx)?;
        Ok((c1, c2))
    }

    /// Builds a ciphertext from QFI components `(c1, c2)`.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn ct_from_components(&self, c1: &Qfi, c2: &Qfi) -> ClResult<ClHsmqkCiphertext> {
        Ok(ClHsmqkCiphertext::from_c1c2(&self.ctx, c1, c2)?)
    }

    /// Returns the public key's underlying QFI element.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn pk_element(&self, pk: &ClHsmqkPublicKey) -> ClResult<Qfi> {
        Ok(pk.elt(&self.ctx)?)
    }

    /// Constructs a public key from a QFI element.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn pk_from_qfi(&self, qfi: &Qfi) -> ClResult<ClHsmqkPublicKey> {
        Ok(ClHsmqkPublicKey::from_qfi(&self.ctx, &self.cl, qfi)?)
    }

    /// Serialises a secret key to a decimal string.
    ///
    /// # Errors
    ///
    /// Returns an error if serialisation fails.
    pub fn sk_to_decimal(&self, sk: &ClHsmqkSecretKey) -> ClResult<String> {
        Ok(sk.to_decimal(&self.ctx)?)
    }

    /// Deserialises a secret key from a decimal string.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialisation fails.
    pub fn sk_from_decimal(&self, sk_decimal: &str) -> ClResult<ClHsmqkSecretKey> {
        Ok(ClHsmqkSecretKey::from_decimal(
            &self.ctx, &self.cl, sk_decimal,
        )?)
    }

    /// Converts a `BigUint` to a decimal string suitable for BICYCL.
    #[must_use]
    pub fn biguint_to_decimal(v: &BigUint) -> String {
        v.to_str_radix(10)
    }

    /// Parses a decimal string to `BigUint`.
    ///
    /// # Errors
    ///
    /// Returns an error if the string is not a valid decimal integer.
    pub fn decimal_to_biguint(s: &str) -> ClResult<BigUint> {
        BigUint::from_str_radix(s, 10)
            .map_err(|e| ClError::InvalidParam(format!("invalid decimal: {e}")))
    }
}

// Re-export useful bicycl-rs types so downstream doesn't need to depend on
// bicycl-rs directly.
pub use bicycl_rs::{
    ClHsmqk as BicyclClHsmqk, ClHsmqkCiphertext as BicyclCiphertext,
    ClHsmqkPublicKey as BicyclPublicKey, ClHsmqkSecretKey as BicyclSecretKey,
    ClassGroup as BicyclClassGroup, Context as BicyclContext, Qfi as BicyclQfi,
    RandGen as BicyclRandGen,
};

// Re-export the error type.
pub use ClError as Error;
