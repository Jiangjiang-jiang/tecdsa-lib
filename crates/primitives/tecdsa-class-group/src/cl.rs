#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

use std::{borrow::Borrow, str::FromStr, sync::Arc};

pub use self::{Ciphertext as ClCiphertext, PublicKey as ClPublicKey, SecretKey as ClSecretKey};
pub use crate::class_group::{
    error::ClassGroupError,
    mpz::Mpz,
    qfi::{ClassGroup, FixedBaseComb, QFI, QFI as Qfi},
    rand::RandGen,
};

#[derive(Debug, thiserror::Error)]
pub enum ClError {
    #[error("class group: {0}")]
    ClassGroup(#[from] ClassGroupError),

    #[error("invalid parameter: {0}")]
    InvalidParam(String),
}

pub type ClResult<T> = Result<T, ClError>;

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

pub const SECP256K1_ORDER: &str =
    "115792089237316195423570985008687907852837564279074904382605163141518161494337";

pub const SECP256K1_CL_PRIME_128BIT: &str =
    "165427457039117011823074561613444035351792492968921911807749264167080539287954032009049341053817071909297408790078970165320482418378310001089994560969562298297850775105757501192300518402392755866330857379154546192687115362055161787245008991873302392117599634534192225466830770950397155986355417462441267574549737435039212228475528923355314428234034516940321913098953375361830573701543197780605487019385455259679887245284016137256968388198675036060069434723034369192376576943";

impl ClSetup {
    pub fn new_secp256k1(seed_decimal: &str) -> ClResult<Self> {
        Self::new_custom(SECP256K1_ORDER, 1, "7", seed_decimal)
    }

    pub fn new_secp256k1_128bit(seed_decimal: &str) -> ClResult<Self> {
        Self::new_custom(SECP256K1_ORDER, 1, SECP256K1_CL_PRIME_128BIT, seed_decimal)
    }

    pub fn new_custom(
        q_decimal: &str,
        k: u32,
        p_decimal: &str,
        seed_decimal: &str,
    ) -> ClResult<Self> {
        let mut randgen = RandGen::new();
        randgen.set_seed(&Mpz::from_str(seed_decimal)?);

        let cl = CL_HSMqk::new(
            &Mpz::from_str(q_decimal)?,
            k as usize,
            &Mpz::from_str(p_decimal)?,
            Params::default(),
        )?;

        Ok(Self {
            rng: randgen,
            cl: Arc::new(cl),
        })
    }

    pub fn rng(&mut self) -> &mut RandGen {
        &mut self.rng
    }

    #[must_use]
    pub fn cl(&self) -> &CL_HSMqk {
        &self.cl
    }

    pub fn keygen(&mut self) -> ClResult<(SecretKey, PublicKey)> {
        let sk = self.cl.keygen_secret(&mut self.rng);
        let pk = self.cl.keygen_public(&sk);
        Ok((sk, pk))
    }

    pub fn encrypt(&mut self, pk: &PublicKey, message_decimal: &str) -> ClResult<Ciphertext> {
        Ok(self.cl.encrypt(
            pk,
            &Cleartext::from_mpz(&self.cl, Mpz::from_str(message_decimal)?)?,
            &mut self.rng,
        ))
    }

    pub fn encrypt_with_r(
        &self,
        pk: &PublicKey,
        message_decimal: &str,
        r_decimal: &str,
    ) -> ClResult<Ciphertext> {
        Ok(self.cl.encrypt_with_randomness(
            pk,
            &Cleartext::from_mpz(&self.cl, Mpz::from_str(message_decimal)?)?,
            &Mpz::from_str(r_decimal)?,
        ))
    }

    pub fn decrypt(&self, sk: &SecretKey, ct: &Ciphertext) -> ClResult<String> {
        Ok(self.cl.decrypt(sk, ct).to_string())
    }

    pub fn add_ciphertexts(
        &mut self,
        pk: &PublicKey,
        ca: &Ciphertext,
        cb: &Ciphertext,
    ) -> ClResult<Ciphertext> {
        Ok(self.cl.add_ciphertexts(pk, ca, cb, &mut self.rng))
    }

    pub fn scal_ciphertext(
        &mut self,
        pk: &PublicKey,
        ct: &Ciphertext,
        scalar_decimal: &str,
    ) -> ClResult<Ciphertext> {
        Ok(self
            .cl
            .scal_ciphertexts(pk, ct, &Mpz::from_str(scalar_decimal)?, &mut self.rng))
    }

    pub fn power_of_h(&self, e_decimal: &str) -> ClResult<Qfi> {
        Ok(self.cl.power_of_h(&Mpz::from_str(e_decimal)?))
    }

    pub fn power_of_f(&self, m_decimal: &str) -> ClResult<Qfi> {
        Ok(self.cl.power_of_f(&Mpz::from_str(m_decimal)?))
    }

    pub fn encrypt_bytes(
        &mut self,
        pk: &PublicKey,
        plaintext_bytes: &[u8],
    ) -> ClResult<Ciphertext> {
        Ok(self.cl.encrypt(
            pk,
            &Cleartext::from_mpz(&self.cl, Mpz::from_bytes_be(plaintext_bytes))?,
            &mut self.rng,
        ))
    }

    pub fn decrypt_bytes(&self, sk: &SecretKey, ct: &Ciphertext) -> ClResult<Vec<u8>> {
        Ok(self.cl.decrypt(sk, ct).to_bytes_be())
    }

    pub fn scal_ciphertext_bytes(
        &mut self,
        pk: &PublicKey,
        ct: &Ciphertext,
        scalar_bytes: &[u8],
    ) -> ClResult<Ciphertext> {
        Ok(self
            .cl
            .scal_ciphertexts(pk, ct, &Mpz::from_bytes_be(scalar_bytes), &mut self.rng))
    }

    pub fn power_of_f_bytes(&self, m_bytes: &[u8]) -> ClResult<Qfi> {
        Ok(self.cl.power_of_f(&Mpz::from_bytes_be(m_bytes)))
    }

    pub fn power_of_h_bytes(&self, e_bytes: &[u8]) -> ClResult<Qfi> {
        Ok(self.cl.power_of_h(&Mpz::from_bytes_be(e_bytes)))
    }

    #[allow(non_snake_case)]
    pub fn dlog_in_F_bytes(&self, fm: &Qfi) -> ClResult<Vec<u8>> {
        Ok(self.cl.dlog_in_F(fm).to_bytes_be())
    }

    pub fn exp_bytes(&self, f: &Qfi, n: &[u8]) -> ClResult<Qfi> {
        let cl_delta = self.cl.cl_delta();
        Ok(cl_delta.exp(f, &Mpz::from_bytes_be(n)))
    }

    pub fn encrypt_with_r_bytes(
        &self,
        pk: &PublicKey,
        msg: &[u8],
        r: &[u8],
    ) -> ClResult<Ciphertext> {
        Ok(self.cl.encrypt_with_randomness(
            pk,
            &Cleartext::from_mpz(&self.cl, Mpz::from_bytes_be(msg))?,
            &Mpz::from_bytes_be(r),
        ))
    }

    pub fn sk_to_bytes(&self, sk: &SecretKey) -> ClResult<Vec<u8>> {
        Ok(sk.to_bytes_be())
    }

    pub fn sk_from_bytes(&self, bytes: &[u8]) -> ClResult<SecretKey> {
        Ok(SecretKey::from_mpz(&self.cl, Mpz::from_bytes_be(bytes))?)
    }

    pub fn q_bytes(&self) -> ClResult<Vec<u8>> {
        Ok(self.cl.q().to_bytes_be())
    }

    pub fn secretkey_bound_bytes(&self) -> ClResult<Vec<u8>> {
        Ok(self.cl.secretkey_bound().to_bytes_be())
    }

    pub fn compose(&self, f1: &Qfi, f2: &Qfi) -> ClResult<Qfi> {
        let cl_delta = self.cl.cl_delta();
        Ok(cl_delta.compose(f1, f2))
    }

    pub fn exp(&self, f: &Qfi, n_decimal: &str) -> ClResult<Qfi> {
        let cl_delta = self.cl.cl_delta();
        Ok(cl_delta.exp(f, &Mpz::from_str(n_decimal)?))
    }

    pub fn multiexp_bytes(
        &self,
        bases: &[impl Borrow<Qfi>],
        exps: &[impl Borrow<[u8]>],
    ) -> ClResult<Qfi> {
        let exps_mpz: Vec<Mpz> = exps
            .iter()
            .map(|e| Mpz::from_bytes_be(e.borrow()))
            .collect();
        Ok(self.cl.cl_delta().multiexp(bases, &exps_mpz))
    }

    pub fn pk_pow_bytes(&self, pk: &PublicKey, e: &[u8]) -> ClResult<Qfi> {
        let n = Mpz::from_bytes_be(e);
        if !self.cl.compact_variant {
            let comb = pk.comb(&self.cl);
            if n.nbits() <= comb.max_bits() {
                return Ok(self.cl.cl_delta.exp_comb(comb, &n));
            }
        }
        Ok(self.cl.cl_delta.exp(pk.elt(), &n))
    }

    pub fn multiexp_signed_bytes(
        &self,
        bases: &[impl Borrow<Qfi>],
        exps: &[(bool, impl Borrow<[u8]>)],
    ) -> ClResult<Qfi> {
        let exps_mpz: Vec<Mpz> = exps
            .iter()
            .map(|(neg, e)| {
                let m = Mpz::from_bytes_be(e.borrow());
                if *neg {
                    m.neg()
                } else {
                    m
                }
            })
            .collect();
        Ok(self.cl.cl_delta().multiexp(bases, &exps_mpz))
    }

    pub fn identity(&self) -> ClResult<Qfi> {
        let cl_delta = self.cl.cl_delta();
        Ok(cl_delta.identity())
    }

    pub fn ct_components(&self, ct: &Ciphertext) -> ClResult<(Qfi, Qfi)> {
        let c1 = ct.c1().clone();
        let c2 = ct.c2().clone();
        Ok((c1, c2))
    }

    pub fn ct_from_components(&self, c1: &Qfi, c2: &Qfi) -> ClResult<Ciphertext> {
        Ok(Ciphertext::new(c1.clone(), c2.clone()))
    }

    pub fn pk_from_qfi(&self, qfi: &Qfi) -> ClResult<PublicKey> {
        Ok(PublicKey::from_qfi(&self.cl, qfi.clone())?)
    }
}

const COMB_BLOCKS: usize = 8;

pub type Genus = (i32, i32);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    pub distance: usize,
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

#[derive(Clone, Debug)]
pub struct CL_HSMqk {
    pub(crate) q: Mpz,
    pub(crate) k: usize,
    pub(crate) p: Mpz,
    pub(crate) m: Mpz,
    pub(crate) delta_k: Mpz,
    pub(crate) delta: Mpz,
    pub(crate) cl_delta_k: ClassGroup,
    pub(crate) cl_delta: ClassGroup,
    pub(crate) cl_g: ClassGroup,
    pub(crate) h: QFI,
    pub(crate) h_comb: FixedBaseComb,
    pub(crate) gamma: QFI,
    pub(crate) compact_variant: bool,
    pub(crate) large_message_variant: bool,
    pub(crate) secretkey_bound: Mpz,
    pub(crate) cleartext_bound: Mpz,
    pub(crate) encrypt_randomness_bound: Mpz,
    pub(crate) lambda_distance: usize,
}

const MR_REPS: u32 = 30;

impl CL_HSMqk {

    pub fn new(q: &Mpz, k: usize, p: &Mpz, params: Params) -> Result<CL_HSMqk, ClassGroupError> {
        if k == 0 {
            return Err(ClassGroupError::InvalidParameter("k must be >= 1".into()));
        }
        if q.is_even() || !q.is_probab_prime(MR_REPS) {
            return Err(ClassGroupError::InvalidParameter(
                "q must be an odd prime".into(),
            ));
        }
        let p_is_one = *p == 1u64;
        if !p_is_one && (p.is_even() || !p.is_probab_prime(MR_REPS)) {
            return Err(ClassGroupError::InvalidParameter(
                "p must be 1 or an odd prime".into(),
            ));
        }
        let pq = p * q;
        if pq.modulo(&Mpz::from(4u64)) != 3u64 {
            return Err(ClassGroupError::InvalidParameter(
                "must have p·q ≡ 3 (mod 4)".into(),
            ));
        }
        if !p_is_one && p.kronecker(q) != -1 {
            return Err(ClassGroupError::InvalidParameter(
                "must have Kronecker (p|q) = -1".into(),
            ));
        }

        let delta_k = pq.neg();
        let m = q.pow_u(k as u32);
        let q2k = q.pow_u(2 * k as u32);
        let delta = &q2k * &delta_k;

        let cl_delta_k = ClassGroup::new(delta_k.clone());
        let cl_delta = ClassGroup::new(delta.clone());
        let cl_g = cl_delta.clone();

        let h = build_h(&cl_delta, &m, q, p);

        let c_f = (&Mpz::from(1u64) - &delta_k).fdiv_2exp(2);
        let large_message_variant = q2k > c_f;

        let cleartext_bound = m.clone();
        let cn_bound = classnumber_upper_bound(&delta_k);
        let dist = params.distance.max(2);
        let secretkey_bound = cn_bound.mul_2exp((dist - 2) as u32);
        let encrypt_randomness_bound = secretkey_bound.clone();

        let exp_bits = secretkey_bound.nbits() + q.nbits() + 2;
        let h_comb = cl_delta.precompute_comb(&h, exp_bits, COMB_BLOCKS);

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
        q: &Mpz,
        k: usize,
        delta_k_nbits: usize,
        rng: &mut RandGen,
        params: Params,
    ) -> Result<CL_HSMqk, ClassGroupError> {
        if q.is_even() || !q.is_probab_prime(MR_REPS) {
            return Err(ClassGroupError::InvalidParameter(
                "q must be an odd prime".into(),
            ));
        }
        let qbits = q.nbits();
        let p = if delta_k_nbits <= qbits + 1 {
            if q.modulo(&Mpz::from(4u64)) == 3u64 {
                Mpz::from(1u64)
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

    pub fn q(&self) -> &Mpz {
        &self.q
    }
    pub fn k(&self) -> usize {
        self.k
    }
    pub fn p(&self) -> &Mpz {
        &self.p
    }
    pub fn m(&self) -> &Mpz {
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
    pub fn delta_k(&self) -> &Mpz {
        &self.delta_k
    }
    pub fn delta(&self) -> &Mpz {
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
    pub fn secretkey_bound(&self) -> &Mpz {
        &self.secretkey_bound
    }
    pub fn cleartext_bound(&self) -> &Mpz {
        &self.cleartext_bound
    }
    pub fn encrypt_randomness_bound(&self) -> &Mpz {
        &self.encrypt_randomness_bound
    }
    pub fn lambda_distance(&self) -> usize {
        self.lambda_distance
    }

    pub fn power_of_h(&self, n: &Mpz) -> QFI {
        if n.sgn() < 0 {
            return self.cl_delta.inverse(&self.power_of_h(&n.neg()));
        }
        if n.nbits() <= self.h_comb.max_bits() {
            self.cl_delta.exp_comb(&self.h_comb, n)
        } else {
            self.cl_delta.exp(&self.h, n)
        }
    }

    pub fn power_of_f(&self, m: &Mpz) -> QFI {
        let mm = m.modulo(&self.m);
        if mm.is_zero() {
            return self.cl_delta.identity();
        }
        let t = self.ring_param_from_exponent(&mm);
        self.form_from_ring_param(&t)
    }

    pub fn dlog_in_F(&self, fm: &QFI) -> Mpz {
        if fm.a().is_one() {
            return Mpz::new();
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
            let u = fm.b().divexact(&self.q);
            return u
                .invert(&self.q)
                .expect("dlog: form not in F")
                .modulo(&self.q);
        }
        self.dlog_in_F_general(fm)
    }

    pub fn from_cl_delta_k_to_cl_delta(&self, f: &mut QFI) {
        let mut lifted = f.lift(&self.m);
        self.cl_delta.reduce(&mut lifted);
        *f = lifted;
    }

    pub fn to_cl_delta_k(&self, f: &QFI) -> QFI {
        let mut g = f.to_maximal_order(&self.m, &self.delta_k);
        self.cl_delta_k.reduce(&mut g);
        g
    }

    fn psi(&self, omega: &QFI) -> QFI {
        let mut lifted = omega.clone();
        self.from_cl_delta_k_to_cl_delta(&mut lifted);
        self.cl_delta.exp(&lifted, &self.m)
    }

    fn c1_group(&self) -> &ClassGroup {
        if self.compact_variant {
            &self.cl_delta_k
        } else {
            &self.cl_delta
        }
    }

    fn enc_c1(&self, r: &Mpz) -> QFI {
        if self.compact_variant {
            self.cl_delta_k.exp(&self.gamma, r)
        } else {
            self.power_of_h(r)
        }
    }

    fn enc_mask(&self, pk: &PublicKey, r: &Mpz) -> QFI {
        if self.compact_variant {
            self.psi(&self.cl_delta_k.exp(pk.elt(), r))
        } else {
            self.cl_delta.exp_comb(pk.comb(self), r)
        }
    }

    pub fn genus(&self, f: &QFI) -> Genus {
        let pq = &self.p * &self.q;
        let one = Mpz::from(1u64);
        let candidates = [
            f.a().clone(),
            f.c().clone(),
            &(f.a() + f.b()) + f.c(),
        ];
        let v = candidates
            .into_iter()
            .find(|c| c.gcd(&pq) == one)
            .expect("no represented value coprime to p·q");
        (v.kronecker(&self.p), v.kronecker(&self.q))
    }

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

    pub fn encrypt_with_randomness(&self, pk: &PublicKey, m: &Cleartext, r: &Mpz) -> Ciphertext {
        let c1 = self.enc_c1(r);
        let c2 = self
            .cl_delta
            .compose(&self.power_of_f(m.as_mpz()), &self.enc_mask(pk, r));
        Ciphertext::new(c1, c2)
    }

    pub fn decrypt(&self, sk: &SecretKey, c: &Ciphertext) -> Cleartext {
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
        r: &Mpz,
    ) -> Ciphertext {
        let g1 = self.c1_group();
        let d = &self.cl_delta;
        let c1 = g1.compose(&g1.compose(ca.c1(), cb.c1()), &self.enc_c1(r));
        let c2 = d.compose(&d.compose(ca.c2(), cb.c2()), &self.enc_mask(pk, r));
        Ciphertext::new(c1, c2)
    }

    pub fn add_cleartexts(&self, ma: &Cleartext, mb: &Cleartext) -> Cleartext {
        Cleartext((ma.as_mpz() + mb.as_mpz()).modulo(&self.m))
    }

    pub fn scal_ciphertexts(
        &self,
        pk: &PublicKey,
        c: &Ciphertext,
        s: &Mpz,
        rng: &mut RandGen,
    ) -> Ciphertext {
        let r = rng.random_mpz(&self.encrypt_randomness_bound);
        self.scal_ciphertexts_with_randomness(pk, c, s, &r)
    }

    pub fn scal_ciphertexts_with_randomness(
        &self,
        pk: &PublicKey,
        c: &Ciphertext,
        s: &Mpz,
        r: &Mpz,
    ) -> Ciphertext {
        let g1 = self.c1_group();
        let d = &self.cl_delta;
        let c1 = g1.compose(&g1.exp(c.c1(), s), &self.enc_c1(r));
        let c2 = d.compose(&d.exp(c.c2(), s), &self.enc_mask(pk, r));
        Ciphertext::new(c1, c2)
    }

    pub fn scal_cleartexts(&self, m: &Cleartext, s: &Mpz) -> Cleartext {
        Cleartext((m.as_mpz() * s).modulo(&self.m))
    }

    pub fn addscal_ciphertexts(
        &self,
        pk: &PublicKey,
        ca: &Ciphertext,
        cb: &Ciphertext,
        s: &Mpz,
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
        s: &Mpz,
        r: &Mpz,
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

    fn ring_param_from_exponent(&self, m: &Mpz) -> Mpz {
        let n = &self.m;
        let p_param = Mpz::from(1u64);
        let q_param = (&Mpz::from(1u64) - &self.delta_k).fdiv_2exp(2);
        let (u_l, v_l) = lucas_uv(&p_param, &q_param, m, n, &self.delta_k);
        (&u_l * &v_l.invert(n).expect("V_m invertible mod q^k")).modulo(n)
    }

    fn form_from_ring_param(&self, t: &Mpz) -> QFI {
        if t.is_zero() {
            return self.cl_delta.identity();
        }
        let v = val_q(t, &self.q);
        let j = self.k - v;
        let qj = self.q.pow_u(j as u32);
        let qv = self.q.pow_u(v as u32);
        let two_qj = qj.mul_2exp(1);
        let w = t.divexact(&qv);
        let inv = w.modulo(&qj).invert(&qj).expect("w invertible mod q^j");
        let u_pos = if inv.is_odd() { inv } else { &inv + &qj };
        let u = center(u_pos, &two_qj, &qj);
        let a = &qj * &qj;
        let b = &u * &qj;
        let q2v = &qv * &qv;
        let c = (&(&u * &u) - &(&q2v * &self.delta_k)).divexact(&Mpz::from(4u64));
        let mut form = QFI::from_abc(a, b, c);
        self.cl_delta.reduce(&mut form);
        form
    }

    fn dlog_in_F_general(&self, fm: &QFI) -> Mpz {
        let n = &self.m;
        let dk = self.delta_k.modulo(n);

        let val = val_q(fm.a(), &self.q);
        let j = val / 2;
        let qj = self.q.pow_u(j as u32);
        let v = self.k - j;
        let qv = self.q.pow_u(v as u32);
        let u = fm.b().divexact(&qj);
        let t0 = (&qv * &u.invert(&qj).expect("u invertible mod q^j")).modulo(n);

        let mut cur = (Mpz::from(1u64), t0);
        let mut alpha = (Mpz::from(1u64), Mpz::from(1u64));
        let mut m_acc = Mpz::new();
        let mut qi = Mpz::from(1u64);
        for _ in 0..self.k {
            let tc = (&cur.1 * &cur.0.invert(n).expect("e invertible mod q^k")).modulo(n);
            let mi = tc.divexact(&qi).modulo(&self.q);
            let a_mi = ring_pow(&alpha, &mi, &dk, n);
            let a_mi_inv = ring_inv(&a_mi, &dk, n);
            cur = ring_mul(&cur, &a_mi_inv, &dk, n);
            alpha = ring_pow(&alpha, &self.q, &dk, n);
            m_acc = &m_acc + &(&mi * &qi);
            qi = &qi * &self.q;
        }
        m_acc
    }

    fn dlog_in_F_large_k1(&self, fm: &QFI) -> Mpz {
        let q = &self.q;
        let g = fm.to_maximal_order(q, &self.delta_k);
        let (e, f) = reduce_track_generator(&g, q);
        if e.sgn() != 0 {
            return (&f.neg() * &e.invert(q).expect("γ rational part invertible")).modulo(q);
        }
        let (e, f) = reduce_track_generator_exact(&g, &self.delta_k);
        let v = val_q(&e, q);
        let qv = q.pow_u(v as u32);
        let er = e.divexact(&qv);
        let fr = f.divexact(&qv);
        (&fr.neg() * &er.invert(q).expect("γ rational part a unit")).modulo(q)
    }
}

fn reduce_track_generator(g: &QFI, q: &Mpz) -> (Mpz, Mpz) {
    let (mut a, mut b, mut c) = (g.a().clone(), g.b().clone(), g.c().clone());
    let (mut e, mut f) = (Mpz::from(1u64), Mpz::new());
    normalize(&mut a, &mut b, &mut c);
    while a > c {
        let nf = (&e + &(&f * &b)).modulo(q);
        e = (&e * &b).modulo(q);
        f = nf;
        rho(&mut a, &mut b, &mut c);
    }
    (e, f)
}

fn reduce_track_generator_exact(g: &QFI, delta_k: &Mpz) -> (Mpz, Mpz) {
    let (mut a, mut b, mut c) = (g.a().clone(), g.b().clone(), g.c().clone());
    let (mut e, mut f) = (Mpz::from(1u64), Mpz::new());
    normalize(&mut a, &mut b, &mut c);
    while a > c {
        let ne = &(&e * &b) + &(&f * delta_k);
        let nf = &e + &(&f * &b);
        e = ne;
        f = nf;
        rho(&mut a, &mut b, &mut c);
    }
    (e, f)
}

fn normalize(a: &mut Mpz, b: &mut Mpz, c: &mut Mpz) {
    let two_a = a.mul_2exp(1);
    let r = (&*a - &*b).fdiv_q(&two_a);
    *c = &*c + &(&r * &(&*b + &(&*a * &r)));
    *b = &*b + &(&two_a * &r);
}

fn rho(a: &mut Mpz, b: &mut Mpz, c: &mut Mpz) {
    let s = (&*c + &*b).fdiv_q(&c.mul_2exp(1));
    let sc = &s * &*c;
    let new_c = &*a + &(&s * &(&sc - &*b));
    let new_b = &sc.mul_2exp(1) - &*b;
    *a = c.clone();
    *b = new_b;
    *c = new_c;
}

fn ring_mul(x: &(Mpz, Mpz), y: &(Mpz, Mpz), dk: &Mpz, n: &Mpz) -> (Mpz, Mpz) {
    let e = (&(&x.0 * &y.0) + &(&(&x.1 * &y.1) * dk)).modulo(n);
    let f = (&(&x.0 * &y.1) + &(&x.1 * &y.0)).modulo(n);
    (e, f)
}

fn ring_inv(x: &(Mpz, Mpz), dk: &Mpz, n: &Mpz) -> (Mpz, Mpz) {
    let norm = (&(&x.0 * &x.0) - &(&(&x.1 * &x.1) * dk)).modulo(n);
    let inv = norm.invert(n).expect("ring element not invertible mod q^k");
    let e = (&x.0 * &inv).modulo(n);
    let f = (&x.1.neg() * &inv).modulo(n);
    (e, f)
}

fn ring_pow(x: &(Mpz, Mpz), exp: &Mpz, dk: &Mpz, n: &Mpz) -> (Mpz, Mpz) {
    let mut result = (Mpz::from(1u64), Mpz::new());
    if exp.is_zero() {
        return result;
    }
    let mut base = (x.0.clone(), x.1.clone());
    for i in 0..exp.nbits() {
        if exp.get_bit(i as u32) {
            result = ring_mul(&result, &base, dk, n);
        }
        base = ring_mul(&base, &base, dk, n);
    }
    result
}

fn val_q(x: &Mpz, q: &Mpz) -> usize {
    if x.is_zero() {
        return 0;
    }
    let mut v = 0;
    let mut t = x.clone();
    while q.divides(&t) {
        t = t.divexact(q);
        v += 1;
    }
    v
}

fn center(x: Mpz, modulus: &Mpz, half: &Mpz) -> Mpz {
    if &x > half {
        &x - modulus
    } else {
        x
    }
}

fn lucas_uv(p_param: &Mpz, q_param: &Mpz, n: &Mpz, modn: &Mpz, d_param: &Mpz) -> (Mpz, Mpz) {
    if n.is_zero() {
        return (Mpz::new(), Mpz::from(2u64).modulo(modn));
    }
    let inv2 = Mpz::from(2u64).invert(modn).expect("2 invertible mod q^k");
    let pr = p_param.modulo(modn);
    let qr = q_param.modulo(modn);
    let dr = d_param.modulo(modn);

    let mut u = Mpz::from(1u64).modulo(modn);
    let mut v = pr.clone();
    let mut qpow = qr.clone();
    let nb = n.nbits();
    for i in (0..nb - 1).rev() {
        let u2 = (&u * &v).modulo(modn);
        let v2 = (&(&v * &v) - &qpow.mul_2exp(1)).modulo(modn);
        let q2 = (&qpow * &qpow).modulo(modn);
        if n.get_bit(i as u32) {
            let u_new = (&(&(&pr * &u2) + &v2) * &inv2).modulo(modn);
            let v_new = (&(&(&dr * &u2) + &(&pr * &v2)) * &inv2).modulo(modn);
            let q_new = (&q2 * &qr).modulo(modn);
            u = u_new;
            v = v_new;
            qpow = q_new;
        } else {
            u = u2;
            v = v2;
            qpow = q2;
        }
    }
    (u, v)
}

fn classnumber_upper_bound(delta_k: &Mpz) -> Mpz {
    let abs = delta_k.abs();
    let nbits = abs.nbits() as u64;
    let s = abs.sqrt();
    let sqrt_ceil = if (&s * &s) == abs { s } else { s.add_ui(1) };
    let numer =
        &(&(&Mpz::from(nbits) * &Mpz::from(6_931_472u64)) * &Mpz::from(3_183_099u64)) * &sqrt_ceil;
    let denom = Mpz::from(100_000_000_000_000u64);
    let (q, r) = numer.fdiv_qr(&denom);
    if r.is_zero() {
        q
    } else {
        q.add_ui(1)
    }
}

fn smallest_aux_prime(q: &Mpz) -> Mpz {
    let four = Mpz::from(4u64);
    let mut p = Mpz::from(3u64);
    loop {
        if p.is_probab_prime(MR_REPS) && (&p * q).modulo(&four) == 3u64 && p.kronecker(q) == -1 {
            return p;
        }
        p = p.next_prime();
    }
}

fn gen_aux_prime(q: &Mpz, pbits: usize, rng: &mut RandGen) -> Mpz {
    let four = Mpz::from(4u64);
    loop {
        let p = rng.random_prime(pbits);
        if (&p * q).modulo(&four) == 3u64 && p.kronecker(q) == -1 {
            return p;
        }
    }
}

fn build_h(cl: &ClassGroup, m: &Mpz, q: &Mpz, p: &Mpz) -> QFI {
    let mut l = Mpz::from(2u64);
    loop {
        if &l != q && &l != p && cl.discriminant().kronecker(&l) == 1 {
            let r = cl.prime_form(&l);
            let r2 = cl.square(&r);
            return cl.exp(&r2, m);
        }
        l = l.next_prime();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretKey(Mpz);

impl SecretKey {
    pub fn random(c: &CL_HSMqk, rng: &mut RandGen) -> Self {
        SecretKey(rng.random_mpz(&c.secretkey_bound))
    }
    pub fn from_mpz(c: &CL_HSMqk, v: Mpz) -> Result<Self, ClassGroupError> {
        if v.sgn() < 0 || v >= c.secretkey_bound {
            return Err(ClassGroupError::OutOfBounds(
                "secret key out of range".into(),
            ));
        }
        Ok(SecretKey(v))
    }
    pub fn as_mpz(&self) -> &Mpz {
        &self.0
    }
}
impl core::ops::Deref for SecretKey {
    type Target = Mpz;
    fn deref(&self) -> &Mpz {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cleartext(Mpz);

impl Cleartext {
    pub fn random(c: &CL_HSMqk, rng: &mut RandGen) -> Self {
        Cleartext(rng.random_mpz(&c.cleartext_bound))
    }
    pub fn from_mpz(c: &CL_HSMqk, v: Mpz) -> Result<Self, ClassGroupError> {
        if v.sgn() < 0 || v >= c.cleartext_bound {
            return Err(ClassGroupError::OutOfBounds(
                "cleartext out of range".into(),
            ));
        }
        Ok(Cleartext(v))
    }
    pub fn as_mpz(&self) -> &Mpz {
        &self.0
    }
}
impl core::ops::Deref for Cleartext {
    type Target = Mpz;
    fn deref(&self) -> &Mpz {
        &self.0
    }
}

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
            let exp_bits = c.secretkey_bound.nbits() + c.q.nbits() + 2;
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

    fn small_instance() -> (CL_HSMqk, RandGen) {
        let mut rng = RandGen::with_seed(&Mpz::from(20240602u64));
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

            let csum = c.add_ciphertexts(&pk, &ca, &cb, rng);
            let expect_sum = c.add_cleartexts(&ma, &mb);
            assert_eq!(c.decrypt(&sk, &csum).as_mpz(), expect_sum.as_mpz());

            let cscal = c.scal_ciphertexts(&pk, &ca, &s, rng);
            let expect_scal = c.scal_cleartexts(&ma, &s);
            assert_eq!(c.decrypt(&sk, &cscal).as_mpz(), expect_scal.as_mpz());

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

        let cc = c.with_compact_variant(true);
        check_encryption_roundtrip(&cc, &mut rng, 20);
        check_homomorphic(&cc, &mut rng, 10);
    }

    #[test]
    fn large_k_roundtrip() {
        let mut rng = RandGen::with_seed(&Mpz::from(777u64));
        let c = CL_HSMqk::with_random_q(5, 15, 150, &mut rng, Params::default()).unwrap();
        check_encryption_roundtrip(&c, &mut rng, 20);
        check_homomorphic(&c, &mut rng, 8);
        let cc = c.with_compact_variant(true);
        check_encryption_roundtrip(&cc, &mut rng, 10);
    }

    #[test]
    fn large_message_variant_roundtrip() {
        let mut rng = RandGen::with_seed(&Mpz::from(13131u64));
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
        let m = Cleartext::from_mpz(&c, Mpz::from(14u64)).unwrap();
        let ct = c.encrypt(&pk, &m, &mut rng);
        assert_eq!(c.decrypt(&sk, &ct).as_mpz(), &Mpz::from(14u64));
    }

    #[test]
    #[ignore = "perf micro-benchmark: pk-comb routing; run with --ignored --nocapture"]
    fn pk_pow_comb_vs_bare_timing() {
        use std::time::Instant;
        let mut setup = ClSetup::new_secp256k1_128bit("42").expect("setup");
        let (_sk, pk) = setup.keygen().expect("keygen");
        let z = {
            let (s2, _) = setup.keygen().expect("k2");
            let body = setup.sk_to_bytes(&s2).expect("bytes");
            let mut ext = vec![0xABu8; 28];
            ext.extend_from_slice(&body);
            ext
        };
        let elt = pk.elt().clone();
        const N: u32 = 20;
        let t0 = Instant::now();
        for _ in 0..N {
            let _ = setup.pk_pow_bytes(&pk, &z).expect("comb");
        }
        let t_comb = t0.elapsed() / N;
        let t1 = Instant::now();
        for _ in 0..N {
            let _ = setup.exp_bytes(&elt, &z).expect("bare");
        }
        let t_bare = t1.elapsed() / N;
        println!(
            "pk^z ({}-bit) amortised over {N} reuses: comb={t_comb:?} bare={t_bare:?} speedup={:.2}x",
            z.len() * 8,
            t_bare.as_secs_f64() / t_comb.as_secs_f64()
        );
    }
}
