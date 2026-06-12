use k256::Secp256k1;
use rand_core::OsRng;
use tecdsa_curve::TecdsaCurve;
use tecdsa_paillier::backend::Integer;

pub type C = Secp256k1;

pub fn random_scalar() -> k256::Scalar {
    C::random_scalar(&mut OsRng)
}

pub fn scalar_to_bytes(s: &k256::Scalar) -> Vec<u8> {
    tecdsa_curve::conv::scalar_to_bytes::<C>(s)
}

pub fn paillier_keys() -> (
    tecdsa_paillier::DecryptionKey,
    tecdsa_paillier::EncryptionKey,
) {
    let dk = tecdsa_paillier::DecryptionKey::generate(&mut OsRng).expect("paillier keygen");
    let ek = dk.encryption_key().clone();
    (dk, ek)
}

pub fn paillier_encrypt(
    ek: &tecdsa_paillier::EncryptionKey,
    plaintext: &Integer,
) -> (tecdsa_paillier::Ciphertext, tecdsa_paillier::Nonce) {
    ek.encrypt_with_random(&mut OsRng, plaintext)
        .expect("encrypt")
}

pub fn cl_setup() -> tecdsa_class_group::cl::ClSetup {
    tecdsa_class_group::cl::ClSetup::new_secp256k1_128bit("42042").expect("cl setup")
}

pub fn cl_setup_with_keys() -> (
    tecdsa_class_group::cl::ClSetup,
    tecdsa_class_group::cl::ClSecretKey,
    tecdsa_class_group::cl::ClPublicKey,
) {
    let mut setup = cl_setup();
    let (sk, pk) = setup.keygen().expect("cl keygen");
    (setup, sk, pk)
}

pub fn sample_below(bound: &Integer) -> Integer {
    bound.random_below_ref(&mut OsRng)
}

pub fn group_order() -> Integer {
    tecdsa_paillier::conv::group_order_integer::<C>()
}

pub fn ntilde_params() -> (Integer, Integer, Integer) {
    let p = Integer::generate_safe_prime(&mut OsRng, 1536);
    let q = Integer::generate_safe_prime(&mut OsRng, 1536);
    let n_tilde = &p * &q;
    let h1 = Integer::sample_in_mult_group_of(&mut OsRng, &n_tilde);
    let lambda = (&p - Integer::one()) * (&q - Integer::one());
    let h2 = h1.pow_mod_ref(&lambda, &n_tilde).expect("pow_mod for h2");
    (n_tilde, h1, h2)
}

pub fn pow_mod_signed(base: &Integer, exp: &Integer, modulus: &Integer) -> Integer {
    if exp.cmp0().is_lt() {
        let base_inv = base.invert_ref(modulus).expect("base must be invertible");
        let pos_exp = -exp.clone();
        base_inv.pow_mod_ref(&pos_exp, modulus).expect("pow_mod")
    } else {
        base.pow_mod_ref(exp, modulus).expect("pow_mod")
    }
}

pub fn jl_keys() -> (
    tecdsa_joye_libert::kgen::JlPublicKey,
    tecdsa_joye_libert::kgen::JlSecretKey,
    rug::Integer,
) {
    tecdsa_joye_libert::kgen::generate_keypair_with_qnr(1680, 712, &mut OsRng)
}

pub struct PaillierFixture {
    pub dk: tecdsa_paillier::DecryptionKey,
    pub ek: tecdsa_paillier::EncryptionKey,
}

impl PaillierFixture {
    pub fn generate() -> Self {
        let dk = tecdsa_paillier::DecryptionKey::generate(&mut OsRng).expect("paillier keygen");
        let ek = dk.encryption_key().clone();
        Self { dk, ek }
    }
}

pub struct NTildeFixture {
    pub n_tilde: Integer,
    pub h1: Integer,
    pub h2: Integer,
}

impl NTildeFixture {
    pub fn generate() -> Self {
        let (n_tilde, h1, h2) = ntilde_params();
        Self { n_tilde, h1, h2 }
    }

    pub fn to_mta_params(&self) -> tecdsa_paillier::zk::mta_range::NTildeParams {
        tecdsa_paillier::zk::mta_range::NTildeParams {
            N_tilde: self.n_tilde.clone(),
            h1: self.h1.clone(),
            h2: self.h2.clone(),
        }
    }
}

pub struct PedersenFixture {
    pub params: tecdsa_pedersen_mod::PedersenModParams,
    pub secret: tecdsa_pedersen_mod::PedersenModSecret,
}

impl PedersenFixture {
    pub fn generate() -> Self {
        let (params, secret) = tecdsa_pedersen_mod::PedersenModParams::generate(1536, &mut OsRng);
        Self { params, secret }
    }
}

pub struct JlFixture {
    pub pk: tecdsa_joye_libert::kgen::JlPublicKey,
    pub sk: tecdsa_joye_libert::kgen::JlSecretKey,
    pub x: rug::Integer,
}

impl JlFixture {
    pub fn generate() -> Self {
        let (pk, sk, x) = jl_keys();
        Self { pk, sk, x }
    }
}

pub struct JlExtraFixture {
    pub pk0: tecdsa_joye_libert::kgen::JlPublicKey,
}

impl JlExtraFixture {
    pub fn generate() -> Self {
        let (pk0, _, _) =
            tecdsa_joye_libert::kgen::generate_keypair_with_qnr(1680, 712, &mut OsRng);
        Self { pk0 }
    }
}
