use rug::Integer;
use tecdsa_bigint::{mul_mod, pow_mod};

use crate::{enc_dec::JlCiphertext, kgen::JlPublicKey};

#[must_use]
pub fn hadd(pk: &JlPublicKey, c1: &JlCiphertext, c2: &JlCiphertext) -> JlCiphertext {
    let c = mul_mod(&c1.c, &c2.c, &pk.n);
    JlCiphertext { c }
}

#[must_use]
pub fn hscmul(pk: &JlPublicKey, ct: &JlCiphertext, scalar: &Integer) -> JlCiphertext {
    let c = pow_mod(&ct.c, scalar, &pk.n);
    JlCiphertext { c }
}
