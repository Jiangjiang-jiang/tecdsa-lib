use rand_core::CryptoRngCore;
use rug::Integer;

#[allow(clippy::many_single_char_names)]
fn blum_sqrt(y: &Integer, p: &Integer, q: &Integer, n: &Integer) -> Integer {
    let p1 = Integer::from(p - 1);
    let q1 = Integer::from(q - 1);
    let e = (Integer::from(&p1 * &q1) + 4) / 8;
    y.clone().pow_mod(&e, n).unwrap()
}

#[allow(clippy::many_single_char_names)]
pub fn blum_fourth_root(y: &Integer, p: &Integer, q: &Integer, n: &Integer) -> Integer {
    let sqrt = blum_sqrt(y, p, q, n);
    blum_sqrt(&sqrt, p, q, n)
}

#[allow(clippy::many_single_char_names)]
pub fn find_residue(
    y: &Integer,
    w: &Integer,
    p: &Integer,
    q: &Integer,
    n: &Integer,
) -> Option<(bool, bool, Integer)> {
    let y_mod_p = Integer::from(y % p);
    let y_mod_q = Integer::from(y % q);
    let jp = tecdsa_bigint::jacobi(&y_mod_p, p);
    let jq = tecdsa_bigint::jacobi(&y_mod_q, q);

    match (jp, jq) {
        (1, 1) => return Some((false, false, y.clone())),
        (-1, -1) => {
            let neg_y = Integer::from(n - y);
            return Some((true, false, neg_y));
        }
        _ => {}
    }

    let wy = Integer::from(w * y) % n;
    let wy_mod_p = Integer::from(&wy % p);
    let wy_mod_q = Integer::from(&wy % q);
    let jp = tecdsa_bigint::jacobi(&wy_mod_p, p);
    let jq = tecdsa_bigint::jacobi(&wy_mod_q, q);

    match (jp, jq) {
        (1, 1) => Some((false, true, wy)),
        (-1, -1) => {
            let neg_wy = Integer::from(n - &wy);
            Some((true, true, neg_wy))
        }
        _ => None,
    }
}

pub fn sample_neg_jacobi(n: &Integer, rng: &mut impl CryptoRngCore) -> Integer {
    use tecdsa_bigint::SyncRng;
    let mut sync_rng = SyncRng(rng);
    let rug_rng = &mut rug::rand::ThreadRandState::new_custom(&mut sync_rng);
    loop {
        let w = n.clone().random_below(rug_rng);
        if w <= 1 {
            continue;
        }
        if w.clone().gcd(n) != 1 {
            continue;
        }
        if tecdsa_bigint::jacobi(&w, n) == -1 {
            return w;
        }
    }
}

pub fn mod_inverse(a: &Integer, m: &Integer) -> Option<Integer> {
    a.clone().invert(m).ok()
}

#[allow(clippy::many_single_char_names)]
pub fn is_probably_composite(n: &Integer, iterations: u32, _rng: &mut impl CryptoRngCore) -> bool {
    n.is_probably_prime(iterations) == rug::integer::IsPrime::No
}
