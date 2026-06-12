use super::mpz::Mpz;

pub fn sqrt_mod_prime(a: &Mpz, p: &Mpz) -> Option<Mpz> {
    let one = Mpz::from(1u64);
    let am = a.modulo(p);
    if am.is_zero() {
        return Some(Mpz::new());
    }
    if am.kronecker(p) != 1 {
        return None;
    }

    if p.modulo(&Mpz::from(4u64)) == 3u64 {
        let e = p.add_ui(1).fdiv_2exp(2);
        return Some(am.powm(&e, p));
    }

    let pm1 = p - &one;
    let mut s: u32 = 0;
    let mut q = pm1.clone();
    while q.is_even() {
        q = q.fdiv_2exp(1);
        s += 1;
    }

    let mut z = Mpz::from(2u64);
    while z.kronecker(p) != -1 {
        z = z.add_ui(1);
    }

    let mut m = s;
    let mut c = z.powm(&q, p);
    let mut t = am.powm(&q, p);
    let mut r = am.powm(&q.add_ui(1).fdiv_2exp(1), p);

    loop {
        if t == one {
            return Some(r);
        }
        let mut i: u32 = 0;
        let mut t2 = t.clone();
        while t2 != one {
            t2 = t2.powm(&Mpz::from(2u64), p);
            i += 1;
            if i == m {
                return None;
            }
        }
        let mut b = c.clone();
        for _ in 0..(m - i - 1) {
            b = b.powm(&Mpz::from(2u64), p);
        }
        m = i;
        c = b.powm(&Mpz::from(2u64), p);
        t = (&t * &c).modulo(p);
        r = (&r * &b).modulo(p);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqrt_mod_small_primes() {
        let p = Mpz::from(13u64);
        for a in 1u64..13 {
            let am = Mpz::from(a);
            match sqrt_mod_prime(&am, &p) {
                Some(x) => assert_eq!((&x * &x).modulo(&p), am),
                None => assert_eq!(am.kronecker(&p), -1),
            }
        }
    }

    #[test]
    fn sqrt_mod_p3mod4() {
        let p = Mpz::from(103u64);
        let a = Mpz::from(7u64);
        if let Some(x) = sqrt_mod_prime(&a, &p) {
            assert_eq!((&x * &x).modulo(&p), a);
        } else {
            assert_eq!(a.kronecker(&p), -1);
        }
    }

    #[test]
    fn sqrt_mod_large_prime() {
        let p = Mpz::from_str_auto("0xfffffffffffffffffffffffffffffffeffffffffffffffff").unwrap();
        let a = Mpz::from(123456789u64);
        if let Some(x) = sqrt_mod_prime(&a, &p) {
            assert_eq!((&x * &x).modulo(&p), a.modulo(&p));
        }
    }
}
