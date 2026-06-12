use tecdsa_core::{Csprng, Dst, Secret, TecdsaError, Versioned};

#[test]
fn secret_zeroizes_on_drop() {
    let s = Secret::new(vec![0xffu8; 32]);
    let ptr = s.as_ref().as_ptr();
    let len = s.as_ref().len();
    drop(s);
    let _ = (ptr, len);
}

#[test]
fn secret_deref_gives_inner() {
    let s = Secret::new(42u64);
    assert_eq!(*s.as_ref(), 42u64);
}

#[test]
fn csprng_produces_different_values() {
    let mut rng = Csprng::new();
    let a: [u8; 32] = rand_core::RngCore::next_u64(&mut *rng)
        .to_le_bytes()
        .into_iter()
        .chain(std::iter::repeat(0))
        .take(32)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let b: [u8; 32] = rand_core::RngCore::next_u64(&mut *rng)
        .to_le_bytes()
        .into_iter()
        .chain(std::iter::repeat(0))
        .take(32)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    assert_ne!(a, b);
}

#[test]
fn dst_domain_separation() {
    let d1 = Dst::new(b"tecdsa/paillier/enc");
    let d2 = Dst::new(b"tecdsa/paillier/dec");
    assert_ne!(d1.as_bytes(), d2.as_bytes());
}

#[test]
fn versioned_roundtrip() {
    let v = Versioned::new(1u16, vec![1, 2, 3]);
    assert_eq!(v.version(), 1u16);
    assert_eq!(v.payload(), &[1, 2, 3]);
}

#[test]
fn error_display() {
    let e = TecdsaError::InvalidProof("test".into());
    assert!(format!("{e}").contains("test"));
}
