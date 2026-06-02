use bicycl_rs::{abi_version, version, ClDlogMessage, Context};

// ── helpers ──────────────────────────────────────────────────────────────────

/// Run a full threshold-ECDSA keygen+sign protocol for the given (n, t)
/// at 112-bit security and return whether the final signature is valid.
fn run_threshold_ecdsa(n: u32, t: u32, msg: &[u8]) -> bool {
    let ctx = Context::new().unwrap();
    let mut rng = ctx
        .randgen_from_seed_decimal(&format!("{}{}", n * 100 + t, 777))
        .unwrap();
    let s = ctx
        .threshold_ecdsa_session(&mut rng, 112, n, t)
        .unwrap()
        .keygen_round1(&ctx, &mut rng)
        .unwrap()
        .keygen_round2(&ctx, &mut rng)
        .unwrap()
        .keygen_finalize(&ctx)
        .unwrap()
        .sign_round1(&ctx, &mut rng, msg)
        .unwrap()
        .sign_round2(&ctx, &mut rng)
        .unwrap()
        .sign_round3(&ctx)
        .unwrap()
        .sign_round4(&ctx)
        .unwrap()
        .sign_round5(&ctx, &mut rng)
        .unwrap()
        .sign_round6(&ctx, &mut rng)
        .unwrap()
        .sign_round7(&ctx, &mut rng)
        .unwrap()
        .sign_round8(&ctx)
        .unwrap()
        .sign_finalize(&ctx)
        .unwrap();
    s.signature_valid(&ctx).unwrap()
}

fn mod_decimal(value: i64, modulus: i64) -> String {
    value.rem_euclid(modulus).to_string()
}

#[test]
fn smoke_safe_api() {
    assert_eq!(abi_version(), bicycl_rs_sys::BICYCL_CAPI_VERSION);
    assert!(!version().is_empty());

    let ctx = Context::new().expect("context init should succeed");
    assert_eq!(ctx.last_error(), "");

    let mut rng = ctx.randgen_from_seed_decimal("1337").unwrap();
    let cg = ctx.classgroup_from_discriminant_decimal("-23").unwrap();
    let one = cg.one(&ctx).unwrap();
    assert!(one.is_one(&ctx).unwrap());
    assert_eq!(one.discriminant_decimal(&ctx).unwrap(), "-23");

    let paillier = ctx.paillier(64).unwrap();
    let (sk, pk) = paillier.keygen(&ctx, &mut rng).unwrap();
    let ct = paillier.encrypt_decimal(&ctx, &pk, &mut rng, "42").unwrap();
    let clear = paillier.decrypt_decimal(&ctx, &pk, &sk, &ct).unwrap();
    assert_eq!(clear, "42");

    let jl = ctx.joye_libert(64, 8).unwrap();
    let (jl_sk, jl_pk) = jl.keygen(&ctx, &mut rng).unwrap();
    let jl_ct = jl.encrypt_decimal(&ctx, &jl_pk, &mut rng, "7").unwrap();
    let jl_clear = jl.decrypt_decimal(&ctx, &jl_sk, &jl_ct).unwrap();
    assert_eq!(jl_clear, "7");

    let cl = ctx.cl_hsmqk("3", 1, "5").unwrap();
    let (cl_sk, cl_pk) = cl.keygen(&ctx, &mut rng).unwrap();
    let cl_ct = cl.encrypt_decimal(&ctx, &cl_pk, &mut rng, "2").unwrap();
    let cl_clear = cl.decrypt_decimal(&ctx, &cl_sk, &cl_ct).unwrap();
    assert_eq!(cl_clear, "2");

    let cl_ct_add = cl
        .add_ciphertexts(&ctx, &cl_pk, &mut rng, &cl_ct, &cl_ct)
        .unwrap();
    assert_eq!(cl.decrypt_decimal(&ctx, &cl_sk, &cl_ct_add).unwrap(), "1");

    let cl_ct_scal = cl
        .scal_ciphertext_decimal(&ctx, &cl_pk, &mut rng, &cl_ct, "3")
        .unwrap();
    assert_eq!(cl.decrypt_decimal(&ctx, &cl_sk, &cl_ct_scal).unwrap(), "0");

    let cl_ct_addscal = cl
        .addscal_ciphertexts_decimal(&ctx, &cl_pk, &mut rng, &cl_ct, &cl_ct, "2")
        .unwrap();
    assert_eq!(
        cl.decrypt_decimal(&ctx, &cl_sk, &cl_ct_addscal).unwrap(),
        "0"
    );

    let cl2 = ctx.cl_hsm2k("15", 3).unwrap();
    let (cl2_sk, cl2_pk) = cl2.keygen(&ctx, &mut rng).unwrap();
    let cl2_ct = cl2.encrypt_decimal(&ctx, &cl2_pk, &mut rng, "5").unwrap();
    assert_eq!(cl2.decrypt_decimal(&ctx, &cl2_sk, &cl2_ct).unwrap(), "5");

    let cl2_add = cl2
        .add_ciphertexts(&ctx, &cl2_pk, &mut rng, &cl2_ct, &cl2_ct)
        .unwrap();
    assert_eq!(cl2.decrypt_decimal(&ctx, &cl2_sk, &cl2_add).unwrap(), "2");

    let cl2_scal = cl2
        .scal_ciphertext_decimal(&ctx, &cl2_pk, &mut rng, &cl2_ct, "3")
        .unwrap();
    assert_eq!(cl2.decrypt_decimal(&ctx, &cl2_sk, &cl2_scal).unwrap(), "7");

    let cl2_addscal = cl2
        .addscal_ciphertexts_decimal(&ctx, &cl2_pk, &mut rng, &cl2_ct, &cl2_ct, "2")
        .unwrap();
    assert_eq!(
        cl2.decrypt_decimal(&ctx, &cl2_sk, &cl2_addscal).unwrap(),
        "7"
    );

    let ecdsa = ctx.ecdsa(112).unwrap();
    let (ecdsa_sk, ecdsa_pk) = ecdsa.keygen(&ctx, &mut rng).unwrap();
    let sig = ecdsa
        .sign_message(&ctx, &mut rng, &ecdsa_sk, b"abc")
        .unwrap();
    assert!(ecdsa.verify_message(&ctx, &ecdsa_pk, b"abc", &sig).unwrap());
    assert!(!ecdsa.verify_message(&ctx, &ecdsa_pk, b"abd", &sig).unwrap());
    assert!(!sig.r_decimal(&ctx).unwrap().is_empty());
    assert!(!sig.s_decimal(&ctx).unwrap().is_empty());

    let tp = ctx.two_party_ecdsa_session(&mut rng, 112).unwrap();
    let tp = tp.keygen_round1(&ctx, &mut rng).unwrap();
    let tp = tp.keygen_round2(&ctx, &mut rng).unwrap();
    let tp = tp.keygen_round3(&ctx, &mut rng).unwrap();
    let tp = tp.keygen_round4(&ctx).unwrap();
    let tp = tp.sign_round1(&ctx, &mut rng, b"abc").unwrap();
    let tp = tp.sign_round2(&ctx, &mut rng).unwrap();
    let tp = tp.sign_round3(&ctx).unwrap();
    let tp = tp.sign_round4(&ctx, &mut rng).unwrap();
    let (_tp, valid) = tp.sign_finalize(&ctx).unwrap();
    assert!(valid);

    let dlog = ctx.cl_dlog_session(&mut rng, 112).unwrap();
    let dlog = dlog.prepare_statement(&ctx, &mut rng).unwrap();
    let dlog = dlog.prove_round(&ctx, &mut rng).unwrap();
    assert!(dlog.verify_round(&ctx).unwrap());

    let mut stmt = ClDlogMessage::new().unwrap();
    let mut proof = ClDlogMessage::new().unwrap();
    dlog.export_statement(&ctx, &mut stmt).unwrap();
    dlog.export_proof(&ctx, &mut proof).unwrap();
    let stmt_bytes = stmt.to_bytes(&ctx).unwrap();
    let proof_bytes = proof.to_bytes(&ctx).unwrap();
    let mut stmt_rx = ClDlogMessage::new().unwrap();
    let mut proof_rx = ClDlogMessage::new().unwrap();
    stmt_rx.load_bytes(&ctx, &stmt_bytes).unwrap();
    proof_rx.load_bytes(&ctx, &proof_bytes).unwrap();
    let verifier = ctx.cl_dlog_session(&mut rng, 112).unwrap();
    let verifier = verifier.import_statement(&ctx, &stmt_rx).unwrap();
    let verifier = verifier.import_proof(&ctx, &proof_rx).unwrap();
    assert!(verifier.verify_round(&ctx).unwrap());

    let th = ctx.threshold_ecdsa_session(&mut rng, 112, 2, 1).unwrap();
    let th = th.keygen_round1(&ctx, &mut rng).unwrap();
    let th = th.keygen_round2(&ctx, &mut rng).unwrap();
    let th = th.keygen_finalize(&ctx).unwrap();
    let th = th.sign_round1(&ctx, &mut rng, b"abc").unwrap();
    let th = th.sign_round2(&ctx, &mut rng).unwrap();
    let th = th.sign_round3(&ctx).unwrap();
    let th = th.sign_round4(&ctx).unwrap();
    let th = th.sign_round5(&ctx, &mut rng).unwrap();
    let th = th.sign_round6(&ctx, &mut rng).unwrap();
    let th = th.sign_round7(&ctx, &mut rng).unwrap();
    let th = th.sign_round8(&ctx).unwrap();
    let th = th.sign_finalize(&ctx).unwrap();
    assert!(th.signature_valid(&ctx).unwrap());
}

#[test]
fn zeroize_works() {
    let mut buf = [10_u8, 20, 30, 40];
    bicycl_rs::zeroize(&mut buf);
    assert_eq!(buf, [0_u8; 4]);
}

#[test]
fn repeated_encrypt_decrypt_matches_upstream_test_patterns() {
    let ctx = Context::new().unwrap();
    let mut rng = ctx.randgen_from_seed_decimal("20250309").unwrap();

    let paillier = ctx.paillier(64).unwrap();
    let (paillier_sk, paillier_pk) = paillier.keygen(&ctx, &mut rng).unwrap();
    for message in ["0", "1", "2", "17", "42"] {
        let ct = paillier
            .encrypt_decimal(&ctx, &paillier_pk, &mut rng, message)
            .unwrap();
        let clear = paillier
            .decrypt_decimal(&ctx, &paillier_pk, &paillier_sk, &ct)
            .unwrap();
        assert_eq!(clear, message);
    }

    let jl = ctx.joye_libert(64, 8).unwrap();
    let (jl_sk, jl_pk) = jl.keygen(&ctx, &mut rng).unwrap();
    for message in ["0", "1", "7", "13"] {
        let ct = jl.encrypt_decimal(&ctx, &jl_pk, &mut rng, message).unwrap();
        let clear = jl.decrypt_decimal(&ctx, &jl_sk, &ct).unwrap();
        assert_eq!(clear, message);
    }
}

#[test]
fn ecdsa_rejects_wrong_key_and_wrong_message_across_multiple_cases() {
    let ctx = Context::new().unwrap();
    let mut rng = ctx.randgen_from_seed_decimal("424242").unwrap();
    let ecdsa = ctx.ecdsa(112).unwrap();

    for message in [
        b"abc".as_slice(),
        b"message-2".as_slice(),
        b"\x00\x01payload".as_slice(),
    ] {
        let (sk, pk) = ecdsa.keygen(&ctx, &mut rng).unwrap();
        let (wrong_sk, wrong_pk) = ecdsa.keygen(&ctx, &mut rng).unwrap();
        let sig = ecdsa.sign_message(&ctx, &mut rng, &sk, message).unwrap();

        assert!(ecdsa.verify_message(&ctx, &pk, message, &sig).unwrap());
        assert!(!ecdsa
            .verify_message(&ctx, &wrong_pk, message, &sig)
            .unwrap());

        let wrong_sig = ecdsa
            .sign_message(&ctx, &mut rng, &wrong_sk, message)
            .unwrap();
        assert!(!ecdsa
            .verify_message(&ctx, &pk, message, &wrong_sig)
            .unwrap());

        let wrong_message = if message == b"abc" {
            b"abd".as_slice()
        } else {
            b"abc".as_slice()
        };
        assert!(!ecdsa
            .verify_message(&ctx, &pk, wrong_message, &sig)
            .unwrap());
    }
}

#[test]
fn cl_ciphertext_ops_match_expected_modular_results() {
    let ctx = Context::new().unwrap();
    let mut rng = ctx.randgen_from_seed_decimal("777").unwrap();

    let cl_qk = ctx.cl_hsmqk("3", 1, "5").unwrap();
    let (cl_qk_sk, cl_qk_pk) = cl_qk.keygen(&ctx, &mut rng).unwrap();
    for (a, b, scalar) in [(0_i64, 0_i64, 0_i64), (1, 2, 2), (2, 2, 3), (2, 1, 4)] {
        let ct_a = cl_qk
            .encrypt_decimal(&ctx, &cl_qk_pk, &mut rng, &a.to_string())
            .unwrap();
        let ct_b = cl_qk
            .encrypt_decimal(&ctx, &cl_qk_pk, &mut rng, &b.to_string())
            .unwrap();

        let ct_sum = cl_qk
            .add_ciphertexts(&ctx, &cl_qk_pk, &mut rng, &ct_a, &ct_b)
            .unwrap();
        let sum = cl_qk.decrypt_decimal(&ctx, &cl_qk_sk, &ct_sum).unwrap();
        assert_eq!(sum, mod_decimal(a + b, 3));

        let ct_scal = cl_qk
            .scal_ciphertext_decimal(&ctx, &cl_qk_pk, &mut rng, &ct_a, &scalar.to_string())
            .unwrap();
        let scal = cl_qk.decrypt_decimal(&ctx, &cl_qk_sk, &ct_scal).unwrap();
        assert_eq!(scal, mod_decimal(a * scalar, 3));
    }

    let cl_2k = ctx.cl_hsm2k("15", 3).unwrap();
    let (cl_2k_sk, cl_2k_pk) = cl_2k.keygen(&ctx, &mut rng).unwrap();
    for (a, b, scalar) in [(0_i64, 0_i64, 0_i64), (1, 6, 3), (5, 5, 2), (7, 4, 5)] {
        let ct_a = cl_2k
            .encrypt_decimal(&ctx, &cl_2k_pk, &mut rng, &a.to_string())
            .unwrap();
        let ct_b = cl_2k
            .encrypt_decimal(&ctx, &cl_2k_pk, &mut rng, &b.to_string())
            .unwrap();

        let ct_sum = cl_2k
            .add_ciphertexts(&ctx, &cl_2k_pk, &mut rng, &ct_a, &ct_b)
            .unwrap();
        let sum = cl_2k.decrypt_decimal(&ctx, &cl_2k_sk, &ct_sum).unwrap();
        assert_eq!(sum, mod_decimal(a + b, 8));

        let ct_scal = cl_2k
            .scal_ciphertext_decimal(&ctx, &cl_2k_pk, &mut rng, &ct_a, &scalar.to_string())
            .unwrap();
        let scal = cl_2k.decrypt_decimal(&ctx, &cl_2k_sk, &ct_scal).unwrap();
        assert_eq!(scal, mod_decimal(a * scalar, 8));
    }
}

#[test]
fn classgroup_nudupl_of_identity_is_identity() {
    let ctx = Context::new().unwrap();
    let cg = ctx.classgroup_from_discriminant_decimal("-23").unwrap();
    let one = cg.one(&ctx).unwrap();
    let squared = cg.nudupl(&ctx, &one).unwrap();
    assert!(squared.is_one(&ctx).unwrap());
    assert_eq!(squared.discriminant_decimal(&ctx).unwrap(), "-23");
}

#[test]
fn context_clear_error_resets_last_error() {
    let mut ctx = Context::new().unwrap();
    assert_eq!(ctx.last_error(), "");
    ctx.clear_error();
    assert_eq!(ctx.last_error(), "");
}

#[test]
fn cl_dlog_prover_self_verify_without_export() {
    let ctx = Context::new().unwrap();
    let mut rng = ctx.randgen_from_seed_decimal("9999").unwrap();
    let session = ctx.cl_dlog_session(&mut rng, 112).unwrap();
    let session = session.prepare_statement(&ctx, &mut rng).unwrap();
    let session = session.prove_round(&ctx, &mut rng).unwrap();
    assert!(session.verify_round(&ctx).unwrap());
}

#[test]
fn error_display_formatting() {
    use bicycl_rs::Error;

    assert_eq!(Error::NullPtr.to_string(), "BICYCL null pointer");
    assert_eq!(
        Error::InvalidArgument.to_string(),
        "BICYCL invalid argument"
    );
    assert_eq!(Error::Parse.to_string(), "BICYCL parse error");
    assert_eq!(
        Error::InvalidState.to_string(),
        "BICYCL invalid protocol state"
    );
    assert_eq!(
        Error::Unknown(999).to_string(),
        "unknown BICYCL error code: 999"
    );
}

#[test]
fn ecdsa_signature_r_s_are_valid_decimals() {
    let ctx = Context::new().unwrap();
    let mut rng = ctx.randgen_from_seed_decimal("54321").unwrap();
    let ecdsa = ctx.ecdsa(112).unwrap();
    let (sk, _pk) = ecdsa.keygen(&ctx, &mut rng).unwrap();
    let sig = ecdsa.sign_message(&ctx, &mut rng, &sk, b"test").unwrap();

    let r = sig.r_decimal(&ctx).unwrap();
    let s = sig.s_decimal(&ctx).unwrap();
    assert!(!r.is_empty());
    assert!(!s.is_empty());
    assert!(r.chars().all(|c| c.is_ascii_digit()));
    assert!(s.chars().all(|c| c.is_ascii_digit()));
    assert_ne!(r, s);
}

#[test]
fn threshold_ecdsa_3_of_2() {
    let ctx = Context::new().unwrap();
    let mut rng = ctx.randgen_from_seed_decimal("3232").unwrap();

    let th = ctx.threshold_ecdsa_session(&mut rng, 112, 3, 2).unwrap();
    let th = th.keygen_round1(&ctx, &mut rng).unwrap();
    let th = th.keygen_round2(&ctx, &mut rng).unwrap();
    let th = th.keygen_finalize(&ctx).unwrap();
    let th = th.sign_round1(&ctx, &mut rng, b"threshold-msg").unwrap();
    let th = th.sign_round2(&ctx, &mut rng).unwrap();
    let th = th.sign_round3(&ctx).unwrap();
    let th = th.sign_round4(&ctx).unwrap();
    let th = th.sign_round5(&ctx, &mut rng).unwrap();
    let th = th.sign_round6(&ctx, &mut rng).unwrap();
    let th = th.sign_round7(&ctx, &mut rng).unwrap();
    let th = th.sign_round8(&ctx).unwrap();
    let th = th.sign_finalize(&ctx).unwrap();
    assert!(th.signature_valid(&ctx).unwrap());
}

#[test]
fn debug_impls_do_not_panic() {
    let ctx = Context::new().unwrap();
    let mut rng = ctx.randgen_from_seed_decimal("7777").unwrap();

    let tp = ctx.two_party_ecdsa_session(&mut rng, 112).unwrap();
    let _ = format!("{tp:?}");

    let dlog = ctx.cl_dlog_session(&mut rng, 112).unwrap();
    let _ = format!("{dlog:?}");

    let th = ctx.threshold_ecdsa_session(&mut rng, 112, 2, 1).unwrap();
    let _ = format!("{th:?}");
}

// ── CL_HSMqk k=2 ─────────────────────────────────────────────────────────────

/// Upstream test_CL_HSMqk.cpp tests k=1 and k=2.  Here we verify that the
/// Rust wrapper correctly handles k=2, where the plaintext space is Z/q^k.
///
/// Parameters: q=19, k=2, p=193.  These satisfy the required constraints:
///   - q and p are prime
///   - Kronecker(q, p) = -1  (193 ≡ 3 mod 19, which is a QNR mod 19)
///   - -q*p ≡ 1 (mod 4)  (-19*193 mod 4 = 1 ✓)
///   - p > 4*q (193 > 76)
///
/// Note: the upstream "small" test uses 5-bit random q with DeltaK ≥ 150 bits
/// (i.e. a ~147-bit p).  Here q=19 (5-bit) with p=193 gives DeltaK of only
/// 12 bits — intentionally minimal for a fast wrapper correctness test,
/// consistent with the N=15 convention used elsewhere in this suite.
/// The dlog_in_F algorithm is algebraic and correct regardless of discriminant
/// size; security properties require a much larger discriminant in practice.
#[test]
fn cl_hsmqk_k2_plaintext_space_and_homomorphism() {
    let ctx = Context::new().unwrap();
    let mut rng = ctx.randgen_from_seed_decimal("20241").unwrap();

    // Plaintext space: Z/19^2 = Z/361
    let q = 19_i64;
    let k = 2_u32;
    let modulus = q.pow(k); // 361
    let cl = ctx.cl_hsmqk(&q.to_string(), k, "193").unwrap();
    let (sk, pk) = cl.keygen(&ctx, &mut rng).unwrap();

    // Round-trip for boundary and interior values
    for m in ["0", "1", "18", "19", "360"] {
        let ct = cl.encrypt_decimal(&ctx, &pk, &mut rng, m).unwrap();
        assert_eq!(
            cl.decrypt_decimal(&ctx, &sk, &ct).unwrap(),
            m,
            "k=2 roundtrip failed for m={m}"
        );
    }

    // Homomorphic add: (19 + 18) mod 361 = 37
    let ct19 = cl.encrypt_decimal(&ctx, &pk, &mut rng, "19").unwrap();
    let ct18 = cl.encrypt_decimal(&ctx, &pk, &mut rng, "18").unwrap();
    let sum = cl
        .add_ciphertexts(&ctx, &pk, &mut rng, &ct19, &ct18)
        .unwrap();
    let expected_sum = (19_i64 + 18).rem_euclid(modulus).to_string();
    assert_eq!(cl.decrypt_decimal(&ctx, &sk, &sum).unwrap(), expected_sum);

    // Homomorphic scalar mult: 19 * 3 mod 361 = 57
    let scaled = cl
        .scal_ciphertext_decimal(&ctx, &pk, &mut rng, &ct19, "3")
        .unwrap();
    let expected_scaled = (19_i64 * 3).rem_euclid(modulus).to_string();
    assert_eq!(
        cl.decrypt_decimal(&ctx, &sk, &scaled).unwrap(),
        expected_scaled
    );

    // addscal: Enc(19) + Enc(18)*2 = (19 + 36) mod 361 = 55
    let addscal = cl
        .addscal_ciphertexts_decimal(&ctx, &pk, &mut rng, &ct19, &ct18, "2")
        .unwrap();
    let expected_addscal = (19_i64 + 18 * 2).rem_euclid(modulus).to_string();
    assert_eq!(
        cl.decrypt_decimal(&ctx, &sk, &addscal).unwrap(),
        expected_addscal
    );
}

// ── CL_HSM2k k=8 ─────────────────────────────────────────────────────────────

/// Upstream test_CL_HSM2k.cpp tests k=64 (standard path), k=128 and k=1100
/// (large_message_variant path, triggered when 2^(2k) > |DeltaK|).
/// With N=15 (DeltaK=-120) and k=8: 2^16=65536 >> 120, so this test
/// exercises the large_message_variant path — the same branch covered by the
/// upstream's k=128/k=1100 cases — while keeping key generation fast.
#[test]
fn cl_hsm2k_k8_boundary_values_and_wrap_around() {
    let ctx = Context::new().unwrap();
    let mut rng = ctx.randgen_from_seed_decimal("20248").unwrap();

    // Plaintext space: Z/2^8 = Z/256
    let cl2 = ctx.cl_hsm2k("15", 8).unwrap();
    let (sk, pk) = cl2.keygen(&ctx, &mut rng).unwrap();

    // Boundary values
    for m in ["0", "1", "127", "255"] {
        let ct = cl2.encrypt_decimal(&ctx, &pk, &mut rng, m).unwrap();
        assert_eq!(
            cl2.decrypt_decimal(&ctx, &sk, &ct).unwrap(),
            m,
            "k=8 roundtrip failed for m={m}"
        );
    }

    // Wrap-around add: (200 + 100) mod 256 = 44
    let ct200 = cl2.encrypt_decimal(&ctx, &pk, &mut rng, "200").unwrap();
    let ct100 = cl2.encrypt_decimal(&ctx, &pk, &mut rng, "100").unwrap();
    let sum = cl2
        .add_ciphertexts(&ctx, &pk, &mut rng, &ct200, &ct100)
        .unwrap();
    assert_eq!(cl2.decrypt_decimal(&ctx, &sk, &sum).unwrap(), "44");

    // Scalar: 100 * 3 mod 256 = 44
    let scaled = cl2
        .scal_ciphertext_decimal(&ctx, &pk, &mut rng, &ct100, "3")
        .unwrap();
    assert_eq!(cl2.decrypt_decimal(&ctx, &sk, &scaled).unwrap(), "44");

    // addscal: Enc(200) + Enc(100)*2 = (200 + 200) mod 256 = 144
    let addscal = cl2
        .addscal_ciphertexts_decimal(&ctx, &pk, &mut rng, &ct200, &ct100, "2")
        .unwrap();
    assert_eq!(cl2.decrypt_decimal(&ctx, &sk, &addscal).unwrap(), "144");
}

// ── ECDSA 128-bit ─────────────────────────────────────────────────────────────

/// Upstream test_ec.cpp tests security levels 112, 128, 192, 256.
/// The Rust suite previously only covered 112; this adds 128-bit.
#[test]
fn ecdsa_128bit_security_level() {
    let ctx = Context::new().unwrap();
    let mut rng = ctx.randgen_from_seed_decimal("20128").unwrap();

    let ecdsa = ctx.ecdsa(128).unwrap();
    let (sk, pk) = ecdsa.keygen(&ctx, &mut rng).unwrap();

    for msg in [b"hello".as_slice(), b"bicycl-rs", b"\x00\x01\x02\x03"] {
        let sig = ecdsa.sign_message(&ctx, &mut rng, &sk, msg).unwrap();
        assert!(
            ecdsa.verify_message(&ctx, &pk, msg, &sig).unwrap(),
            "128-bit ECDSA should verify its own signature"
        );
        assert!(
            !ecdsa.verify_message(&ctx, &pk, b"tampered", &sig).unwrap(),
            "128-bit ECDSA should reject a modified message"
        );
    }

    // r and s components should be non-empty decimal digits
    let sig = ecdsa.sign_message(&ctx, &mut rng, &sk, b"test").unwrap();
    let r = sig.r_decimal(&ctx).unwrap();
    let s = sig.s_decimal(&ctx).unwrap();
    assert!(r.chars().all(|c| c.is_ascii_digit()) && !r.is_empty());
    assert!(s.chars().all(|c| c.is_ascii_digit()) && !s.is_empty());
}

// ── Joye-Libert larger k ──────────────────────────────────────────────────────

/// Upstream test_Joye_Libert.cpp tests k=32 (small: N_nbits=200) and k=64
/// (security levels 112–192).  Here we use k=16 with modulus_bits=64, following
/// the convention of this test suite (small N).  k=32 at modulus_bits=64 hits
/// the k = modulus_bits/2 boundary and is prohibitively slow; the upstream's
/// k=32 test pairs it with a 200-bit N which avoids that degenerate case.
/// k=16 exercises a distinct plaintext space ([0, 2^16)) from the existing
/// k=8 tests, covering boundary values including sub-byte and multi-byte edges.
#[test]
fn joye_libert_k16_plaintext_space() {
    let ctx = Context::new().unwrap();
    let mut rng = ctx.randgen_from_seed_decimal("20116").unwrap();

    // k=16: plaintext space [0, 2^16) = [0, 65536)
    let jl = ctx.joye_libert(64, 16).unwrap();
    let (sk, pk) = jl.keygen(&ctx, &mut rng).unwrap();

    for m in ["0", "1", "255", "256", "32767", "65535"] {
        let ct = jl.encrypt_decimal(&ctx, &pk, &mut rng, m).unwrap();
        assert_eq!(
            jl.decrypt_decimal(&ctx, &sk, &ct).unwrap(),
            m,
            "JL k=16 roundtrip failed for m={m}"
        );
    }
}

// ── Threshold ECDSA additional configurations ─────────────────────────────────

/// Upstream test_CL_threshold.cpp covers (n,t) pairs including (5,2), (7,4),
/// (10,9).  We test a selection of additional configurations to ensure the
/// typestate API handles different player counts correctly.
#[test]
fn threshold_ecdsa_additional_configurations() {
    for (n, t) in [(4u32, 2u32), (5, 3)] {
        assert!(
            run_threshold_ecdsa(n, t, b"threshold test"),
            "threshold ({n},{t}) should produce a valid signature"
        );
    }
}
