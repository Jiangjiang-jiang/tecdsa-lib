use std::ffi::{CStr, CString};
use std::ptr;

use bicycl_rs_sys::*;

#[test]
fn smoke_api() {
    unsafe {
        assert_eq!(bicycl_get_abi_version(), BICYCL_CAPI_VERSION);

        let version_ptr = bicycl_get_version();
        assert!(!version_ptr.is_null());
        let version = CStr::from_ptr(version_ptr).to_str().unwrap();
        assert!(!version.is_empty());

        let msg_ptr = bicycl_status_message(bicycl_status_t::BICYCL_OK);
        assert!(!msg_ptr.is_null());
        assert_eq!(CStr::from_ptr(msg_ptr).to_str().unwrap(), "ok");

        let mut ctx: *mut bicycl_context_t = ptr::null_mut();
        assert_eq!(
            bicycl_context_new(&mut ctx as *mut _),
            bicycl_status_t::BICYCL_OK
        );

        let mut rng: *mut bicycl_randgen_t = ptr::null_mut();
        let seed = CString::new("1337").unwrap();
        assert_eq!(
            bicycl_randgen_new_from_seed_decimal(ctx, seed.as_ptr(), &mut rng as *mut _),
            bicycl_status_t::BICYCL_OK
        );

        let mut cg: *mut bicycl_classgroup_t = ptr::null_mut();
        let disc = CString::new("-23").unwrap();
        assert_eq!(
            bicycl_classgroup_new_from_discriminant_decimal(ctx, disc.as_ptr(), &mut cg as *mut _),
            bicycl_status_t::BICYCL_OK
        );

        let mut one: *mut bicycl_qfi_t = ptr::null_mut();
        assert_eq!(
            bicycl_classgroup_one(ctx, cg, &mut one as *mut _),
            bicycl_status_t::BICYCL_OK
        );

        let mut is_one: i32 = 0;
        assert_eq!(
            bicycl_qfi_is_one(ctx, one, &mut is_one as *mut _),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(is_one, 1);

        let mut disc_len: usize = 0;
        assert_eq!(
            bicycl_qfi_discriminant_decimal(ctx, one, ptr::null_mut(), &mut disc_len as *mut _),
            bicycl_status_t::BICYCL_ERR_BUFFER_TOO_SMALL
        );
        let mut disc_buf = vec![0_u8; disc_len];
        assert_eq!(
            bicycl_qfi_discriminant_decimal(
                ctx,
                one,
                disc_buf.as_mut_ptr().cast(),
                &mut disc_len as *mut _
            ),
            bicycl_status_t::BICYCL_OK
        );
        let disc_out = CStr::from_bytes_with_nul(&disc_buf)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(disc_out, "-23");

        let mut paillier: *mut bicycl_paillier_t = ptr::null_mut();
        assert_eq!(
            bicycl_paillier_new(ctx, 64, &mut paillier as *mut _),
            bicycl_status_t::BICYCL_OK
        );

        let mut sk: *mut bicycl_paillier_sk_t = ptr::null_mut();
        let mut pk: *mut bicycl_paillier_pk_t = ptr::null_mut();
        assert_eq!(
            bicycl_paillier_keygen(ctx, paillier, rng, &mut sk as *mut _, &mut pk as *mut _),
            bicycl_status_t::BICYCL_OK
        );

        let msg = CString::new("42").unwrap();
        let mut ct: *mut bicycl_paillier_ct_t = ptr::null_mut();
        assert_eq!(
            bicycl_paillier_encrypt_decimal(
                ctx,
                paillier,
                pk,
                rng,
                msg.as_ptr(),
                &mut ct as *mut _
            ),
            bicycl_status_t::BICYCL_OK
        );

        let mut out_len: usize = 0;
        assert_eq!(
            bicycl_paillier_decrypt_decimal(
                ctx,
                paillier,
                pk,
                sk,
                ct,
                ptr::null_mut(),
                &mut out_len as *mut _
            ),
            bicycl_status_t::BICYCL_ERR_BUFFER_TOO_SMALL
        );

        let mut out_buf = vec![0_u8; out_len];
        assert_eq!(
            bicycl_paillier_decrypt_decimal(
                ctx,
                paillier,
                pk,
                sk,
                ct,
                out_buf.as_mut_ptr().cast(),
                &mut out_len as *mut _
            ),
            bicycl_status_t::BICYCL_OK
        );
        let out = CStr::from_bytes_with_nul(&out_buf)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(out, "42");

        let mut jl: *mut bicycl_joye_libert_t = ptr::null_mut();
        assert_eq!(
            bicycl_joye_libert_new(ctx, 64, 8, &mut jl as *mut _),
            bicycl_status_t::BICYCL_OK
        );
        let mut jl_sk: *mut bicycl_joye_libert_sk_t = ptr::null_mut();
        let mut jl_pk: *mut bicycl_joye_libert_pk_t = ptr::null_mut();
        assert_eq!(
            bicycl_joye_libert_keygen(ctx, jl, rng, &mut jl_sk as *mut _, &mut jl_pk as *mut _),
            bicycl_status_t::BICYCL_OK
        );
        let mut jl_ct: *mut bicycl_joye_libert_ct_t = ptr::null_mut();
        let jl_msg = CString::new("7").unwrap();
        assert_eq!(
            bicycl_joye_libert_encrypt_decimal(
                ctx,
                jl,
                jl_pk,
                rng,
                jl_msg.as_ptr(),
                &mut jl_ct as *mut _
            ),
            bicycl_status_t::BICYCL_OK
        );
        let mut jl_out_len: usize = 0;
        assert_eq!(
            bicycl_joye_libert_decrypt_decimal(
                ctx,
                jl,
                jl_sk,
                jl_ct,
                ptr::null_mut(),
                &mut jl_out_len as *mut _
            ),
            bicycl_status_t::BICYCL_ERR_BUFFER_TOO_SMALL
        );
        let mut jl_out_buf = vec![0_u8; jl_out_len];
        assert_eq!(
            bicycl_joye_libert_decrypt_decimal(
                ctx,
                jl,
                jl_sk,
                jl_ct,
                jl_out_buf.as_mut_ptr().cast(),
                &mut jl_out_len as *mut _
            ),
            bicycl_status_t::BICYCL_OK
        );
        let jl_out = CStr::from_bytes_with_nul(&jl_out_buf)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(jl_out, "7");

        let mut cl: *mut bicycl_cl_hsmqk_t = ptr::null_mut();
        let q = CString::new("3").unwrap();
        let p = CString::new("5").unwrap();
        assert_eq!(
            bicycl_cl_hsmqk_new(ctx, q.as_ptr(), 1, p.as_ptr(), &mut cl as *mut _),
            bicycl_status_t::BICYCL_OK
        );
        let mut cl_sk: *mut bicycl_cl_hsmqk_sk_t = ptr::null_mut();
        let mut cl_pk: *mut bicycl_cl_hsmqk_pk_t = ptr::null_mut();
        assert_eq!(
            bicycl_cl_hsmqk_keygen(ctx, cl, rng, &mut cl_sk as *mut _, &mut cl_pk as *mut _),
            bicycl_status_t::BICYCL_OK
        );
        let mut cl_ct: *mut bicycl_cl_hsmqk_ct_t = ptr::null_mut();
        let cl_msg = CString::new("2").unwrap();
        assert_eq!(
            bicycl_cl_hsmqk_encrypt_decimal(
                ctx,
                cl,
                cl_pk,
                rng,
                cl_msg.as_ptr(),
                &mut cl_ct as *mut _
            ),
            bicycl_status_t::BICYCL_OK
        );
        let mut cl_out_len: usize = 0;
        assert_eq!(
            bicycl_cl_hsmqk_decrypt_decimal(
                ctx,
                cl,
                cl_sk,
                cl_ct,
                ptr::null_mut(),
                &mut cl_out_len as *mut _
            ),
            bicycl_status_t::BICYCL_ERR_BUFFER_TOO_SMALL
        );
        let mut cl_out_buf = vec![0_u8; cl_out_len];
        assert_eq!(
            bicycl_cl_hsmqk_decrypt_decimal(
                ctx,
                cl,
                cl_sk,
                cl_ct,
                cl_out_buf.as_mut_ptr().cast(),
                &mut cl_out_len as *mut _
            ),
            bicycl_status_t::BICYCL_OK
        );
        let cl_out = CStr::from_bytes_with_nul(&cl_out_buf)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(cl_out, "2");

        let mut cl_ct_add: *mut bicycl_cl_hsmqk_ct_t = ptr::null_mut();
        assert_eq!(
            bicycl_cl_hsmqk_add_ciphertexts(
                ctx,
                cl,
                cl_pk,
                rng,
                cl_ct,
                cl_ct,
                &mut cl_ct_add as *mut _
            ),
            bicycl_status_t::BICYCL_OK
        );
        let mut cl_add_len: usize = 0;
        assert_eq!(
            bicycl_cl_hsmqk_decrypt_decimal(
                ctx,
                cl,
                cl_sk,
                cl_ct_add,
                ptr::null_mut(),
                &mut cl_add_len as *mut _
            ),
            bicycl_status_t::BICYCL_ERR_BUFFER_TOO_SMALL
        );
        let mut cl_add_buf = vec![0_u8; cl_add_len];
        assert_eq!(
            bicycl_cl_hsmqk_decrypt_decimal(
                ctx,
                cl,
                cl_sk,
                cl_ct_add,
                cl_add_buf.as_mut_ptr().cast(),
                &mut cl_add_len as *mut _
            ),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(
            CStr::from_bytes_with_nul(&cl_add_buf)
                .unwrap()
                .to_str()
                .unwrap(),
            "1"
        );

        let mut cl_ct_scal: *mut bicycl_cl_hsmqk_ct_t = ptr::null_mut();
        let scalar_3 = CString::new("3").unwrap();
        assert_eq!(
            bicycl_cl_hsmqk_scal_ciphertext_decimal(
                ctx,
                cl,
                cl_pk,
                rng,
                cl_ct,
                scalar_3.as_ptr(),
                &mut cl_ct_scal as *mut _
            ),
            bicycl_status_t::BICYCL_OK
        );
        let mut cl_scal_len: usize = 0;
        assert_eq!(
            bicycl_cl_hsmqk_decrypt_decimal(
                ctx,
                cl,
                cl_sk,
                cl_ct_scal,
                ptr::null_mut(),
                &mut cl_scal_len as *mut _
            ),
            bicycl_status_t::BICYCL_ERR_BUFFER_TOO_SMALL
        );
        let mut cl_scal_buf = vec![0_u8; cl_scal_len];
        assert_eq!(
            bicycl_cl_hsmqk_decrypt_decimal(
                ctx,
                cl,
                cl_sk,
                cl_ct_scal,
                cl_scal_buf.as_mut_ptr().cast(),
                &mut cl_scal_len as *mut _
            ),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(
            CStr::from_bytes_with_nul(&cl_scal_buf)
                .unwrap()
                .to_str()
                .unwrap(),
            "0"
        );

        let mut cl_ct_addscal: *mut bicycl_cl_hsmqk_ct_t = ptr::null_mut();
        let scalar_2 = CString::new("2").unwrap();
        assert_eq!(
            bicycl_cl_hsmqk_addscal_ciphertexts_decimal(
                ctx,
                cl,
                cl_pk,
                rng,
                cl_ct,
                cl_ct,
                scalar_2.as_ptr(),
                &mut cl_ct_addscal as *mut _
            ),
            bicycl_status_t::BICYCL_OK
        );
        let mut cl_addscal_len: usize = 0;
        assert_eq!(
            bicycl_cl_hsmqk_decrypt_decimal(
                ctx,
                cl,
                cl_sk,
                cl_ct_addscal,
                ptr::null_mut(),
                &mut cl_addscal_len as *mut _
            ),
            bicycl_status_t::BICYCL_ERR_BUFFER_TOO_SMALL
        );
        let mut cl_addscal_buf = vec![0_u8; cl_addscal_len];
        assert_eq!(
            bicycl_cl_hsmqk_decrypt_decimal(
                ctx,
                cl,
                cl_sk,
                cl_ct_addscal,
                cl_addscal_buf.as_mut_ptr().cast(),
                &mut cl_addscal_len as *mut _
            ),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(
            CStr::from_bytes_with_nul(&cl_addscal_buf)
                .unwrap()
                .to_str()
                .unwrap(),
            "0"
        );

        let mut cl2: *mut bicycl_cl_hsm2k_t = ptr::null_mut();
        let n = CString::new("15").unwrap();
        assert_eq!(
            bicycl_cl_hsm2k_new(ctx, n.as_ptr(), 3, &mut cl2 as *mut _),
            bicycl_status_t::BICYCL_OK
        );
        let mut cl2_sk: *mut bicycl_cl_hsm2k_sk_t = ptr::null_mut();
        let mut cl2_pk: *mut bicycl_cl_hsm2k_pk_t = ptr::null_mut();
        assert_eq!(
            bicycl_cl_hsm2k_keygen(ctx, cl2, rng, &mut cl2_sk as *mut _, &mut cl2_pk as *mut _),
            bicycl_status_t::BICYCL_OK
        );
        let mut cl2_ct: *mut bicycl_cl_hsm2k_ct_t = ptr::null_mut();
        let cl2_msg = CString::new("5").unwrap();
        assert_eq!(
            bicycl_cl_hsm2k_encrypt_decimal(
                ctx,
                cl2,
                cl2_pk,
                rng,
                cl2_msg.as_ptr(),
                &mut cl2_ct as *mut _
            ),
            bicycl_status_t::BICYCL_OK
        );
        let mut cl2_len: usize = 0;
        assert_eq!(
            bicycl_cl_hsm2k_decrypt_decimal(
                ctx,
                cl2,
                cl2_sk,
                cl2_ct,
                ptr::null_mut(),
                &mut cl2_len as *mut _
            ),
            bicycl_status_t::BICYCL_ERR_BUFFER_TOO_SMALL
        );
        let mut cl2_buf = vec![0_u8; cl2_len];
        assert_eq!(
            bicycl_cl_hsm2k_decrypt_decimal(
                ctx,
                cl2,
                cl2_sk,
                cl2_ct,
                cl2_buf.as_mut_ptr().cast(),
                &mut cl2_len as *mut _
            ),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(
            CStr::from_bytes_with_nul(&cl2_buf)
                .unwrap()
                .to_str()
                .unwrap(),
            "5"
        );

        let mut cl2_add: *mut bicycl_cl_hsm2k_ct_t = ptr::null_mut();
        assert_eq!(
            bicycl_cl_hsm2k_add_ciphertexts(
                ctx,
                cl2,
                cl2_pk,
                rng,
                cl2_ct,
                cl2_ct,
                &mut cl2_add as *mut _
            ),
            bicycl_status_t::BICYCL_OK
        );
        let mut cl2_add_len: usize = 0;
        assert_eq!(
            bicycl_cl_hsm2k_decrypt_decimal(
                ctx,
                cl2,
                cl2_sk,
                cl2_add,
                ptr::null_mut(),
                &mut cl2_add_len as *mut _
            ),
            bicycl_status_t::BICYCL_ERR_BUFFER_TOO_SMALL
        );
        let mut cl2_add_buf = vec![0_u8; cl2_add_len];
        assert_eq!(
            bicycl_cl_hsm2k_decrypt_decimal(
                ctx,
                cl2,
                cl2_sk,
                cl2_add,
                cl2_add_buf.as_mut_ptr().cast(),
                &mut cl2_add_len as *mut _
            ),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(
            CStr::from_bytes_with_nul(&cl2_add_buf)
                .unwrap()
                .to_str()
                .unwrap(),
            "2"
        );

        let mut cl2_scal: *mut bicycl_cl_hsm2k_ct_t = ptr::null_mut();
        let scalar3 = CString::new("3").unwrap();
        assert_eq!(
            bicycl_cl_hsm2k_scal_ciphertext_decimal(
                ctx,
                cl2,
                cl2_pk,
                rng,
                cl2_ct,
                scalar3.as_ptr(),
                &mut cl2_scal as *mut _
            ),
            bicycl_status_t::BICYCL_OK
        );
        let mut cl2_scal_len: usize = 0;
        assert_eq!(
            bicycl_cl_hsm2k_decrypt_decimal(
                ctx,
                cl2,
                cl2_sk,
                cl2_scal,
                ptr::null_mut(),
                &mut cl2_scal_len as *mut _
            ),
            bicycl_status_t::BICYCL_ERR_BUFFER_TOO_SMALL
        );
        let mut cl2_scal_buf = vec![0_u8; cl2_scal_len];
        assert_eq!(
            bicycl_cl_hsm2k_decrypt_decimal(
                ctx,
                cl2,
                cl2_sk,
                cl2_scal,
                cl2_scal_buf.as_mut_ptr().cast(),
                &mut cl2_scal_len as *mut _
            ),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(
            CStr::from_bytes_with_nul(&cl2_scal_buf)
                .unwrap()
                .to_str()
                .unwrap(),
            "7"
        );

        let mut cl2_addscal: *mut bicycl_cl_hsm2k_ct_t = ptr::null_mut();
        let scalar2 = CString::new("2").unwrap();
        assert_eq!(
            bicycl_cl_hsm2k_addscal_ciphertexts_decimal(
                ctx,
                cl2,
                cl2_pk,
                rng,
                cl2_ct,
                cl2_ct,
                scalar2.as_ptr(),
                &mut cl2_addscal as *mut _
            ),
            bicycl_status_t::BICYCL_OK
        );
        let mut cl2_addscal_len: usize = 0;
        assert_eq!(
            bicycl_cl_hsm2k_decrypt_decimal(
                ctx,
                cl2,
                cl2_sk,
                cl2_addscal,
                ptr::null_mut(),
                &mut cl2_addscal_len as *mut _
            ),
            bicycl_status_t::BICYCL_ERR_BUFFER_TOO_SMALL
        );
        let mut cl2_addscal_buf = vec![0_u8; cl2_addscal_len];
        assert_eq!(
            bicycl_cl_hsm2k_decrypt_decimal(
                ctx,
                cl2,
                cl2_sk,
                cl2_addscal,
                cl2_addscal_buf.as_mut_ptr().cast(),
                &mut cl2_addscal_len as *mut _
            ),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(
            CStr::from_bytes_with_nul(&cl2_addscal_buf)
                .unwrap()
                .to_str()
                .unwrap(),
            "7"
        );

        let mut ecdsa: *mut bicycl_ecdsa_t = ptr::null_mut();
        assert_eq!(
            bicycl_ecdsa_new(ctx, 112, &mut ecdsa as *mut _),
            bicycl_status_t::BICYCL_OK
        );
        let mut ecdsa_sk: *mut bicycl_ecdsa_sk_t = ptr::null_mut();
        let mut ecdsa_pk: *mut bicycl_ecdsa_pk_t = ptr::null_mut();
        assert_eq!(
            bicycl_ecdsa_keygen(
                ctx,
                ecdsa,
                rng,
                &mut ecdsa_sk as *mut _,
                &mut ecdsa_pk as *mut _
            ),
            bicycl_status_t::BICYCL_OK
        );
        let msg_ok = b"abc";
        let mut sig: *mut bicycl_ecdsa_sig_t = ptr::null_mut();
        assert_eq!(
            bicycl_ecdsa_sign_message(
                ctx,
                ecdsa,
                rng,
                ecdsa_sk,
                msg_ok.as_ptr(),
                msg_ok.len(),
                &mut sig as *mut _
            ),
            bicycl_status_t::BICYCL_OK
        );
        let mut valid: i32 = 0;
        assert_eq!(
            bicycl_ecdsa_verify_message(
                ctx,
                ecdsa,
                ecdsa_pk,
                msg_ok.as_ptr(),
                msg_ok.len(),
                sig,
                &mut valid as *mut _
            ),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(valid, 1);
        let msg_bad = b"abd";
        assert_eq!(
            bicycl_ecdsa_verify_message(
                ctx,
                ecdsa,
                ecdsa_pk,
                msg_bad.as_ptr(),
                msg_bad.len(),
                sig,
                &mut valid as *mut _
            ),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(valid, 0);

        let mut rs_len: usize = 0;
        assert_eq!(
            bicycl_ecdsa_sig_r_decimal(ctx, sig, ptr::null_mut(), &mut rs_len as *mut _),
            bicycl_status_t::BICYCL_ERR_BUFFER_TOO_SMALL
        );
        let mut r_buf = vec![0_u8; rs_len];
        assert_eq!(
            bicycl_ecdsa_sig_r_decimal(ctx, sig, r_buf.as_mut_ptr().cast(), &mut rs_len as *mut _),
            bicycl_status_t::BICYCL_OK
        );
        assert!(!CStr::from_bytes_with_nul(&r_buf)
            .unwrap()
            .to_str()
            .unwrap()
            .is_empty());
        rs_len = 0;
        assert_eq!(
            bicycl_ecdsa_sig_s_decimal(ctx, sig, ptr::null_mut(), &mut rs_len as *mut _),
            bicycl_status_t::BICYCL_ERR_BUFFER_TOO_SMALL
        );
        let mut s_buf = vec![0_u8; rs_len];
        assert_eq!(
            bicycl_ecdsa_sig_s_decimal(ctx, sig, s_buf.as_mut_ptr().cast(), &mut rs_len as *mut _),
            bicycl_status_t::BICYCL_OK
        );
        assert!(!CStr::from_bytes_with_nul(&s_buf)
            .unwrap()
            .to_str()
            .unwrap()
            .is_empty());

        let mut two_party_valid: i32 = 0;
        assert_eq!(
            bicycl_two_party_ecdsa_run_demo(
                ctx,
                rng,
                112,
                msg_ok.as_ptr(),
                msg_ok.len(),
                &mut two_party_valid as *mut _
            ),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(two_party_valid, 1);

        let mut tp_session: *mut bicycl_two_party_ecdsa_session_t = ptr::null_mut();
        assert_eq!(
            bicycl_two_party_ecdsa_session_new(ctx, rng, 112, &mut tp_session as *mut _),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(
            bicycl_two_party_ecdsa_keygen_round1(ctx, tp_session, rng),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(
            bicycl_two_party_ecdsa_keygen_round2(ctx, tp_session, rng),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(
            bicycl_two_party_ecdsa_keygen_round3(ctx, tp_session, rng),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(
            bicycl_two_party_ecdsa_keygen_round4(ctx, tp_session),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(
            bicycl_two_party_ecdsa_sign_round1(ctx, tp_session, rng, msg_ok.as_ptr(), msg_ok.len()),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(
            bicycl_two_party_ecdsa_sign_round2(ctx, tp_session, rng),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(
            bicycl_two_party_ecdsa_sign_round3(ctx, tp_session),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(
            bicycl_two_party_ecdsa_sign_round4(ctx, tp_session, rng),
            bicycl_status_t::BICYCL_OK
        );
        let mut tp_state_valid: i32 = 0;
        assert_eq!(
            bicycl_two_party_ecdsa_sign_finalize(ctx, tp_session, &mut tp_state_valid as *mut _),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(tp_state_valid, 1);
        bicycl_two_party_ecdsa_session_free(tp_session);

        let mut cl_dlog_valid: i32 = 0;
        assert_eq!(
            bicycl_cl_dlog_proof_run_demo(ctx, rng, 112, &mut cl_dlog_valid as *mut _),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(cl_dlog_valid, 1);

        let mut threshold_ecdsa_valid: i32 = 0;
        assert_eq!(
            bicycl_threshold_ecdsa_run_demo(
                ctx,
                rng,
                112,
                msg_ok.as_ptr(),
                msg_ok.len(),
                &mut threshold_ecdsa_valid as *mut _
            ),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(threshold_ecdsa_valid, 1);

        let mut dlog_session: *mut bicycl_cl_dlog_session_t = ptr::null_mut();
        assert_eq!(
            bicycl_cl_dlog_session_new(ctx, rng, 112, &mut dlog_session as *mut _),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(
            bicycl_cl_dlog_session_prepare_statement(ctx, dlog_session, rng),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(
            bicycl_cl_dlog_session_prove_round(ctx, dlog_session, rng),
            bicycl_status_t::BICYCL_OK
        );
        let mut dlog_round_valid: i32 = 0;
        assert_eq!(
            bicycl_cl_dlog_session_verify_round(ctx, dlog_session, &mut dlog_round_valid as *mut _),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(dlog_round_valid, 1);

        let mut stmt_msg: *mut bicycl_cl_dlog_message_t = ptr::null_mut();
        let mut proof_msg: *mut bicycl_cl_dlog_message_t = ptr::null_mut();
        assert_eq!(
            bicycl_cl_dlog_message_new(&mut stmt_msg as *mut _),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(
            bicycl_cl_dlog_message_new(&mut proof_msg as *mut _),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(
            bicycl_cl_dlog_session_export_statement(ctx, dlog_session, stmt_msg),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(
            bicycl_cl_dlog_session_export_proof(ctx, dlog_session, proof_msg),
            bicycl_status_t::BICYCL_OK
        );
        let mut stmt_len: usize = 0;
        assert_eq!(
            bicycl_cl_dlog_message_export_bytes(ctx, stmt_msg, ptr::null_mut(), &mut stmt_len),
            bicycl_status_t::BICYCL_ERR_BUFFER_TOO_SMALL
        );
        let mut stmt_buf = vec![0_u8; stmt_len];
        assert_eq!(
            bicycl_cl_dlog_message_export_bytes(
                ctx,
                stmt_msg,
                stmt_buf.as_mut_ptr(),
                &mut stmt_len as *mut _
            ),
            bicycl_status_t::BICYCL_OK
        );
        let mut proof_len: usize = 0;
        assert_eq!(
            bicycl_cl_dlog_message_export_bytes(ctx, proof_msg, ptr::null_mut(), &mut proof_len),
            bicycl_status_t::BICYCL_ERR_BUFFER_TOO_SMALL
        );
        let mut proof_buf = vec![0_u8; proof_len];
        assert_eq!(
            bicycl_cl_dlog_message_export_bytes(
                ctx,
                proof_msg,
                proof_buf.as_mut_ptr(),
                &mut proof_len as *mut _
            ),
            bicycl_status_t::BICYCL_OK
        );

        let mut dlog_verifier: *mut bicycl_cl_dlog_session_t = ptr::null_mut();
        let mut stmt_rx: *mut bicycl_cl_dlog_message_t = ptr::null_mut();
        let mut proof_rx: *mut bicycl_cl_dlog_message_t = ptr::null_mut();
        assert_eq!(
            bicycl_cl_dlog_session_new(ctx, rng, 112, &mut dlog_verifier as *mut _),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(
            bicycl_cl_dlog_message_new(&mut stmt_rx as *mut _),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(
            bicycl_cl_dlog_message_new(&mut proof_rx as *mut _),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(
            bicycl_cl_dlog_message_import_bytes(ctx, stmt_rx, stmt_buf.as_ptr(), stmt_buf.len()),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(
            bicycl_cl_dlog_message_import_bytes(ctx, proof_rx, proof_buf.as_ptr(), proof_buf.len()),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(
            bicycl_cl_dlog_session_import_statement(ctx, dlog_verifier, stmt_rx),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(
            bicycl_cl_dlog_session_import_proof(ctx, dlog_verifier, proof_rx),
            bicycl_status_t::BICYCL_OK
        );
        let mut dlog_net_valid: i32 = 0;
        assert_eq!(
            bicycl_cl_dlog_session_verify_round(ctx, dlog_verifier, &mut dlog_net_valid as *mut _),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(dlog_net_valid, 1);

        bicycl_cl_dlog_message_free(stmt_rx);
        bicycl_cl_dlog_message_free(proof_rx);
        bicycl_cl_dlog_session_free(dlog_verifier);
        bicycl_cl_dlog_message_free(stmt_msg);
        bicycl_cl_dlog_message_free(proof_msg);
        bicycl_cl_dlog_session_free(dlog_session);

        let mut th_session: *mut bicycl_threshold_ecdsa_session_t = ptr::null_mut();
        assert_eq!(
            bicycl_threshold_ecdsa_session_new(ctx, rng, 112, 2, 1, &mut th_session as *mut _),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(
            bicycl_threshold_ecdsa_keygen_round1(ctx, th_session, rng),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(
            bicycl_threshold_ecdsa_keygen_round2(ctx, th_session, rng),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(
            bicycl_threshold_ecdsa_keygen_finalize(ctx, th_session),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(
            bicycl_threshold_ecdsa_sign_round1(ctx, th_session, rng, msg_ok.as_ptr(), msg_ok.len()),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(
            bicycl_threshold_ecdsa_sign_round2(ctx, th_session, rng),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(
            bicycl_threshold_ecdsa_sign_round3(ctx, th_session),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(
            bicycl_threshold_ecdsa_sign_round4(ctx, th_session),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(
            bicycl_threshold_ecdsa_sign_round5(ctx, th_session, rng),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(
            bicycl_threshold_ecdsa_sign_round6(ctx, th_session, rng),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(
            bicycl_threshold_ecdsa_sign_round7(ctx, th_session, rng),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(
            bicycl_threshold_ecdsa_sign_round8(ctx, th_session),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(
            bicycl_threshold_ecdsa_sign_finalize(ctx, th_session),
            bicycl_status_t::BICYCL_OK
        );
        let mut th_round_valid: i32 = 0;
        assert_eq!(
            bicycl_threshold_ecdsa_signature_valid(ctx, th_session, &mut th_round_valid as *mut _),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(th_round_valid, 1);
        bicycl_threshold_ecdsa_session_free(th_session);

        let mut thr_len: usize = 0;
        assert_eq!(
            bicycl_cl_threshold_run_demo(ctx, rng, ptr::null_mut(), &mut thr_len as *mut _),
            bicycl_status_t::BICYCL_ERR_BUFFER_TOO_SMALL
        );
        let mut thr_buf = vec![0_u8; thr_len];
        assert_eq!(
            bicycl_cl_threshold_run_demo(
                ctx,
                rng,
                thr_buf.as_mut_ptr().cast(),
                &mut thr_len as *mut _
            ),
            bicycl_status_t::BICYCL_OK
        );
        assert_eq!(
            CStr::from_bytes_with_nul(&thr_buf)
                .unwrap()
                .to_str()
                .unwrap(),
            "2"
        );

        bicycl_joye_libert_ct_free(jl_ct);
        bicycl_joye_libert_pk_free(jl_pk);
        bicycl_joye_libert_sk_free(jl_sk);
        bicycl_joye_libert_free(jl);
        bicycl_cl_hsmqk_ct_free(cl_ct_addscal);
        bicycl_cl_hsmqk_ct_free(cl_ct_scal);
        bicycl_cl_hsmqk_ct_free(cl_ct_add);
        bicycl_cl_hsmqk_ct_free(cl_ct);
        bicycl_cl_hsm2k_ct_free(cl2_addscal);
        bicycl_cl_hsm2k_ct_free(cl2_scal);
        bicycl_cl_hsm2k_ct_free(cl2_add);
        bicycl_cl_hsm2k_ct_free(cl2_ct);
        bicycl_cl_hsm2k_pk_free(cl2_pk);
        bicycl_cl_hsm2k_sk_free(cl2_sk);
        bicycl_cl_hsm2k_free(cl2);
        bicycl_ecdsa_sig_free(sig);
        bicycl_ecdsa_pk_free(ecdsa_pk);
        bicycl_ecdsa_sk_free(ecdsa_sk);
        bicycl_ecdsa_free(ecdsa);
        bicycl_cl_hsmqk_pk_free(cl_pk);
        bicycl_cl_hsmqk_sk_free(cl_sk);
        bicycl_cl_hsmqk_free(cl);

        bicycl_paillier_ct_free(ct);
        bicycl_paillier_pk_free(pk);
        bicycl_paillier_sk_free(sk);
        bicycl_paillier_free(paillier);
        bicycl_qfi_free(one);
        bicycl_classgroup_free(cg);
        bicycl_randgen_free(rng);

        let mut buf = [1_u8, 2, 3, 4];
        bicycl_zeroize(buf.as_mut_ptr().cast(), buf.len());
        assert_eq!(buf, [0_u8; 4]);

        bicycl_context_free(ctx);
    }
}
