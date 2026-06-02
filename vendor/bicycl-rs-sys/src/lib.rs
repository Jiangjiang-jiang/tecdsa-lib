#![deny(unsafe_op_in_unsafe_fn)]

use core::ffi::{c_char, c_int, c_void};

#[allow(non_camel_case_types)]
#[non_exhaustive]
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum bicycl_status_t {
    BICYCL_OK = 0,
    BICYCL_ERR_NULL_PTR = 1,
    BICYCL_ERR_INVALID_ARGUMENT = 2,
    BICYCL_ERR_ALLOCATION_FAILED = 3,
    BICYCL_ERR_INTERNAL = 4,
    BICYCL_ERR_BUFFER_TOO_SMALL = 5,
    BICYCL_ERR_PARSE = 6,
    BICYCL_ERR_INVALID_STATE = 7,
    BICYCL_ERR_VERIFY_FAILED = 8,
    BICYCL_ERR_PROTOCOL_ABORT = 9,
    BICYCL_ERR_CORE = 90,
    BICYCL_ERR_PAILLIER = 100,
    BICYCL_ERR_JOYE_LIBERT = 101,
    BICYCL_ERR_CL_HSMQK = 102,
    BICYCL_ERR_CL_HSM2K = 103,
    BICYCL_ERR_ECDSA = 104,
    BICYCL_ERR_TWO_PARTY_ECDSA = 105,
    BICYCL_ERR_CL_THRESHOLD = 106,
    BICYCL_ERR_CL_DLOG = 107,
    BICYCL_ERR_THRESHOLD_ECDSA = 108,
}

#[repr(C)]
pub struct bicycl_context_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct bicycl_randgen_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct bicycl_classgroup_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct bicycl_qfi_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct bicycl_paillier_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct bicycl_paillier_sk_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct bicycl_paillier_pk_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct bicycl_paillier_ct_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct bicycl_joye_libert_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct bicycl_joye_libert_sk_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct bicycl_joye_libert_pk_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct bicycl_joye_libert_ct_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct bicycl_cl_hsmqk_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct bicycl_cl_hsmqk_sk_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct bicycl_cl_hsmqk_pk_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct bicycl_cl_hsmqk_ct_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct bicycl_cl_hsm2k_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct bicycl_cl_hsm2k_sk_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct bicycl_cl_hsm2k_pk_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct bicycl_cl_hsm2k_ct_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct bicycl_ecdsa_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct bicycl_ecdsa_sk_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct bicycl_ecdsa_pk_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct bicycl_ecdsa_sig_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct bicycl_two_party_ecdsa_session_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct bicycl_cl_dlog_session_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct bicycl_threshold_ecdsa_session_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct bicycl_cl_dlog_message_t {
    _private: [u8; 0],
}

pub const BICYCL_CAPI_VERSION: u32 = 0x0001_0100;

unsafe extern "C" {
    pub fn bicycl_get_abi_version() -> u32;
    pub fn bicycl_get_version() -> *const c_char;
    pub fn bicycl_status_message(status: bicycl_status_t) -> *const c_char;

    pub fn bicycl_context_new(out_ctx: *mut *mut bicycl_context_t) -> bicycl_status_t;
    pub fn bicycl_context_free(ctx: *mut bicycl_context_t);
    pub fn bicycl_context_last_error(ctx: *const bicycl_context_t) -> *const c_char;
    pub fn bicycl_context_clear_error(ctx: *mut bicycl_context_t);

    pub fn bicycl_zeroize(ptr: *mut c_void, len: usize);

    pub fn bicycl_randgen_new_from_seed_decimal(
        ctx: *mut bicycl_context_t,
        seed_decimal: *const c_char,
        out_randgen: *mut *mut bicycl_randgen_t,
    ) -> bicycl_status_t;
    pub fn bicycl_randgen_free(randgen: *mut bicycl_randgen_t);

    pub fn bicycl_classgroup_new_from_discriminant_decimal(
        ctx: *mut bicycl_context_t,
        discriminant_decimal: *const c_char,
        out_classgroup: *mut *mut bicycl_classgroup_t,
    ) -> bicycl_status_t;
    pub fn bicycl_classgroup_free(classgroup: *mut bicycl_classgroup_t);

    pub fn bicycl_classgroup_one(
        ctx: *mut bicycl_context_t,
        classgroup: *const bicycl_classgroup_t,
        out_qfi: *mut *mut bicycl_qfi_t,
    ) -> bicycl_status_t;

    pub fn bicycl_classgroup_nudupl(
        ctx: *mut bicycl_context_t,
        classgroup: *const bicycl_classgroup_t,
        input: *const bicycl_qfi_t,
        out_qfi: *mut *mut bicycl_qfi_t,
    ) -> bicycl_status_t;

    pub fn bicycl_qfi_free(qfi: *mut bicycl_qfi_t);
    pub fn bicycl_qfi_is_one(
        ctx: *mut bicycl_context_t,
        qfi: *const bicycl_qfi_t,
        out_is_one: *mut c_int,
    ) -> bicycl_status_t;
    pub fn bicycl_qfi_discriminant_decimal(
        ctx: *mut bicycl_context_t,
        qfi: *const bicycl_qfi_t,
        out_buf: *mut c_char,
        inout_len: *mut usize,
    ) -> bicycl_status_t;

    // ── QFI additional ──────────────────────────────────────────────────────
    pub fn bicycl_qfi_new_from_abc_decimal(
        ctx: *mut bicycl_context_t,
        a: *const c_char,
        b: *const c_char,
        c: *const c_char,
        out: *mut *mut bicycl_qfi_t,
    ) -> bicycl_status_t;

    pub fn bicycl_qfi_a_decimal(
        ctx: *mut bicycl_context_t,
        qfi: *const bicycl_qfi_t,
        out_buf: *mut c_char,
        inout_len: *mut usize,
    ) -> bicycl_status_t;

    pub fn bicycl_qfi_b_decimal(
        ctx: *mut bicycl_context_t,
        qfi: *const bicycl_qfi_t,
        out_buf: *mut c_char,
        inout_len: *mut usize,
    ) -> bicycl_status_t;

    pub fn bicycl_qfi_c_decimal(
        ctx: *mut bicycl_context_t,
        qfi: *const bicycl_qfi_t,
        out_buf: *mut c_char,
        inout_len: *mut usize,
    ) -> bicycl_status_t;

    pub fn bicycl_qfi_equal(
        ctx: *mut bicycl_context_t,
        a: *const bicycl_qfi_t,
        b: *const bicycl_qfi_t,
        out: *mut c_int,
    ) -> bicycl_status_t;

    pub fn bicycl_qfi_neg(
        ctx: *mut bicycl_context_t,
        qfi: *const bicycl_qfi_t,
        out: *mut *mut bicycl_qfi_t,
    ) -> bicycl_status_t;

    pub fn bicycl_qfi_lift_decimal(
        ctx: *mut bicycl_context_t,
        qfi: *mut bicycl_qfi_t,
        conductor_decimal: *const c_char,
    ) -> bicycl_status_t;

    pub fn bicycl_qfi_to_maximal_order_decimal(
        ctx: *mut bicycl_context_t,
        qfi: *mut bicycl_qfi_t,
        conductor_decimal: *const c_char,
        delta_k_decimal: *const c_char,
        to_neg: c_int,
    ) -> bicycl_status_t;

    // ── ClassGroup additional ────────────────────────────────────────────────
    pub fn bicycl_classgroup_discriminant_decimal(
        ctx: *mut bicycl_context_t,
        cg: *const bicycl_classgroup_t,
        out_buf: *mut c_char,
        inout_len: *mut usize,
    ) -> bicycl_status_t;

    pub fn bicycl_classgroup_nucomp(
        ctx: *mut bicycl_context_t,
        cg: *const bicycl_classgroup_t,
        f1: *const bicycl_qfi_t,
        f2: *const bicycl_qfi_t,
        out: *mut *mut bicycl_qfi_t,
    ) -> bicycl_status_t;

    pub fn bicycl_classgroup_nucompinv(
        ctx: *mut bicycl_context_t,
        cg: *const bicycl_classgroup_t,
        f1: *const bicycl_qfi_t,
        f2: *const bicycl_qfi_t,
        out: *mut *mut bicycl_qfi_t,
    ) -> bicycl_status_t;

    pub fn bicycl_classgroup_nupow_decimal(
        ctx: *mut bicycl_context_t,
        cg: *const bicycl_classgroup_t,
        f: *const bicycl_qfi_t,
        n_decimal: *const c_char,
        out: *mut *mut bicycl_qfi_t,
    ) -> bicycl_status_t;

    pub fn bicycl_classgroup_nupow2_decimal(
        ctx: *mut bicycl_context_t,
        cg: *const bicycl_classgroup_t,
        f0: *const bicycl_qfi_t,
        n0_decimal: *const c_char,
        f1: *const bicycl_qfi_t,
        n1_decimal: *const c_char,
        out: *mut *mut bicycl_qfi_t,
    ) -> bicycl_status_t;

    pub fn bicycl_classgroup_primeform_decimal(
        ctx: *mut bicycl_context_t,
        cg: *const bicycl_classgroup_t,
        p_decimal: *const c_char,
        out: *mut *mut bicycl_qfi_t,
    ) -> bicycl_status_t;

    // ── CL_HSMqk parameters ──────────────────────────────────────────────────
    pub fn bicycl_cl_hsmqk_q_decimal(
        ctx: *mut bicycl_context_t,
        cl: *const bicycl_cl_hsmqk_t,
        out_buf: *mut c_char,
        inout_len: *mut usize,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsmqk_p_decimal(
        ctx: *mut bicycl_context_t,
        cl: *const bicycl_cl_hsmqk_t,
        out_buf: *mut c_char,
        inout_len: *mut usize,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsmqk_M_decimal(
        ctx: *mut bicycl_context_t,
        cl: *const bicycl_cl_hsmqk_t,
        out_buf: *mut c_char,
        inout_len: *mut usize,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsmqk_DeltaK_decimal(
        ctx: *mut bicycl_context_t,
        cl: *const bicycl_cl_hsmqk_t,
        out_buf: *mut c_char,
        inout_len: *mut usize,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsmqk_Delta_decimal(
        ctx: *mut bicycl_context_t,
        cl: *const bicycl_cl_hsmqk_t,
        out_buf: *mut c_char,
        inout_len: *mut usize,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsmqk_secretkey_bound_decimal(
        ctx: *mut bicycl_context_t,
        cl: *const bicycl_cl_hsmqk_t,
        out_buf: *mut c_char,
        inout_len: *mut usize,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsmqk_Cl_DeltaK(
        ctx: *mut bicycl_context_t,
        cl: *const bicycl_cl_hsmqk_t,
        out: *mut *mut bicycl_classgroup_t,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsmqk_Cl_Delta(
        ctx: *mut bicycl_context_t,
        cl: *const bicycl_cl_hsmqk_t,
        out: *mut *mut bicycl_classgroup_t,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsmqk_h(
        ctx: *mut bicycl_context_t,
        cl: *const bicycl_cl_hsmqk_t,
        out: *mut *mut bicycl_qfi_t,
    ) -> bicycl_status_t;

    // ── CL_HSMqk subgroup operations ─────────────────────────────────────────
    pub fn bicycl_cl_hsmqk_power_of_h_decimal(
        ctx: *mut bicycl_context_t,
        cl: *const bicycl_cl_hsmqk_t,
        e_decimal: *const c_char,
        out: *mut *mut bicycl_qfi_t,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsmqk_power_of_f_decimal(
        ctx: *mut bicycl_context_t,
        cl: *const bicycl_cl_hsmqk_t,
        m_decimal: *const c_char,
        out: *mut *mut bicycl_qfi_t,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsmqk_dlog_in_F(
        ctx: *mut bicycl_context_t,
        cl: *const bicycl_cl_hsmqk_t,
        fm: *const bicycl_qfi_t,
        out_buf: *mut c_char,
        inout_len: *mut usize,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsmqk_from_Cl_DeltaK_to_Cl_Delta(
        ctx: *mut bicycl_context_t,
        cl: *const bicycl_cl_hsmqk_t,
        f: *mut bicycl_qfi_t,
    ) -> bicycl_status_t;

    // ── CL_HSMqk key/ciphertext access ───────────────────────────────────────
    pub fn bicycl_cl_hsmqk_pk_elt(
        ctx: *mut bicycl_context_t,
        pk: *const bicycl_cl_hsmqk_pk_t,
        out: *mut *mut bicycl_qfi_t,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsmqk_pk_new_from_qfi(
        ctx: *mut bicycl_context_t,
        cl: *const bicycl_cl_hsmqk_t,
        qfi: *const bicycl_qfi_t,
        out: *mut *mut bicycl_cl_hsmqk_pk_t,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsmqk_ct_c1(
        ctx: *mut bicycl_context_t,
        ct: *const bicycl_cl_hsmqk_ct_t,
        out: *mut *mut bicycl_qfi_t,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsmqk_ct_c2(
        ctx: *mut bicycl_context_t,
        ct: *const bicycl_cl_hsmqk_ct_t,
        out: *mut *mut bicycl_qfi_t,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsmqk_ct_new_from_c1c2(
        ctx: *mut bicycl_context_t,
        c1: *const bicycl_qfi_t,
        c2: *const bicycl_qfi_t,
        out: *mut *mut bicycl_cl_hsmqk_ct_t,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsmqk_sk_decimal(
        ctx: *mut bicycl_context_t,
        sk: *const bicycl_cl_hsmqk_sk_t,
        out_buf: *mut c_char,
        inout_len: *mut usize,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsmqk_sk_new_from_decimal(
        ctx: *mut bicycl_context_t,
        cl: *const bicycl_cl_hsmqk_t,
        sk_decimal: *const c_char,
        out: *mut *mut bicycl_cl_hsmqk_sk_t,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsmqk_encrypt_decimal_with_r(
        ctx: *mut bicycl_context_t,
        cl: *const bicycl_cl_hsmqk_t,
        pk: *const bicycl_cl_hsmqk_pk_t,
        message_decimal: *const c_char,
        r_decimal: *const c_char,
        out_ct: *mut *mut bicycl_cl_hsmqk_ct_t,
    ) -> bicycl_status_t;

    // ── CL_HSM2k parameters ──────────────────────────────────────────────────
    pub fn bicycl_cl_hsm2k_N_decimal(
        ctx: *mut bicycl_context_t,
        cl: *const bicycl_cl_hsm2k_t,
        out_buf: *mut c_char,
        inout_len: *mut usize,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsm2k_M_decimal(
        ctx: *mut bicycl_context_t,
        cl: *const bicycl_cl_hsm2k_t,
        out_buf: *mut c_char,
        inout_len: *mut usize,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsm2k_DeltaK_decimal(
        ctx: *mut bicycl_context_t,
        cl: *const bicycl_cl_hsm2k_t,
        out_buf: *mut c_char,
        inout_len: *mut usize,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsm2k_Delta_decimal(
        ctx: *mut bicycl_context_t,
        cl: *const bicycl_cl_hsm2k_t,
        out_buf: *mut c_char,
        inout_len: *mut usize,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsm2k_secretkey_bound_decimal(
        ctx: *mut bicycl_context_t,
        cl: *const bicycl_cl_hsm2k_t,
        out_buf: *mut c_char,
        inout_len: *mut usize,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsm2k_Cl_DeltaK(
        ctx: *mut bicycl_context_t,
        cl: *const bicycl_cl_hsm2k_t,
        out: *mut *mut bicycl_classgroup_t,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsm2k_Cl_Delta(
        ctx: *mut bicycl_context_t,
        cl: *const bicycl_cl_hsm2k_t,
        out: *mut *mut bicycl_classgroup_t,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsm2k_h(
        ctx: *mut bicycl_context_t,
        cl: *const bicycl_cl_hsm2k_t,
        out: *mut *mut bicycl_qfi_t,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsm2k_power_of_h_decimal(
        ctx: *mut bicycl_context_t,
        cl: *const bicycl_cl_hsm2k_t,
        e_decimal: *const c_char,
        out: *mut *mut bicycl_qfi_t,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsm2k_power_of_f_decimal(
        ctx: *mut bicycl_context_t,
        cl: *const bicycl_cl_hsm2k_t,
        m_decimal: *const c_char,
        out: *mut *mut bicycl_qfi_t,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsm2k_dlog_in_F(
        ctx: *mut bicycl_context_t,
        cl: *const bicycl_cl_hsm2k_t,
        fm: *const bicycl_qfi_t,
        out_buf: *mut c_char,
        inout_len: *mut usize,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsm2k_from_Cl_DeltaK_to_Cl_Delta(
        ctx: *mut bicycl_context_t,
        cl: *const bicycl_cl_hsm2k_t,
        f: *mut bicycl_qfi_t,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsm2k_pk_elt(
        ctx: *mut bicycl_context_t,
        pk: *const bicycl_cl_hsm2k_pk_t,
        out: *mut *mut bicycl_qfi_t,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsm2k_pk_new_from_qfi(
        ctx: *mut bicycl_context_t,
        cl: *const bicycl_cl_hsm2k_t,
        qfi: *const bicycl_qfi_t,
        out: *mut *mut bicycl_cl_hsm2k_pk_t,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsm2k_ct_c1(
        ctx: *mut bicycl_context_t,
        ct: *const bicycl_cl_hsm2k_ct_t,
        out: *mut *mut bicycl_qfi_t,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsm2k_ct_c2(
        ctx: *mut bicycl_context_t,
        ct: *const bicycl_cl_hsm2k_ct_t,
        out: *mut *mut bicycl_qfi_t,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsm2k_ct_new_from_c1c2(
        ctx: *mut bicycl_context_t,
        c1: *const bicycl_qfi_t,
        c2: *const bicycl_qfi_t,
        out: *mut *mut bicycl_cl_hsm2k_ct_t,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsm2k_sk_decimal(
        ctx: *mut bicycl_context_t,
        sk: *const bicycl_cl_hsm2k_sk_t,
        out_buf: *mut c_char,
        inout_len: *mut usize,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsm2k_sk_new_from_decimal(
        ctx: *mut bicycl_context_t,
        cl: *const bicycl_cl_hsm2k_t,
        sk_decimal: *const c_char,
        out: *mut *mut bicycl_cl_hsm2k_sk_t,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsm2k_encrypt_decimal_with_r(
        ctx: *mut bicycl_context_t,
        cl: *const bicycl_cl_hsm2k_t,
        pk: *const bicycl_cl_hsm2k_pk_t,
        message_decimal: *const c_char,
        r_decimal: *const c_char,
        out_ct: *mut *mut bicycl_cl_hsm2k_ct_t,
    ) -> bicycl_status_t;

    pub fn bicycl_paillier_new(
        ctx: *mut bicycl_context_t,
        modulus_bits: u32,
        out_paillier: *mut *mut bicycl_paillier_t,
    ) -> bicycl_status_t;
    pub fn bicycl_paillier_free(paillier: *mut bicycl_paillier_t);

    pub fn bicycl_paillier_keygen(
        ctx: *mut bicycl_context_t,
        paillier: *const bicycl_paillier_t,
        randgen: *mut bicycl_randgen_t,
        out_sk: *mut *mut bicycl_paillier_sk_t,
        out_pk: *mut *mut bicycl_paillier_pk_t,
    ) -> bicycl_status_t;

    pub fn bicycl_paillier_sk_free(sk: *mut bicycl_paillier_sk_t);
    pub fn bicycl_paillier_pk_free(pk: *mut bicycl_paillier_pk_t);
    pub fn bicycl_paillier_ct_free(ct: *mut bicycl_paillier_ct_t);

    pub fn bicycl_paillier_encrypt_decimal(
        ctx: *mut bicycl_context_t,
        paillier: *const bicycl_paillier_t,
        pk: *const bicycl_paillier_pk_t,
        randgen: *mut bicycl_randgen_t,
        message_decimal: *const c_char,
        out_ct: *mut *mut bicycl_paillier_ct_t,
    ) -> bicycl_status_t;

    pub fn bicycl_paillier_decrypt_decimal(
        ctx: *mut bicycl_context_t,
        paillier: *const bicycl_paillier_t,
        pk: *const bicycl_paillier_pk_t,
        sk: *const bicycl_paillier_sk_t,
        ct: *const bicycl_paillier_ct_t,
        out_buf: *mut c_char,
        inout_len: *mut usize,
    ) -> bicycl_status_t;

    pub fn bicycl_joye_libert_new(
        ctx: *mut bicycl_context_t,
        modulus_bits: u32,
        k: u32,
        out_joye_libert: *mut *mut bicycl_joye_libert_t,
    ) -> bicycl_status_t;
    pub fn bicycl_joye_libert_free(joye_libert: *mut bicycl_joye_libert_t);

    pub fn bicycl_joye_libert_keygen(
        ctx: *mut bicycl_context_t,
        joye_libert: *const bicycl_joye_libert_t,
        randgen: *mut bicycl_randgen_t,
        out_sk: *mut *mut bicycl_joye_libert_sk_t,
        out_pk: *mut *mut bicycl_joye_libert_pk_t,
    ) -> bicycl_status_t;

    pub fn bicycl_joye_libert_sk_free(sk: *mut bicycl_joye_libert_sk_t);
    pub fn bicycl_joye_libert_pk_free(pk: *mut bicycl_joye_libert_pk_t);
    pub fn bicycl_joye_libert_ct_free(ct: *mut bicycl_joye_libert_ct_t);

    pub fn bicycl_joye_libert_encrypt_decimal(
        ctx: *mut bicycl_context_t,
        joye_libert: *const bicycl_joye_libert_t,
        pk: *const bicycl_joye_libert_pk_t,
        randgen: *mut bicycl_randgen_t,
        message_decimal: *const c_char,
        out_ct: *mut *mut bicycl_joye_libert_ct_t,
    ) -> bicycl_status_t;

    pub fn bicycl_joye_libert_decrypt_decimal(
        ctx: *mut bicycl_context_t,
        joye_libert: *const bicycl_joye_libert_t,
        sk: *const bicycl_joye_libert_sk_t,
        ct: *const bicycl_joye_libert_ct_t,
        out_buf: *mut c_char,
        inout_len: *mut usize,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsmqk_new(
        ctx: *mut bicycl_context_t,
        q_decimal: *const c_char,
        k: u32,
        p_decimal: *const c_char,
        out_cl: *mut *mut bicycl_cl_hsmqk_t,
    ) -> bicycl_status_t;
    pub fn bicycl_cl_hsmqk_free(cl: *mut bicycl_cl_hsmqk_t);

    pub fn bicycl_cl_hsmqk_keygen(
        ctx: *mut bicycl_context_t,
        cl: *const bicycl_cl_hsmqk_t,
        randgen: *mut bicycl_randgen_t,
        out_sk: *mut *mut bicycl_cl_hsmqk_sk_t,
        out_pk: *mut *mut bicycl_cl_hsmqk_pk_t,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsmqk_sk_free(sk: *mut bicycl_cl_hsmqk_sk_t);
    pub fn bicycl_cl_hsmqk_pk_free(pk: *mut bicycl_cl_hsmqk_pk_t);
    pub fn bicycl_cl_hsmqk_ct_free(ct: *mut bicycl_cl_hsmqk_ct_t);

    pub fn bicycl_cl_hsmqk_encrypt_decimal(
        ctx: *mut bicycl_context_t,
        cl: *const bicycl_cl_hsmqk_t,
        pk: *const bicycl_cl_hsmqk_pk_t,
        randgen: *mut bicycl_randgen_t,
        message_decimal: *const c_char,
        out_ct: *mut *mut bicycl_cl_hsmqk_ct_t,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsmqk_decrypt_decimal(
        ctx: *mut bicycl_context_t,
        cl: *const bicycl_cl_hsmqk_t,
        sk: *const bicycl_cl_hsmqk_sk_t,
        ct: *const bicycl_cl_hsmqk_ct_t,
        out_buf: *mut c_char,
        inout_len: *mut usize,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsmqk_add_ciphertexts(
        ctx: *mut bicycl_context_t,
        cl: *const bicycl_cl_hsmqk_t,
        pk: *const bicycl_cl_hsmqk_pk_t,
        randgen: *mut bicycl_randgen_t,
        ca: *const bicycl_cl_hsmqk_ct_t,
        cb: *const bicycl_cl_hsmqk_ct_t,
        out_ct: *mut *mut bicycl_cl_hsmqk_ct_t,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsmqk_scal_ciphertext_decimal(
        ctx: *mut bicycl_context_t,
        cl: *const bicycl_cl_hsmqk_t,
        pk: *const bicycl_cl_hsmqk_pk_t,
        randgen: *mut bicycl_randgen_t,
        ct: *const bicycl_cl_hsmqk_ct_t,
        scalar_decimal: *const c_char,
        out_ct: *mut *mut bicycl_cl_hsmqk_ct_t,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsmqk_addscal_ciphertexts_decimal(
        ctx: *mut bicycl_context_t,
        cl: *const bicycl_cl_hsmqk_t,
        pk: *const bicycl_cl_hsmqk_pk_t,
        randgen: *mut bicycl_randgen_t,
        ca: *const bicycl_cl_hsmqk_ct_t,
        cb: *const bicycl_cl_hsmqk_ct_t,
        scalar_decimal: *const c_char,
        out_ct: *mut *mut bicycl_cl_hsmqk_ct_t,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsm2k_new(
        ctx: *mut bicycl_context_t,
        n_decimal: *const c_char,
        k: u32,
        out_cl: *mut *mut bicycl_cl_hsm2k_t,
    ) -> bicycl_status_t;
    pub fn bicycl_cl_hsm2k_free(cl: *mut bicycl_cl_hsm2k_t);

    pub fn bicycl_cl_hsm2k_keygen(
        ctx: *mut bicycl_context_t,
        cl: *const bicycl_cl_hsm2k_t,
        randgen: *mut bicycl_randgen_t,
        out_sk: *mut *mut bicycl_cl_hsm2k_sk_t,
        out_pk: *mut *mut bicycl_cl_hsm2k_pk_t,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsm2k_sk_free(sk: *mut bicycl_cl_hsm2k_sk_t);
    pub fn bicycl_cl_hsm2k_pk_free(pk: *mut bicycl_cl_hsm2k_pk_t);
    pub fn bicycl_cl_hsm2k_ct_free(ct: *mut bicycl_cl_hsm2k_ct_t);

    pub fn bicycl_cl_hsm2k_encrypt_decimal(
        ctx: *mut bicycl_context_t,
        cl: *const bicycl_cl_hsm2k_t,
        pk: *const bicycl_cl_hsm2k_pk_t,
        randgen: *mut bicycl_randgen_t,
        message_decimal: *const c_char,
        out_ct: *mut *mut bicycl_cl_hsm2k_ct_t,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsm2k_decrypt_decimal(
        ctx: *mut bicycl_context_t,
        cl: *const bicycl_cl_hsm2k_t,
        sk: *const bicycl_cl_hsm2k_sk_t,
        ct: *const bicycl_cl_hsm2k_ct_t,
        out_buf: *mut c_char,
        inout_len: *mut usize,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsm2k_add_ciphertexts(
        ctx: *mut bicycl_context_t,
        cl: *const bicycl_cl_hsm2k_t,
        pk: *const bicycl_cl_hsm2k_pk_t,
        randgen: *mut bicycl_randgen_t,
        ca: *const bicycl_cl_hsm2k_ct_t,
        cb: *const bicycl_cl_hsm2k_ct_t,
        out_ct: *mut *mut bicycl_cl_hsm2k_ct_t,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsm2k_scal_ciphertext_decimal(
        ctx: *mut bicycl_context_t,
        cl: *const bicycl_cl_hsm2k_t,
        pk: *const bicycl_cl_hsm2k_pk_t,
        randgen: *mut bicycl_randgen_t,
        ct: *const bicycl_cl_hsm2k_ct_t,
        scalar_decimal: *const c_char,
        out_ct: *mut *mut bicycl_cl_hsm2k_ct_t,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_hsm2k_addscal_ciphertexts_decimal(
        ctx: *mut bicycl_context_t,
        cl: *const bicycl_cl_hsm2k_t,
        pk: *const bicycl_cl_hsm2k_pk_t,
        randgen: *mut bicycl_randgen_t,
        ca: *const bicycl_cl_hsm2k_ct_t,
        cb: *const bicycl_cl_hsm2k_ct_t,
        scalar_decimal: *const c_char,
        out_ct: *mut *mut bicycl_cl_hsm2k_ct_t,
    ) -> bicycl_status_t;

    pub fn bicycl_ecdsa_new(
        ctx: *mut bicycl_context_t,
        seclevel_bits: u32,
        out_ecdsa: *mut *mut bicycl_ecdsa_t,
    ) -> bicycl_status_t;
    pub fn bicycl_ecdsa_free(ecdsa: *mut bicycl_ecdsa_t);

    pub fn bicycl_ecdsa_keygen(
        ctx: *mut bicycl_context_t,
        ecdsa: *const bicycl_ecdsa_t,
        randgen: *mut bicycl_randgen_t,
        out_sk: *mut *mut bicycl_ecdsa_sk_t,
        out_pk: *mut *mut bicycl_ecdsa_pk_t,
    ) -> bicycl_status_t;
    pub fn bicycl_ecdsa_sk_free(sk: *mut bicycl_ecdsa_sk_t);
    pub fn bicycl_ecdsa_pk_free(pk: *mut bicycl_ecdsa_pk_t);

    pub fn bicycl_ecdsa_sign_message(
        ctx: *mut bicycl_context_t,
        ecdsa: *const bicycl_ecdsa_t,
        randgen: *mut bicycl_randgen_t,
        sk: *const bicycl_ecdsa_sk_t,
        msg_ptr: *const u8,
        msg_len: usize,
        out_sig: *mut *mut bicycl_ecdsa_sig_t,
    ) -> bicycl_status_t;
    pub fn bicycl_ecdsa_sig_free(sig: *mut bicycl_ecdsa_sig_t);

    pub fn bicycl_ecdsa_verify_message(
        ctx: *mut bicycl_context_t,
        ecdsa: *const bicycl_ecdsa_t,
        pk: *const bicycl_ecdsa_pk_t,
        msg_ptr: *const u8,
        msg_len: usize,
        sig: *const bicycl_ecdsa_sig_t,
        out_valid: *mut c_int,
    ) -> bicycl_status_t;

    pub fn bicycl_ecdsa_sig_r_decimal(
        ctx: *mut bicycl_context_t,
        sig: *const bicycl_ecdsa_sig_t,
        out_buf: *mut c_char,
        inout_len: *mut usize,
    ) -> bicycl_status_t;

    pub fn bicycl_ecdsa_sig_s_decimal(
        ctx: *mut bicycl_context_t,
        sig: *const bicycl_ecdsa_sig_t,
        out_buf: *mut c_char,
        inout_len: *mut usize,
    ) -> bicycl_status_t;

    pub fn bicycl_two_party_ecdsa_run_demo(
        ctx: *mut bicycl_context_t,
        randgen: *mut bicycl_randgen_t,
        seclevel_bits: u32,
        msg_ptr: *const u8,
        msg_len: usize,
        out_valid: *mut c_int,
    ) -> bicycl_status_t;
    pub fn bicycl_two_party_ecdsa_session_new(
        ctx: *mut bicycl_context_t,
        randgen: *mut bicycl_randgen_t,
        seclevel_bits: u32,
        out_session: *mut *mut bicycl_two_party_ecdsa_session_t,
    ) -> bicycl_status_t;
    pub fn bicycl_two_party_ecdsa_session_free(session: *mut bicycl_two_party_ecdsa_session_t);
    pub fn bicycl_two_party_ecdsa_keygen_round1(
        ctx: *mut bicycl_context_t,
        session: *mut bicycl_two_party_ecdsa_session_t,
        randgen: *mut bicycl_randgen_t,
    ) -> bicycl_status_t;
    pub fn bicycl_two_party_ecdsa_keygen_round2(
        ctx: *mut bicycl_context_t,
        session: *mut bicycl_two_party_ecdsa_session_t,
        randgen: *mut bicycl_randgen_t,
    ) -> bicycl_status_t;
    pub fn bicycl_two_party_ecdsa_keygen_round3(
        ctx: *mut bicycl_context_t,
        session: *mut bicycl_two_party_ecdsa_session_t,
        randgen: *mut bicycl_randgen_t,
    ) -> bicycl_status_t;
    pub fn bicycl_two_party_ecdsa_keygen_round4(
        ctx: *mut bicycl_context_t,
        session: *mut bicycl_two_party_ecdsa_session_t,
    ) -> bicycl_status_t;
    pub fn bicycl_two_party_ecdsa_sign_round1(
        ctx: *mut bicycl_context_t,
        session: *mut bicycl_two_party_ecdsa_session_t,
        randgen: *mut bicycl_randgen_t,
        msg_ptr: *const u8,
        msg_len: usize,
    ) -> bicycl_status_t;
    pub fn bicycl_two_party_ecdsa_sign_round2(
        ctx: *mut bicycl_context_t,
        session: *mut bicycl_two_party_ecdsa_session_t,
        randgen: *mut bicycl_randgen_t,
    ) -> bicycl_status_t;
    pub fn bicycl_two_party_ecdsa_sign_round3(
        ctx: *mut bicycl_context_t,
        session: *mut bicycl_two_party_ecdsa_session_t,
    ) -> bicycl_status_t;
    pub fn bicycl_two_party_ecdsa_sign_round4(
        ctx: *mut bicycl_context_t,
        session: *mut bicycl_two_party_ecdsa_session_t,
        randgen: *mut bicycl_randgen_t,
    ) -> bicycl_status_t;
    pub fn bicycl_two_party_ecdsa_sign_finalize(
        ctx: *mut bicycl_context_t,
        session: *mut bicycl_two_party_ecdsa_session_t,
        out_valid: *mut c_int,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_threshold_run_demo(
        ctx: *mut bicycl_context_t,
        randgen: *mut bicycl_randgen_t,
        out_buf: *mut c_char,
        inout_len: *mut usize,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_dlog_proof_run_demo(
        ctx: *mut bicycl_context_t,
        randgen: *mut bicycl_randgen_t,
        seclevel_bits: u32,
        out_valid: *mut c_int,
    ) -> bicycl_status_t;

    pub fn bicycl_threshold_ecdsa_run_demo(
        ctx: *mut bicycl_context_t,
        randgen: *mut bicycl_randgen_t,
        seclevel_bits: u32,
        msg_ptr: *const u8,
        msg_len: usize,
        out_valid: *mut c_int,
    ) -> bicycl_status_t;

    pub fn bicycl_cl_dlog_session_new(
        ctx: *mut bicycl_context_t,
        randgen: *mut bicycl_randgen_t,
        seclevel_bits: u32,
        out_session: *mut *mut bicycl_cl_dlog_session_t,
    ) -> bicycl_status_t;
    pub fn bicycl_cl_dlog_session_free(session: *mut bicycl_cl_dlog_session_t);
    pub fn bicycl_cl_dlog_session_prepare_statement(
        ctx: *mut bicycl_context_t,
        session: *mut bicycl_cl_dlog_session_t,
        randgen: *mut bicycl_randgen_t,
    ) -> bicycl_status_t;
    pub fn bicycl_cl_dlog_session_prove_round(
        ctx: *mut bicycl_context_t,
        session: *mut bicycl_cl_dlog_session_t,
        randgen: *mut bicycl_randgen_t,
    ) -> bicycl_status_t;
    pub fn bicycl_cl_dlog_session_verify_round(
        ctx: *mut bicycl_context_t,
        session: *const bicycl_cl_dlog_session_t,
        out_valid: *mut c_int,
    ) -> bicycl_status_t;
    pub fn bicycl_cl_dlog_message_new(
        out_msg: *mut *mut bicycl_cl_dlog_message_t,
    ) -> bicycl_status_t;
    pub fn bicycl_cl_dlog_message_free(msg: *mut bicycl_cl_dlog_message_t);
    pub fn bicycl_cl_dlog_message_export_bytes(
        ctx: *mut bicycl_context_t,
        msg: *const bicycl_cl_dlog_message_t,
        out_buf: *mut u8,
        inout_len: *mut usize,
    ) -> bicycl_status_t;
    pub fn bicycl_cl_dlog_message_import_bytes(
        ctx: *mut bicycl_context_t,
        msg: *mut bicycl_cl_dlog_message_t,
        bytes: *const u8,
        len: usize,
    ) -> bicycl_status_t;
    pub fn bicycl_cl_dlog_session_export_statement(
        ctx: *mut bicycl_context_t,
        session: *const bicycl_cl_dlog_session_t,
        out_msg: *mut bicycl_cl_dlog_message_t,
    ) -> bicycl_status_t;
    pub fn bicycl_cl_dlog_session_import_statement(
        ctx: *mut bicycl_context_t,
        session: *mut bicycl_cl_dlog_session_t,
        msg: *const bicycl_cl_dlog_message_t,
    ) -> bicycl_status_t;
    pub fn bicycl_cl_dlog_session_export_proof(
        ctx: *mut bicycl_context_t,
        session: *const bicycl_cl_dlog_session_t,
        out_msg: *mut bicycl_cl_dlog_message_t,
    ) -> bicycl_status_t;
    pub fn bicycl_cl_dlog_session_import_proof(
        ctx: *mut bicycl_context_t,
        session: *mut bicycl_cl_dlog_session_t,
        msg: *const bicycl_cl_dlog_message_t,
    ) -> bicycl_status_t;

    pub fn bicycl_threshold_ecdsa_session_new(
        ctx: *mut bicycl_context_t,
        randgen: *mut bicycl_randgen_t,
        seclevel_bits: u32,
        n_players: u32,
        threshold_t: u32,
        out_session: *mut *mut bicycl_threshold_ecdsa_session_t,
    ) -> bicycl_status_t;
    pub fn bicycl_threshold_ecdsa_session_free(session: *mut bicycl_threshold_ecdsa_session_t);
    pub fn bicycl_threshold_ecdsa_keygen_round1(
        ctx: *mut bicycl_context_t,
        session: *mut bicycl_threshold_ecdsa_session_t,
        randgen: *mut bicycl_randgen_t,
    ) -> bicycl_status_t;
    pub fn bicycl_threshold_ecdsa_keygen_round2(
        ctx: *mut bicycl_context_t,
        session: *mut bicycl_threshold_ecdsa_session_t,
        randgen: *mut bicycl_randgen_t,
    ) -> bicycl_status_t;
    pub fn bicycl_threshold_ecdsa_keygen_finalize(
        ctx: *mut bicycl_context_t,
        session: *mut bicycl_threshold_ecdsa_session_t,
    ) -> bicycl_status_t;
    pub fn bicycl_threshold_ecdsa_sign_round1(
        ctx: *mut bicycl_context_t,
        session: *mut bicycl_threshold_ecdsa_session_t,
        randgen: *mut bicycl_randgen_t,
        msg_ptr: *const u8,
        msg_len: usize,
    ) -> bicycl_status_t;
    pub fn bicycl_threshold_ecdsa_sign_round2(
        ctx: *mut bicycl_context_t,
        session: *mut bicycl_threshold_ecdsa_session_t,
        randgen: *mut bicycl_randgen_t,
    ) -> bicycl_status_t;
    pub fn bicycl_threshold_ecdsa_sign_round3(
        ctx: *mut bicycl_context_t,
        session: *mut bicycl_threshold_ecdsa_session_t,
    ) -> bicycl_status_t;
    pub fn bicycl_threshold_ecdsa_sign_round4(
        ctx: *mut bicycl_context_t,
        session: *mut bicycl_threshold_ecdsa_session_t,
    ) -> bicycl_status_t;
    pub fn bicycl_threshold_ecdsa_sign_round5(
        ctx: *mut bicycl_context_t,
        session: *mut bicycl_threshold_ecdsa_session_t,
        randgen: *mut bicycl_randgen_t,
    ) -> bicycl_status_t;
    pub fn bicycl_threshold_ecdsa_sign_round6(
        ctx: *mut bicycl_context_t,
        session: *mut bicycl_threshold_ecdsa_session_t,
        randgen: *mut bicycl_randgen_t,
    ) -> bicycl_status_t;
    pub fn bicycl_threshold_ecdsa_sign_round7(
        ctx: *mut bicycl_context_t,
        session: *mut bicycl_threshold_ecdsa_session_t,
        randgen: *mut bicycl_randgen_t,
    ) -> bicycl_status_t;
    pub fn bicycl_threshold_ecdsa_sign_round8(
        ctx: *mut bicycl_context_t,
        session: *mut bicycl_threshold_ecdsa_session_t,
    ) -> bicycl_status_t;
    pub fn bicycl_threshold_ecdsa_sign_finalize(
        ctx: *mut bicycl_context_t,
        session: *mut bicycl_threshold_ecdsa_session_t,
    ) -> bicycl_status_t;
    pub fn bicycl_threshold_ecdsa_signature_valid(
        ctx: *mut bicycl_context_t,
        session: *const bicycl_threshold_ecdsa_session_t,
        out_valid: *mut c_int,
    ) -> bicycl_status_t;
}
