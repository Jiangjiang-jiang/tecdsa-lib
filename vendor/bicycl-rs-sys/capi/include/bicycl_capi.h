#ifndef BICYCL_CAPI_H
#define BICYCL_CAPI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BICYCL_CAPI_VERSION 0x00010100u

typedef enum bicycl_status_t {
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
} bicycl_status_t;

typedef struct bicycl_context_t bicycl_context_t;
typedef struct bicycl_randgen_t bicycl_randgen_t;
typedef struct bicycl_classgroup_t bicycl_classgroup_t;
typedef struct bicycl_qfi_t bicycl_qfi_t;
typedef struct bicycl_paillier_t bicycl_paillier_t;
typedef struct bicycl_paillier_sk_t bicycl_paillier_sk_t;
typedef struct bicycl_paillier_pk_t bicycl_paillier_pk_t;
typedef struct bicycl_paillier_ct_t bicycl_paillier_ct_t;
typedef struct bicycl_joye_libert_t bicycl_joye_libert_t;
typedef struct bicycl_joye_libert_sk_t bicycl_joye_libert_sk_t;
typedef struct bicycl_joye_libert_pk_t bicycl_joye_libert_pk_t;
typedef struct bicycl_joye_libert_ct_t bicycl_joye_libert_ct_t;
typedef struct bicycl_cl_hsmqk_t bicycl_cl_hsmqk_t;
typedef struct bicycl_cl_hsmqk_sk_t bicycl_cl_hsmqk_sk_t;
typedef struct bicycl_cl_hsmqk_pk_t bicycl_cl_hsmqk_pk_t;
typedef struct bicycl_cl_hsmqk_ct_t bicycl_cl_hsmqk_ct_t;
typedef struct bicycl_cl_hsm2k_t bicycl_cl_hsm2k_t;
typedef struct bicycl_cl_hsm2k_sk_t bicycl_cl_hsm2k_sk_t;
typedef struct bicycl_cl_hsm2k_pk_t bicycl_cl_hsm2k_pk_t;
typedef struct bicycl_cl_hsm2k_ct_t bicycl_cl_hsm2k_ct_t;
typedef struct bicycl_ecdsa_t bicycl_ecdsa_t;
typedef struct bicycl_ecdsa_sk_t bicycl_ecdsa_sk_t;
typedef struct bicycl_ecdsa_pk_t bicycl_ecdsa_pk_t;
typedef struct bicycl_ecdsa_sig_t bicycl_ecdsa_sig_t;
typedef struct bicycl_two_party_ecdsa_session_t bicycl_two_party_ecdsa_session_t;
typedef struct bicycl_cl_dlog_session_t bicycl_cl_dlog_session_t;
typedef struct bicycl_threshold_ecdsa_session_t bicycl_threshold_ecdsa_session_t;
typedef struct bicycl_cl_dlog_message_t bicycl_cl_dlog_message_t;

uint32_t bicycl_get_abi_version(void);
const char *bicycl_get_version(void);
const char *bicycl_status_message(bicycl_status_t status);

bicycl_status_t bicycl_context_new(bicycl_context_t **out_ctx);
void bicycl_context_free(bicycl_context_t *ctx);

const char *bicycl_context_last_error(const bicycl_context_t *ctx);
void bicycl_context_clear_error(bicycl_context_t *ctx);

void bicycl_zeroize(void *ptr, size_t len);

bicycl_status_t bicycl_randgen_new_from_seed_decimal(
    bicycl_context_t *ctx,
    const char *seed_decimal,
    bicycl_randgen_t **out_randgen);
void bicycl_randgen_free(bicycl_randgen_t *randgen);

bicycl_status_t bicycl_classgroup_new_from_discriminant_decimal(
    bicycl_context_t *ctx,
    const char *discriminant_decimal,
    bicycl_classgroup_t **out_classgroup);
void bicycl_classgroup_free(bicycl_classgroup_t *classgroup);

bicycl_status_t bicycl_classgroup_one(
    bicycl_context_t *ctx,
    const bicycl_classgroup_t *classgroup,
    bicycl_qfi_t **out_qfi);

bicycl_status_t bicycl_classgroup_nudupl(
    bicycl_context_t *ctx,
    const bicycl_classgroup_t *classgroup,
    const bicycl_qfi_t *input,
    bicycl_qfi_t **out_qfi);

void bicycl_qfi_free(bicycl_qfi_t *qfi);

bicycl_status_t bicycl_qfi_is_one(
    bicycl_context_t *ctx,
    const bicycl_qfi_t *qfi,
    int *out_is_one);

bicycl_status_t bicycl_qfi_discriminant_decimal(
    bicycl_context_t *ctx,
    const bicycl_qfi_t *qfi,
    char *out_buf,
    size_t *inout_len);

// ── QFI additional ──────────────────────────────────────────────────────
bicycl_status_t bicycl_qfi_new_from_abc_decimal(
    bicycl_context_t *ctx, const char *a, const char *b, const char *c,
    bicycl_qfi_t **out);

bicycl_status_t bicycl_qfi_a_decimal(
    bicycl_context_t *ctx, const bicycl_qfi_t *qfi, char *out_buf, size_t *inout_len);

bicycl_status_t bicycl_qfi_b_decimal(
    bicycl_context_t *ctx, const bicycl_qfi_t *qfi, char *out_buf, size_t *inout_len);

bicycl_status_t bicycl_qfi_c_decimal(
    bicycl_context_t *ctx, const bicycl_qfi_t *qfi, char *out_buf, size_t *inout_len);

bicycl_status_t bicycl_qfi_equal(
    bicycl_context_t *ctx, const bicycl_qfi_t *a, const bicycl_qfi_t *b, int *out);

bicycl_status_t bicycl_qfi_neg(
    bicycl_context_t *ctx, const bicycl_qfi_t *qfi, bicycl_qfi_t **out);

bicycl_status_t bicycl_qfi_lift_decimal(
    bicycl_context_t *ctx, bicycl_qfi_t *qfi, const char *conductor_decimal);

bicycl_status_t bicycl_qfi_to_maximal_order_decimal(
    bicycl_context_t *ctx, bicycl_qfi_t *qfi,
    const char *conductor_decimal, const char *DeltaK_decimal, int to_neg);

// ── ClassGroup additional ────────────────────────────────────────────────
bicycl_status_t bicycl_classgroup_discriminant_decimal(
    bicycl_context_t *ctx, const bicycl_classgroup_t *cg, char *out_buf, size_t *inout_len);

bicycl_status_t bicycl_classgroup_nucomp(
    bicycl_context_t *ctx, const bicycl_classgroup_t *cg,
    const bicycl_qfi_t *f1, const bicycl_qfi_t *f2, bicycl_qfi_t **out);

bicycl_status_t bicycl_classgroup_nucompinv(
    bicycl_context_t *ctx, const bicycl_classgroup_t *cg,
    const bicycl_qfi_t *f1, const bicycl_qfi_t *f2, bicycl_qfi_t **out);

bicycl_status_t bicycl_classgroup_nupow_decimal(
    bicycl_context_t *ctx, const bicycl_classgroup_t *cg,
    const bicycl_qfi_t *f, const char *n_decimal, bicycl_qfi_t **out);

bicycl_status_t bicycl_classgroup_nupow2_decimal(
    bicycl_context_t *ctx, const bicycl_classgroup_t *cg,
    const bicycl_qfi_t *f0, const char *n0_decimal,
    const bicycl_qfi_t *f1, const char *n1_decimal, bicycl_qfi_t **out);

bicycl_status_t bicycl_classgroup_primeform_decimal(
    bicycl_context_t *ctx, const bicycl_classgroup_t *cg,
    const char *p_decimal, bicycl_qfi_t **out);

// ── CL_HSMqk parameters ──────────────────────────────────────────────────
bicycl_status_t bicycl_cl_hsmqk_q_decimal(
    bicycl_context_t *ctx, const bicycl_cl_hsmqk_t *cl, char *out_buf, size_t *inout_len);
bicycl_status_t bicycl_cl_hsmqk_p_decimal(
    bicycl_context_t *ctx, const bicycl_cl_hsmqk_t *cl, char *out_buf, size_t *inout_len);
bicycl_status_t bicycl_cl_hsmqk_M_decimal(
    bicycl_context_t *ctx, const bicycl_cl_hsmqk_t *cl, char *out_buf, size_t *inout_len);
bicycl_status_t bicycl_cl_hsmqk_DeltaK_decimal(
    bicycl_context_t *ctx, const bicycl_cl_hsmqk_t *cl, char *out_buf, size_t *inout_len);
bicycl_status_t bicycl_cl_hsmqk_Delta_decimal(
    bicycl_context_t *ctx, const bicycl_cl_hsmqk_t *cl, char *out_buf, size_t *inout_len);
bicycl_status_t bicycl_cl_hsmqk_secretkey_bound_decimal(
    bicycl_context_t *ctx, const bicycl_cl_hsmqk_t *cl, char *out_buf, size_t *inout_len);
bicycl_status_t bicycl_cl_hsmqk_Cl_DeltaK(
    bicycl_context_t *ctx, const bicycl_cl_hsmqk_t *cl, bicycl_classgroup_t **out);
bicycl_status_t bicycl_cl_hsmqk_Cl_Delta(
    bicycl_context_t *ctx, const bicycl_cl_hsmqk_t *cl, bicycl_classgroup_t **out);
bicycl_status_t bicycl_cl_hsmqk_h(
    bicycl_context_t *ctx, const bicycl_cl_hsmqk_t *cl, bicycl_qfi_t **out);

// ── CL_HSMqk subgroup operations ─────────────────────────────────────────
bicycl_status_t bicycl_cl_hsmqk_power_of_h_decimal(
    bicycl_context_t *ctx, const bicycl_cl_hsmqk_t *cl,
    const char *e_decimal, bicycl_qfi_t **out);
bicycl_status_t bicycl_cl_hsmqk_power_of_f_decimal(
    bicycl_context_t *ctx, const bicycl_cl_hsmqk_t *cl,
    const char *m_decimal, bicycl_qfi_t **out);
bicycl_status_t bicycl_cl_hsmqk_dlog_in_F(
    bicycl_context_t *ctx, const bicycl_cl_hsmqk_t *cl,
    const bicycl_qfi_t *fm, char *out_buf, size_t *inout_len);
bicycl_status_t bicycl_cl_hsmqk_from_Cl_DeltaK_to_Cl_Delta(
    bicycl_context_t *ctx, const bicycl_cl_hsmqk_t *cl, bicycl_qfi_t *f);

// ── CL_HSMqk key/ciphertext access ───────────────────────────────────────
bicycl_status_t bicycl_cl_hsmqk_pk_elt(
    bicycl_context_t *ctx, const bicycl_cl_hsmqk_pk_t *pk, bicycl_qfi_t **out);
bicycl_status_t bicycl_cl_hsmqk_pk_new_from_qfi(
    bicycl_context_t *ctx, const bicycl_cl_hsmqk_t *cl,
    const bicycl_qfi_t *qfi, bicycl_cl_hsmqk_pk_t **out);
bicycl_status_t bicycl_cl_hsmqk_ct_c1(
    bicycl_context_t *ctx, const bicycl_cl_hsmqk_ct_t *ct, bicycl_qfi_t **out);
bicycl_status_t bicycl_cl_hsmqk_ct_c2(
    bicycl_context_t *ctx, const bicycl_cl_hsmqk_ct_t *ct, bicycl_qfi_t **out);
bicycl_status_t bicycl_cl_hsmqk_ct_new_from_c1c2(
    bicycl_context_t *ctx, const bicycl_qfi_t *c1, const bicycl_qfi_t *c2,
    bicycl_cl_hsmqk_ct_t **out);
bicycl_status_t bicycl_cl_hsmqk_sk_decimal(
    bicycl_context_t *ctx, const bicycl_cl_hsmqk_sk_t *sk, char *out_buf, size_t *inout_len);
bicycl_status_t bicycl_cl_hsmqk_sk_new_from_decimal(
    bicycl_context_t *ctx, const bicycl_cl_hsmqk_t *cl,
    const char *sk_decimal, bicycl_cl_hsmqk_sk_t **out);
bicycl_status_t bicycl_cl_hsmqk_encrypt_decimal_with_r(
    bicycl_context_t *ctx, const bicycl_cl_hsmqk_t *cl,
    const bicycl_cl_hsmqk_pk_t *pk, const char *message_decimal,
    const char *r_decimal, bicycl_cl_hsmqk_ct_t **out_ct);

// ── CL_HSM2k parameters ──────────────────────────────────────────────────
bicycl_status_t bicycl_cl_hsm2k_N_decimal(
    bicycl_context_t *ctx, const bicycl_cl_hsm2k_t *cl, char *out_buf, size_t *inout_len);
bicycl_status_t bicycl_cl_hsm2k_M_decimal(
    bicycl_context_t *ctx, const bicycl_cl_hsm2k_t *cl, char *out_buf, size_t *inout_len);
bicycl_status_t bicycl_cl_hsm2k_DeltaK_decimal(
    bicycl_context_t *ctx, const bicycl_cl_hsm2k_t *cl, char *out_buf, size_t *inout_len);
bicycl_status_t bicycl_cl_hsm2k_Delta_decimal(
    bicycl_context_t *ctx, const bicycl_cl_hsm2k_t *cl, char *out_buf, size_t *inout_len);
bicycl_status_t bicycl_cl_hsm2k_secretkey_bound_decimal(
    bicycl_context_t *ctx, const bicycl_cl_hsm2k_t *cl, char *out_buf, size_t *inout_len);
bicycl_status_t bicycl_cl_hsm2k_Cl_DeltaK(
    bicycl_context_t *ctx, const bicycl_cl_hsm2k_t *cl, bicycl_classgroup_t **out);
bicycl_status_t bicycl_cl_hsm2k_Cl_Delta(
    bicycl_context_t *ctx, const bicycl_cl_hsm2k_t *cl, bicycl_classgroup_t **out);
bicycl_status_t bicycl_cl_hsm2k_h(
    bicycl_context_t *ctx, const bicycl_cl_hsm2k_t *cl, bicycl_qfi_t **out);
bicycl_status_t bicycl_cl_hsm2k_power_of_h_decimal(
    bicycl_context_t *ctx, const bicycl_cl_hsm2k_t *cl,
    const char *e_decimal, bicycl_qfi_t **out);
bicycl_status_t bicycl_cl_hsm2k_power_of_f_decimal(
    bicycl_context_t *ctx, const bicycl_cl_hsm2k_t *cl,
    const char *m_decimal, bicycl_qfi_t **out);
bicycl_status_t bicycl_cl_hsm2k_dlog_in_F(
    bicycl_context_t *ctx, const bicycl_cl_hsm2k_t *cl,
    const bicycl_qfi_t *fm, char *out_buf, size_t *inout_len);
bicycl_status_t bicycl_cl_hsm2k_from_Cl_DeltaK_to_Cl_Delta(
    bicycl_context_t *ctx, const bicycl_cl_hsm2k_t *cl, bicycl_qfi_t *f);
bicycl_status_t bicycl_cl_hsm2k_pk_elt(
    bicycl_context_t *ctx, const bicycl_cl_hsm2k_pk_t *pk, bicycl_qfi_t **out);
bicycl_status_t bicycl_cl_hsm2k_pk_new_from_qfi(
    bicycl_context_t *ctx, const bicycl_cl_hsm2k_t *cl,
    const bicycl_qfi_t *qfi, bicycl_cl_hsm2k_pk_t **out);
bicycl_status_t bicycl_cl_hsm2k_ct_c1(
    bicycl_context_t *ctx, const bicycl_cl_hsm2k_ct_t *ct, bicycl_qfi_t **out);
bicycl_status_t bicycl_cl_hsm2k_ct_c2(
    bicycl_context_t *ctx, const bicycl_cl_hsm2k_ct_t *ct, bicycl_qfi_t **out);
bicycl_status_t bicycl_cl_hsm2k_ct_new_from_c1c2(
    bicycl_context_t *ctx, const bicycl_qfi_t *c1, const bicycl_qfi_t *c2,
    bicycl_cl_hsm2k_ct_t **out);
bicycl_status_t bicycl_cl_hsm2k_sk_decimal(
    bicycl_context_t *ctx, const bicycl_cl_hsm2k_sk_t *sk, char *out_buf, size_t *inout_len);
bicycl_status_t bicycl_cl_hsm2k_sk_new_from_decimal(
    bicycl_context_t *ctx, const bicycl_cl_hsm2k_t *cl,
    const char *sk_decimal, bicycl_cl_hsm2k_sk_t **out);
bicycl_status_t bicycl_cl_hsm2k_encrypt_decimal_with_r(
    bicycl_context_t *ctx, const bicycl_cl_hsm2k_t *cl,
    const bicycl_cl_hsm2k_pk_t *pk, const char *message_decimal,
    const char *r_decimal, bicycl_cl_hsm2k_ct_t **out_ct);

bicycl_status_t bicycl_paillier_new(
    bicycl_context_t *ctx,
    uint32_t modulus_bits,
    bicycl_paillier_t **out_paillier);
void bicycl_paillier_free(bicycl_paillier_t *paillier);

bicycl_status_t bicycl_paillier_keygen(
    bicycl_context_t *ctx,
    const bicycl_paillier_t *paillier,
    bicycl_randgen_t *randgen,
    bicycl_paillier_sk_t **out_sk,
    bicycl_paillier_pk_t **out_pk);

void bicycl_paillier_sk_free(bicycl_paillier_sk_t *sk);
void bicycl_paillier_pk_free(bicycl_paillier_pk_t *pk);
void bicycl_paillier_ct_free(bicycl_paillier_ct_t *ct);

bicycl_status_t bicycl_paillier_encrypt_decimal(
    bicycl_context_t *ctx,
    const bicycl_paillier_t *paillier,
    const bicycl_paillier_pk_t *pk,
    bicycl_randgen_t *randgen,
    const char *message_decimal,
    bicycl_paillier_ct_t **out_ct);

bicycl_status_t bicycl_paillier_decrypt_decimal(
    bicycl_context_t *ctx,
    const bicycl_paillier_t *paillier,
    const bicycl_paillier_pk_t *pk,
    const bicycl_paillier_sk_t *sk,
    const bicycl_paillier_ct_t *ct,
    char *out_buf,
    size_t *inout_len);

bicycl_status_t bicycl_joye_libert_new(
    bicycl_context_t *ctx,
    uint32_t modulus_bits,
    uint32_t k,
    bicycl_joye_libert_t **out_joye_libert);
void bicycl_joye_libert_free(bicycl_joye_libert_t *joye_libert);

bicycl_status_t bicycl_joye_libert_keygen(
    bicycl_context_t *ctx,
    const bicycl_joye_libert_t *joye_libert,
    bicycl_randgen_t *randgen,
    bicycl_joye_libert_sk_t **out_sk,
    bicycl_joye_libert_pk_t **out_pk);

void bicycl_joye_libert_sk_free(bicycl_joye_libert_sk_t *sk);
void bicycl_joye_libert_pk_free(bicycl_joye_libert_pk_t *pk);
void bicycl_joye_libert_ct_free(bicycl_joye_libert_ct_t *ct);

bicycl_status_t bicycl_joye_libert_encrypt_decimal(
    bicycl_context_t *ctx,
    const bicycl_joye_libert_t *joye_libert,
    const bicycl_joye_libert_pk_t *pk,
    bicycl_randgen_t *randgen,
    const char *message_decimal,
    bicycl_joye_libert_ct_t **out_ct);

bicycl_status_t bicycl_joye_libert_decrypt_decimal(
    bicycl_context_t *ctx,
    const bicycl_joye_libert_t *joye_libert,
    const bicycl_joye_libert_sk_t *sk,
    const bicycl_joye_libert_ct_t *ct,
    char *out_buf,
    size_t *inout_len);

bicycl_status_t bicycl_cl_hsmqk_new(
    bicycl_context_t *ctx,
    const char *q_decimal,
    uint32_t k,
    const char *p_decimal,
    bicycl_cl_hsmqk_t **out_cl);
void bicycl_cl_hsmqk_free(bicycl_cl_hsmqk_t *cl);

bicycl_status_t bicycl_cl_hsmqk_keygen(
    bicycl_context_t *ctx,
    const bicycl_cl_hsmqk_t *cl,
    bicycl_randgen_t *randgen,
    bicycl_cl_hsmqk_sk_t **out_sk,
    bicycl_cl_hsmqk_pk_t **out_pk);

void bicycl_cl_hsmqk_sk_free(bicycl_cl_hsmqk_sk_t *sk);
void bicycl_cl_hsmqk_pk_free(bicycl_cl_hsmqk_pk_t *pk);
void bicycl_cl_hsmqk_ct_free(bicycl_cl_hsmqk_ct_t *ct);

bicycl_status_t bicycl_cl_hsmqk_encrypt_decimal(
    bicycl_context_t *ctx,
    const bicycl_cl_hsmqk_t *cl,
    const bicycl_cl_hsmqk_pk_t *pk,
    bicycl_randgen_t *randgen,
    const char *message_decimal,
    bicycl_cl_hsmqk_ct_t **out_ct);

bicycl_status_t bicycl_cl_hsmqk_decrypt_decimal(
    bicycl_context_t *ctx,
    const bicycl_cl_hsmqk_t *cl,
    const bicycl_cl_hsmqk_sk_t *sk,
    const bicycl_cl_hsmqk_ct_t *ct,
    char *out_buf,
    size_t *inout_len);

bicycl_status_t bicycl_cl_hsmqk_add_ciphertexts(
    bicycl_context_t *ctx,
    const bicycl_cl_hsmqk_t *cl,
    const bicycl_cl_hsmqk_pk_t *pk,
    bicycl_randgen_t *randgen,
    const bicycl_cl_hsmqk_ct_t *ca,
    const bicycl_cl_hsmqk_ct_t *cb,
    bicycl_cl_hsmqk_ct_t **out_ct);

bicycl_status_t bicycl_cl_hsmqk_scal_ciphertext_decimal(
    bicycl_context_t *ctx,
    const bicycl_cl_hsmqk_t *cl,
    const bicycl_cl_hsmqk_pk_t *pk,
    bicycl_randgen_t *randgen,
    const bicycl_cl_hsmqk_ct_t *ct,
    const char *scalar_decimal,
    bicycl_cl_hsmqk_ct_t **out_ct);

bicycl_status_t bicycl_cl_hsmqk_addscal_ciphertexts_decimal(
    bicycl_context_t *ctx,
    const bicycl_cl_hsmqk_t *cl,
    const bicycl_cl_hsmqk_pk_t *pk,
    bicycl_randgen_t *randgen,
    const bicycl_cl_hsmqk_ct_t *ca,
    const bicycl_cl_hsmqk_ct_t *cb,
    const char *scalar_decimal,
    bicycl_cl_hsmqk_ct_t **out_ct);

bicycl_status_t bicycl_cl_hsm2k_new(
    bicycl_context_t *ctx,
    const char *N_decimal,
    uint32_t k,
    bicycl_cl_hsm2k_t **out_cl);
void bicycl_cl_hsm2k_free(bicycl_cl_hsm2k_t *cl);

bicycl_status_t bicycl_cl_hsm2k_keygen(
    bicycl_context_t *ctx,
    const bicycl_cl_hsm2k_t *cl,
    bicycl_randgen_t *randgen,
    bicycl_cl_hsm2k_sk_t **out_sk,
    bicycl_cl_hsm2k_pk_t **out_pk);

void bicycl_cl_hsm2k_sk_free(bicycl_cl_hsm2k_sk_t *sk);
void bicycl_cl_hsm2k_pk_free(bicycl_cl_hsm2k_pk_t *pk);
void bicycl_cl_hsm2k_ct_free(bicycl_cl_hsm2k_ct_t *ct);

bicycl_status_t bicycl_cl_hsm2k_encrypt_decimal(
    bicycl_context_t *ctx,
    const bicycl_cl_hsm2k_t *cl,
    const bicycl_cl_hsm2k_pk_t *pk,
    bicycl_randgen_t *randgen,
    const char *message_decimal,
    bicycl_cl_hsm2k_ct_t **out_ct);

bicycl_status_t bicycl_cl_hsm2k_decrypt_decimal(
    bicycl_context_t *ctx,
    const bicycl_cl_hsm2k_t *cl,
    const bicycl_cl_hsm2k_sk_t *sk,
    const bicycl_cl_hsm2k_ct_t *ct,
    char *out_buf,
    size_t *inout_len);

bicycl_status_t bicycl_cl_hsm2k_add_ciphertexts(
    bicycl_context_t *ctx,
    const bicycl_cl_hsm2k_t *cl,
    const bicycl_cl_hsm2k_pk_t *pk,
    bicycl_randgen_t *randgen,
    const bicycl_cl_hsm2k_ct_t *ca,
    const bicycl_cl_hsm2k_ct_t *cb,
    bicycl_cl_hsm2k_ct_t **out_ct);

bicycl_status_t bicycl_cl_hsm2k_scal_ciphertext_decimal(
    bicycl_context_t *ctx,
    const bicycl_cl_hsm2k_t *cl,
    const bicycl_cl_hsm2k_pk_t *pk,
    bicycl_randgen_t *randgen,
    const bicycl_cl_hsm2k_ct_t *ct,
    const char *scalar_decimal,
    bicycl_cl_hsm2k_ct_t **out_ct);

bicycl_status_t bicycl_cl_hsm2k_addscal_ciphertexts_decimal(
    bicycl_context_t *ctx,
    const bicycl_cl_hsm2k_t *cl,
    const bicycl_cl_hsm2k_pk_t *pk,
    bicycl_randgen_t *randgen,
    const bicycl_cl_hsm2k_ct_t *ca,
    const bicycl_cl_hsm2k_ct_t *cb,
    const char *scalar_decimal,
    bicycl_cl_hsm2k_ct_t **out_ct);

bicycl_status_t bicycl_ecdsa_new(
    bicycl_context_t *ctx,
    uint32_t seclevel_bits,
    bicycl_ecdsa_t **out_ecdsa);
void bicycl_ecdsa_free(bicycl_ecdsa_t *ecdsa);

bicycl_status_t bicycl_ecdsa_keygen(
    bicycl_context_t *ctx,
    const bicycl_ecdsa_t *ecdsa,
    bicycl_randgen_t *randgen,
    bicycl_ecdsa_sk_t **out_sk,
    bicycl_ecdsa_pk_t **out_pk);
void bicycl_ecdsa_sk_free(bicycl_ecdsa_sk_t *sk);
void bicycl_ecdsa_pk_free(bicycl_ecdsa_pk_t *pk);

bicycl_status_t bicycl_ecdsa_sign_message(
    bicycl_context_t *ctx,
    const bicycl_ecdsa_t *ecdsa,
    bicycl_randgen_t *randgen,
    const bicycl_ecdsa_sk_t *sk,
    const uint8_t *msg_ptr,
    size_t msg_len,
    bicycl_ecdsa_sig_t **out_sig);
void bicycl_ecdsa_sig_free(bicycl_ecdsa_sig_t *sig);

bicycl_status_t bicycl_ecdsa_verify_message(
    bicycl_context_t *ctx,
    const bicycl_ecdsa_t *ecdsa,
    const bicycl_ecdsa_pk_t *pk,
    const uint8_t *msg_ptr,
    size_t msg_len,
    const bicycl_ecdsa_sig_t *sig,
    int *out_valid);

bicycl_status_t bicycl_ecdsa_sig_r_decimal(
    bicycl_context_t *ctx,
    const bicycl_ecdsa_sig_t *sig,
    char *out_buf,
    size_t *inout_len);

bicycl_status_t bicycl_ecdsa_sig_s_decimal(
    bicycl_context_t *ctx,
    const bicycl_ecdsa_sig_t *sig,
    char *out_buf,
    size_t *inout_len);

bicycl_status_t bicycl_two_party_ecdsa_run_demo(
    bicycl_context_t *ctx,
    bicycl_randgen_t *randgen,
    uint32_t seclevel_bits,
    const uint8_t *msg_ptr,
    size_t msg_len,
    int *out_valid);

bicycl_status_t bicycl_two_party_ecdsa_session_new(
    bicycl_context_t *ctx,
    bicycl_randgen_t *randgen,
    uint32_t seclevel_bits,
    bicycl_two_party_ecdsa_session_t **out_session);
void bicycl_two_party_ecdsa_session_free(bicycl_two_party_ecdsa_session_t *session);
bicycl_status_t bicycl_two_party_ecdsa_keygen_round1(
    bicycl_context_t *ctx,
    bicycl_two_party_ecdsa_session_t *session,
    bicycl_randgen_t *randgen);
bicycl_status_t bicycl_two_party_ecdsa_keygen_round2(
    bicycl_context_t *ctx,
    bicycl_two_party_ecdsa_session_t *session,
    bicycl_randgen_t *randgen);
bicycl_status_t bicycl_two_party_ecdsa_keygen_round3(
    bicycl_context_t *ctx,
    bicycl_two_party_ecdsa_session_t *session,
    bicycl_randgen_t *randgen);
bicycl_status_t bicycl_two_party_ecdsa_keygen_round4(
    bicycl_context_t *ctx,
    bicycl_two_party_ecdsa_session_t *session);
bicycl_status_t bicycl_two_party_ecdsa_sign_round1(
    bicycl_context_t *ctx,
    bicycl_two_party_ecdsa_session_t *session,
    bicycl_randgen_t *randgen,
    const uint8_t *msg_ptr,
    size_t msg_len);
bicycl_status_t bicycl_two_party_ecdsa_sign_round2(
    bicycl_context_t *ctx,
    bicycl_two_party_ecdsa_session_t *session,
    bicycl_randgen_t *randgen);
bicycl_status_t bicycl_two_party_ecdsa_sign_round3(
    bicycl_context_t *ctx,
    bicycl_two_party_ecdsa_session_t *session);
bicycl_status_t bicycl_two_party_ecdsa_sign_round4(
    bicycl_context_t *ctx,
    bicycl_two_party_ecdsa_session_t *session,
    bicycl_randgen_t *randgen);
bicycl_status_t bicycl_two_party_ecdsa_sign_finalize(
    bicycl_context_t *ctx,
    bicycl_two_party_ecdsa_session_t *session,
    int *out_valid);

bicycl_status_t bicycl_cl_threshold_run_demo(
    bicycl_context_t *ctx,
    bicycl_randgen_t *randgen,
    char *out_buf,
    size_t *inout_len);

bicycl_status_t bicycl_cl_dlog_proof_run_demo(
    bicycl_context_t *ctx,
    bicycl_randgen_t *randgen,
    uint32_t seclevel_bits,
    int *out_valid);

bicycl_status_t bicycl_threshold_ecdsa_run_demo(
    bicycl_context_t *ctx,
    bicycl_randgen_t *randgen,
    uint32_t seclevel_bits,
    const uint8_t *msg_ptr,
    size_t msg_len,
    int *out_valid);

bicycl_status_t bicycl_cl_dlog_session_new(
    bicycl_context_t *ctx,
    bicycl_randgen_t *randgen,
    uint32_t seclevel_bits,
    bicycl_cl_dlog_session_t **out_session);
void bicycl_cl_dlog_session_free(bicycl_cl_dlog_session_t *session);
bicycl_status_t bicycl_cl_dlog_session_prepare_statement(
    bicycl_context_t *ctx,
    bicycl_cl_dlog_session_t *session,
    bicycl_randgen_t *randgen);
bicycl_status_t bicycl_cl_dlog_session_prove_round(
    bicycl_context_t *ctx,
    bicycl_cl_dlog_session_t *session,
    bicycl_randgen_t *randgen);
bicycl_status_t bicycl_cl_dlog_session_verify_round(
    bicycl_context_t *ctx,
    const bicycl_cl_dlog_session_t *session,
    int *out_valid);

bicycl_status_t bicycl_cl_dlog_message_new(bicycl_cl_dlog_message_t **out_msg);
void bicycl_cl_dlog_message_free(bicycl_cl_dlog_message_t *msg);
bicycl_status_t bicycl_cl_dlog_message_export_bytes(
    bicycl_context_t *ctx,
    const bicycl_cl_dlog_message_t *msg,
    uint8_t *out_buf,
    size_t *inout_len);
bicycl_status_t bicycl_cl_dlog_message_import_bytes(
    bicycl_context_t *ctx,
    bicycl_cl_dlog_message_t *msg,
    const uint8_t *bytes,
    size_t len);

bicycl_status_t bicycl_cl_dlog_session_export_statement(
    bicycl_context_t *ctx,
    const bicycl_cl_dlog_session_t *session,
    bicycl_cl_dlog_message_t *out_msg);
bicycl_status_t bicycl_cl_dlog_session_import_statement(
    bicycl_context_t *ctx,
    bicycl_cl_dlog_session_t *session,
    const bicycl_cl_dlog_message_t *msg);
bicycl_status_t bicycl_cl_dlog_session_export_proof(
    bicycl_context_t *ctx,
    const bicycl_cl_dlog_session_t *session,
    bicycl_cl_dlog_message_t *out_msg);
bicycl_status_t bicycl_cl_dlog_session_import_proof(
    bicycl_context_t *ctx,
    bicycl_cl_dlog_session_t *session,
    const bicycl_cl_dlog_message_t *msg);

bicycl_status_t bicycl_threshold_ecdsa_session_new(
    bicycl_context_t *ctx,
    bicycl_randgen_t *randgen,
    uint32_t seclevel_bits,
    uint32_t n_players,
    uint32_t threshold_t,
    bicycl_threshold_ecdsa_session_t **out_session);
void bicycl_threshold_ecdsa_session_free(bicycl_threshold_ecdsa_session_t *session);
bicycl_status_t bicycl_threshold_ecdsa_keygen_round1(
    bicycl_context_t *ctx,
    bicycl_threshold_ecdsa_session_t *session,
    bicycl_randgen_t *randgen);
bicycl_status_t bicycl_threshold_ecdsa_keygen_round2(
    bicycl_context_t *ctx,
    bicycl_threshold_ecdsa_session_t *session,
    bicycl_randgen_t *randgen);
bicycl_status_t bicycl_threshold_ecdsa_keygen_finalize(
    bicycl_context_t *ctx,
    bicycl_threshold_ecdsa_session_t *session);
bicycl_status_t bicycl_threshold_ecdsa_sign_round1(
    bicycl_context_t *ctx,
    bicycl_threshold_ecdsa_session_t *session,
    bicycl_randgen_t *randgen,
    const uint8_t *msg_ptr,
    size_t msg_len);
bicycl_status_t bicycl_threshold_ecdsa_sign_round2(
    bicycl_context_t *ctx,
    bicycl_threshold_ecdsa_session_t *session,
    bicycl_randgen_t *randgen);
bicycl_status_t bicycl_threshold_ecdsa_sign_round3(
    bicycl_context_t *ctx,
    bicycl_threshold_ecdsa_session_t *session);
bicycl_status_t bicycl_threshold_ecdsa_sign_round4(
    bicycl_context_t *ctx,
    bicycl_threshold_ecdsa_session_t *session);
bicycl_status_t bicycl_threshold_ecdsa_sign_round5(
    bicycl_context_t *ctx,
    bicycl_threshold_ecdsa_session_t *session,
    bicycl_randgen_t *randgen);
bicycl_status_t bicycl_threshold_ecdsa_sign_round6(
    bicycl_context_t *ctx,
    bicycl_threshold_ecdsa_session_t *session,
    bicycl_randgen_t *randgen);
bicycl_status_t bicycl_threshold_ecdsa_sign_round7(
    bicycl_context_t *ctx,
    bicycl_threshold_ecdsa_session_t *session,
    bicycl_randgen_t *randgen);
bicycl_status_t bicycl_threshold_ecdsa_sign_round8(
    bicycl_context_t *ctx,
    bicycl_threshold_ecdsa_session_t *session);
bicycl_status_t bicycl_threshold_ecdsa_sign_finalize(
    bicycl_context_t *ctx,
    bicycl_threshold_ecdsa_session_t *session);
bicycl_status_t bicycl_threshold_ecdsa_signature_valid(
    bicycl_context_t *ctx,
    const bicycl_threshold_ecdsa_session_t *session,
    int *out_valid);

#ifdef __cplusplus
}
#endif

#endif
