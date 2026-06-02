#include "bicycl_capi.h"

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
  assert(bicycl_get_abi_version() == BICYCL_CAPI_VERSION);
  assert(bicycl_get_version() != NULL);
  assert(strlen(bicycl_get_version()) > 0u);
  assert(strcmp(bicycl_status_message(BICYCL_OK), "ok") == 0);

  bicycl_context_t *ctx = NULL;
  assert(bicycl_context_new(&ctx) == BICYCL_OK);
  assert(ctx != NULL);
  assert(strcmp(bicycl_context_last_error(ctx), "") == 0);

  bicycl_randgen_t *rng = NULL;
  assert(bicycl_randgen_new_from_seed_decimal(ctx, "1337", &rng) == BICYCL_OK);

  bicycl_classgroup_t *cg = NULL;
  assert(bicycl_classgroup_new_from_discriminant_decimal(ctx, "-23", &cg) == BICYCL_OK);

  bicycl_qfi_t *one = NULL;
  assert(bicycl_classgroup_one(ctx, cg, &one) == BICYCL_OK);

  int is_one = 0;
  assert(bicycl_qfi_is_one(ctx, one, &is_one) == BICYCL_OK);
  assert(is_one == 1);

  bicycl_qfi_t *dup = NULL;
  assert(bicycl_classgroup_nudupl(ctx, cg, one, &dup) == BICYCL_OK);
  assert(bicycl_qfi_is_one(ctx, dup, &is_one) == BICYCL_OK);
  assert(is_one == 1);

  char disc_buf[64];
  size_t disc_len = sizeof(disc_buf);
  assert(bicycl_qfi_discriminant_decimal(ctx, one, disc_buf, &disc_len) == BICYCL_OK);
  assert(strcmp(disc_buf, "-23") == 0);

  bicycl_paillier_t *paillier = NULL;
  assert(bicycl_paillier_new(ctx, 64, &paillier) == BICYCL_OK);

  bicycl_paillier_sk_t *sk = NULL;
  bicycl_paillier_pk_t *pk = NULL;
  assert(bicycl_paillier_keygen(ctx, paillier, rng, &sk, &pk) == BICYCL_OK);

  bicycl_paillier_ct_t *ct = NULL;
  assert(bicycl_paillier_encrypt_decimal(ctx, paillier, pk, rng, "42", &ct) == BICYCL_OK);

  char m_buf[128];
  size_t m_len = sizeof(m_buf);
  assert(bicycl_paillier_decrypt_decimal(ctx, paillier, pk, sk, ct, m_buf, &m_len) == BICYCL_OK);
  assert(strcmp(m_buf, "42") == 0);

  bicycl_joye_libert_t *jl = NULL;
  assert(bicycl_joye_libert_new(ctx, 64, 8, &jl) == BICYCL_OK);
  bicycl_joye_libert_sk_t *jl_sk = NULL;
  bicycl_joye_libert_pk_t *jl_pk = NULL;
  assert(bicycl_joye_libert_keygen(ctx, jl, rng, &jl_sk, &jl_pk) == BICYCL_OK);
  bicycl_joye_libert_ct_t *jl_ct = NULL;
  assert(bicycl_joye_libert_encrypt_decimal(ctx, jl, jl_pk, rng, "7", &jl_ct) == BICYCL_OK);

  char jl_buf[128];
  size_t jl_len = sizeof(jl_buf);
  assert(bicycl_joye_libert_decrypt_decimal(ctx, jl, jl_sk, jl_ct, jl_buf, &jl_len) == BICYCL_OK);
  assert(strcmp(jl_buf, "7") == 0);

  bicycl_joye_libert_ct_free(jl_ct);
  bicycl_joye_libert_pk_free(jl_pk);
  bicycl_joye_libert_sk_free(jl_sk);
  bicycl_joye_libert_free(jl);

  bicycl_cl_hsmqk_t *cl = NULL;
  assert(bicycl_cl_hsmqk_new(ctx, "3", 1, "5", &cl) == BICYCL_OK);
  bicycl_cl_hsmqk_sk_t *cl_sk = NULL;
  bicycl_cl_hsmqk_pk_t *cl_pk = NULL;
  assert(bicycl_cl_hsmqk_keygen(ctx, cl, rng, &cl_sk, &cl_pk) == BICYCL_OK);
  bicycl_cl_hsmqk_ct_t *cl_ct = NULL;
  assert(bicycl_cl_hsmqk_encrypt_decimal(ctx, cl, cl_pk, rng, "2", &cl_ct) == BICYCL_OK);
  bicycl_cl_hsmqk_ct_t *cl_ct_add = NULL;
  bicycl_cl_hsmqk_ct_t *cl_ct_scal = NULL;
  bicycl_cl_hsmqk_ct_t *cl_ct_addscal = NULL;
  assert(bicycl_cl_hsmqk_add_ciphertexts(ctx, cl, cl_pk, rng, cl_ct, cl_ct, &cl_ct_add) == BICYCL_OK);
  assert(bicycl_cl_hsmqk_scal_ciphertext_decimal(ctx, cl, cl_pk, rng, cl_ct, "3", &cl_ct_scal) == BICYCL_OK);
  assert(bicycl_cl_hsmqk_addscal_ciphertexts_decimal(ctx, cl, cl_pk, rng, cl_ct, cl_ct, "2", &cl_ct_addscal) == BICYCL_OK);
  char cl_buf[128];
  size_t cl_len = sizeof(cl_buf);
  assert(bicycl_cl_hsmqk_decrypt_decimal(ctx, cl, cl_sk, cl_ct, cl_buf, &cl_len) == BICYCL_OK);
  assert(strcmp(cl_buf, "2") == 0);
  cl_len = sizeof(cl_buf);
  assert(bicycl_cl_hsmqk_decrypt_decimal(ctx, cl, cl_sk, cl_ct_add, cl_buf, &cl_len) == BICYCL_OK);
  assert(strcmp(cl_buf, "1") == 0);
  cl_len = sizeof(cl_buf);
  assert(bicycl_cl_hsmqk_decrypt_decimal(ctx, cl, cl_sk, cl_ct_scal, cl_buf, &cl_len) == BICYCL_OK);
  assert(strcmp(cl_buf, "0") == 0);
  cl_len = sizeof(cl_buf);
  assert(bicycl_cl_hsmqk_decrypt_decimal(ctx, cl, cl_sk, cl_ct_addscal, cl_buf, &cl_len) == BICYCL_OK);
  assert(strcmp(cl_buf, "0") == 0);
  bicycl_cl_hsmqk_ct_free(cl_ct_addscal);
  bicycl_cl_hsmqk_ct_free(cl_ct_scal);
  bicycl_cl_hsmqk_ct_free(cl_ct_add);
  bicycl_cl_hsmqk_ct_free(cl_ct);
  bicycl_cl_hsmqk_pk_free(cl_pk);
  bicycl_cl_hsmqk_sk_free(cl_sk);
  bicycl_cl_hsmqk_free(cl);

  bicycl_cl_hsm2k_t *cl2 = NULL;
  assert(bicycl_cl_hsm2k_new(ctx, "15", 3, &cl2) == BICYCL_OK);
  bicycl_cl_hsm2k_sk_t *cl2_sk = NULL;
  bicycl_cl_hsm2k_pk_t *cl2_pk = NULL;
  assert(bicycl_cl_hsm2k_keygen(ctx, cl2, rng, &cl2_sk, &cl2_pk) == BICYCL_OK);
  bicycl_cl_hsm2k_ct_t *cl2_ct = NULL;
  assert(bicycl_cl_hsm2k_encrypt_decimal(ctx, cl2, cl2_pk, rng, "5", &cl2_ct) == BICYCL_OK);
  bicycl_cl_hsm2k_ct_t *cl2_ct_add = NULL;
  bicycl_cl_hsm2k_ct_t *cl2_ct_scal = NULL;
  bicycl_cl_hsm2k_ct_t *cl2_ct_addscal = NULL;
  assert(bicycl_cl_hsm2k_add_ciphertexts(ctx, cl2, cl2_pk, rng, cl2_ct, cl2_ct, &cl2_ct_add) == BICYCL_OK);
  assert(bicycl_cl_hsm2k_scal_ciphertext_decimal(ctx, cl2, cl2_pk, rng, cl2_ct, "3", &cl2_ct_scal) == BICYCL_OK);
  assert(bicycl_cl_hsm2k_addscal_ciphertexts_decimal(ctx, cl2, cl2_pk, rng, cl2_ct, cl2_ct, "2", &cl2_ct_addscal) == BICYCL_OK);
  char cl2_buf[128];
  size_t cl2_len = sizeof(cl2_buf);
  assert(bicycl_cl_hsm2k_decrypt_decimal(ctx, cl2, cl2_sk, cl2_ct, cl2_buf, &cl2_len) == BICYCL_OK);
  assert(strcmp(cl2_buf, "5") == 0);
  cl2_len = sizeof(cl2_buf);
  assert(bicycl_cl_hsm2k_decrypt_decimal(ctx, cl2, cl2_sk, cl2_ct_add, cl2_buf, &cl2_len) == BICYCL_OK);
  assert(strcmp(cl2_buf, "2") == 0);
  cl2_len = sizeof(cl2_buf);
  assert(bicycl_cl_hsm2k_decrypt_decimal(ctx, cl2, cl2_sk, cl2_ct_scal, cl2_buf, &cl2_len) == BICYCL_OK);
  assert(strcmp(cl2_buf, "7") == 0);
  cl2_len = sizeof(cl2_buf);
  assert(bicycl_cl_hsm2k_decrypt_decimal(ctx, cl2, cl2_sk, cl2_ct_addscal, cl2_buf, &cl2_len) == BICYCL_OK);
  assert(strcmp(cl2_buf, "7") == 0);
  bicycl_cl_hsm2k_ct_free(cl2_ct_addscal);
  bicycl_cl_hsm2k_ct_free(cl2_ct_scal);
  bicycl_cl_hsm2k_ct_free(cl2_ct_add);
  bicycl_cl_hsm2k_ct_free(cl2_ct);
  bicycl_cl_hsm2k_pk_free(cl2_pk);
  bicycl_cl_hsm2k_sk_free(cl2_sk);
  bicycl_cl_hsm2k_free(cl2);

  bicycl_ecdsa_t *ecdsa = NULL;
  assert(bicycl_ecdsa_new(ctx, 112, &ecdsa) == BICYCL_OK);
  bicycl_ecdsa_sk_t *ecdsa_sk = NULL;
  bicycl_ecdsa_pk_t *ecdsa_pk = NULL;
  assert(bicycl_ecdsa_keygen(ctx, ecdsa, rng, &ecdsa_sk, &ecdsa_pk) == BICYCL_OK);
  const uint8_t msg_ok[] = {'a', 'b', 'c'};
  bicycl_ecdsa_sig_t *ecdsa_sig = NULL;
  assert(bicycl_ecdsa_sign_message(ctx, ecdsa, rng, ecdsa_sk, msg_ok, sizeof(msg_ok), &ecdsa_sig) == BICYCL_OK);
  int valid = 0;
  assert(bicycl_ecdsa_verify_message(ctx, ecdsa, ecdsa_pk, msg_ok, sizeof(msg_ok), ecdsa_sig, &valid) == BICYCL_OK);
  assert(valid == 1);
  const uint8_t msg_bad[] = {'a', 'b', 'd'};
  assert(bicycl_ecdsa_verify_message(ctx, ecdsa, ecdsa_pk, msg_bad, sizeof(msg_bad), ecdsa_sig, &valid) == BICYCL_OK);
  assert(valid == 0);
  char sig_buf[256];
  size_t sig_len = sizeof(sig_buf);
  assert(bicycl_ecdsa_sig_r_decimal(ctx, ecdsa_sig, sig_buf, &sig_len) == BICYCL_OK);
  assert(strlen(sig_buf) > 0);
  sig_len = sizeof(sig_buf);
  assert(bicycl_ecdsa_sig_s_decimal(ctx, ecdsa_sig, sig_buf, &sig_len) == BICYCL_OK);
  assert(strlen(sig_buf) > 0);
  bicycl_ecdsa_sig_free(ecdsa_sig);
  bicycl_ecdsa_pk_free(ecdsa_pk);
  bicycl_ecdsa_sk_free(ecdsa_sk);
  bicycl_ecdsa_free(ecdsa);

  bicycl_two_party_ecdsa_session_t *tp_session = NULL;
  assert(bicycl_two_party_ecdsa_session_new(ctx, rng, 112, &tp_session) == BICYCL_OK);
  assert(bicycl_two_party_ecdsa_keygen_round1(ctx, tp_session, rng) == BICYCL_OK);
  assert(bicycl_two_party_ecdsa_keygen_round2(ctx, tp_session, rng) == BICYCL_OK);
  assert(bicycl_two_party_ecdsa_keygen_round3(ctx, tp_session, rng) == BICYCL_OK);
  assert(bicycl_two_party_ecdsa_keygen_round4(ctx, tp_session) == BICYCL_OK);
  assert(bicycl_two_party_ecdsa_sign_round1(ctx, tp_session, rng, msg_ok, sizeof(msg_ok)) == BICYCL_OK);
  assert(bicycl_two_party_ecdsa_sign_round2(ctx, tp_session, rng) == BICYCL_OK);
  assert(bicycl_two_party_ecdsa_sign_round3(ctx, tp_session) == BICYCL_OK);
  assert(bicycl_two_party_ecdsa_sign_round4(ctx, tp_session, rng) == BICYCL_OK);
  int tp_state_valid = 0;
  assert(bicycl_two_party_ecdsa_sign_finalize(ctx, tp_session, &tp_state_valid) == BICYCL_OK);
  assert(tp_state_valid == 1);
  bicycl_two_party_ecdsa_session_free(tp_session);

  bicycl_cl_dlog_session_t *dlog_session = NULL;
  assert(bicycl_cl_dlog_session_new(ctx, rng, 112, &dlog_session) == BICYCL_OK);
  assert(bicycl_cl_dlog_session_prepare_statement(ctx, dlog_session, rng) == BICYCL_OK);
  assert(bicycl_cl_dlog_session_prove_round(ctx, dlog_session, rng) == BICYCL_OK);
  int dlog_round_valid = 0;
  assert(bicycl_cl_dlog_session_verify_round(ctx, dlog_session, &dlog_round_valid) == BICYCL_OK);
  assert(dlog_round_valid == 1);

  bicycl_cl_dlog_message_t *stmt_msg = NULL;
  bicycl_cl_dlog_message_t *proof_msg = NULL;
  assert(bicycl_cl_dlog_message_new(&stmt_msg) == BICYCL_OK);
  assert(bicycl_cl_dlog_message_new(&proof_msg) == BICYCL_OK);
  assert(bicycl_cl_dlog_session_export_statement(ctx, dlog_session, stmt_msg) == BICYCL_OK);
  assert(bicycl_cl_dlog_session_export_proof(ctx, dlog_session, proof_msg) == BICYCL_OK);

  size_t stmt_len = 0;
  assert(bicycl_cl_dlog_message_export_bytes(ctx, stmt_msg, NULL, &stmt_len) == BICYCL_ERR_BUFFER_TOO_SMALL);
  uint8_t *stmt_buf = (uint8_t *)malloc(stmt_len);
  assert(stmt_buf != NULL);
  assert(bicycl_cl_dlog_message_export_bytes(ctx, stmt_msg, stmt_buf, &stmt_len) == BICYCL_OK);

  size_t proof_len = 0;
  assert(bicycl_cl_dlog_message_export_bytes(ctx, proof_msg, NULL, &proof_len) == BICYCL_ERR_BUFFER_TOO_SMALL);
  uint8_t *proof_buf = (uint8_t *)malloc(proof_len);
  assert(proof_buf != NULL);
  assert(bicycl_cl_dlog_message_export_bytes(ctx, proof_msg, proof_buf, &proof_len) == BICYCL_OK);

  bicycl_cl_dlog_session_t *dlog_verifier = NULL;
  bicycl_cl_dlog_message_t *stmt_msg_rx = NULL;
  bicycl_cl_dlog_message_t *proof_msg_rx = NULL;
  assert(bicycl_cl_dlog_session_new(ctx, rng, 112, &dlog_verifier) == BICYCL_OK);
  assert(bicycl_cl_dlog_message_new(&stmt_msg_rx) == BICYCL_OK);
  assert(bicycl_cl_dlog_message_new(&proof_msg_rx) == BICYCL_OK);
  assert(bicycl_cl_dlog_message_import_bytes(ctx, stmt_msg_rx, stmt_buf, stmt_len) == BICYCL_OK);
  assert(bicycl_cl_dlog_message_import_bytes(ctx, proof_msg_rx, proof_buf, proof_len) == BICYCL_OK);
  assert(bicycl_cl_dlog_session_import_statement(ctx, dlog_verifier, stmt_msg_rx) == BICYCL_OK);
  assert(bicycl_cl_dlog_session_import_proof(ctx, dlog_verifier, proof_msg_rx) == BICYCL_OK);
  int dlog_net_valid = 0;
  assert(bicycl_cl_dlog_session_verify_round(ctx, dlog_verifier, &dlog_net_valid) == BICYCL_OK);
  assert(dlog_net_valid == 1);

  free(stmt_buf);
  free(proof_buf);
  bicycl_cl_dlog_message_free(stmt_msg_rx);
  bicycl_cl_dlog_message_free(proof_msg_rx);
  bicycl_cl_dlog_session_free(dlog_verifier);
  bicycl_cl_dlog_message_free(stmt_msg);
  bicycl_cl_dlog_message_free(proof_msg);
  bicycl_cl_dlog_session_free(dlog_session);

  bicycl_threshold_ecdsa_session_t *th_session = NULL;
  assert(bicycl_threshold_ecdsa_session_new(ctx, rng, 112, 2, 1, &th_session) == BICYCL_OK);
  assert(bicycl_threshold_ecdsa_keygen_round1(ctx, th_session, rng) == BICYCL_OK);
  assert(bicycl_threshold_ecdsa_keygen_round2(ctx, th_session, rng) == BICYCL_OK);
  assert(bicycl_threshold_ecdsa_keygen_finalize(ctx, th_session) == BICYCL_OK);
  assert(bicycl_threshold_ecdsa_sign_round1(ctx, th_session, rng, msg_ok, sizeof(msg_ok)) == BICYCL_OK);
  assert(bicycl_threshold_ecdsa_sign_round2(ctx, th_session, rng) == BICYCL_OK);
  assert(bicycl_threshold_ecdsa_sign_round3(ctx, th_session) == BICYCL_OK);
  assert(bicycl_threshold_ecdsa_sign_round4(ctx, th_session) == BICYCL_OK);
  assert(bicycl_threshold_ecdsa_sign_round5(ctx, th_session, rng) == BICYCL_OK);
  assert(bicycl_threshold_ecdsa_sign_round6(ctx, th_session, rng) == BICYCL_OK);
  assert(bicycl_threshold_ecdsa_sign_round7(ctx, th_session, rng) == BICYCL_OK);
  assert(bicycl_threshold_ecdsa_sign_round8(ctx, th_session) == BICYCL_OK);
  assert(bicycl_threshold_ecdsa_sign_finalize(ctx, th_session) == BICYCL_OK);
  int th_round_valid = 0;
  assert(bicycl_threshold_ecdsa_signature_valid(ctx, th_session, &th_round_valid) == BICYCL_OK);
  assert(th_round_valid == 1);
  bicycl_threshold_ecdsa_session_free(th_session);

  bicycl_paillier_ct_free(ct);
  bicycl_paillier_pk_free(pk);
  bicycl_paillier_sk_free(sk);
  bicycl_paillier_free(paillier);
  bicycl_qfi_free(dup);
  bicycl_qfi_free(one);
  bicycl_classgroup_free(cg);
  bicycl_randgen_free(rng);

  unsigned char buf[4] = {1, 2, 3, 4};
  bicycl_zeroize(buf, sizeof(buf));
  for (size_t i = 0; i < sizeof(buf); ++i) {
    assert(buf[i] == 0u);
  }

  bicycl_context_clear_error(ctx);
  bicycl_context_free(ctx);
  return 0;
}
