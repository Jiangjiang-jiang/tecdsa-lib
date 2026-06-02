#include "bicycl_capi.h"

#include <new>
#include <numeric>
#include <memory>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "bicycl.hpp"

struct bicycl_context_t {
  std::string last_error;
};

struct bicycl_randgen_t {
  explicit bicycl_randgen_t(const BICYCL::Mpz &seed) : value(seed) {}
  BICYCL::RandGen value;
};

struct bicycl_classgroup_t {
  explicit bicycl_classgroup_t(const BICYCL::Mpz &disc) : value(disc) {}
  BICYCL::ClassGroup value;
};

struct bicycl_qfi_t {
  explicit bicycl_qfi_t(const BICYCL::QFI &qfi) : value(qfi) {}
  BICYCL::QFI value;
};

struct bicycl_paillier_t {
  explicit bicycl_paillier_t(const size_t modulus_bits) : value(modulus_bits) {}
  BICYCL::Paillier value;
};

struct bicycl_paillier_sk_t {
  explicit bicycl_paillier_sk_t(const BICYCL::Paillier::SecretKey &sk) : value(sk) {}
  BICYCL::Paillier::SecretKey value;
};

struct bicycl_paillier_pk_t {
  explicit bicycl_paillier_pk_t(const BICYCL::Paillier::PublicKey &pk) : value(pk) {}
  BICYCL::Paillier::PublicKey value;
};

struct bicycl_paillier_ct_t {
  explicit bicycl_paillier_ct_t(const BICYCL::Paillier::CipherText &ct) : value(ct) {}
  BICYCL::Paillier::CipherText value;
};

struct bicycl_joye_libert_t {
  bicycl_joye_libert_t(const size_t modulus_bits, const size_t k) : value(modulus_bits, k) {}
  BICYCL::JoyeLibert value;
};

struct bicycl_joye_libert_sk_t {
  explicit bicycl_joye_libert_sk_t(const BICYCL::JoyeLibert::SecretKey &sk) : value(sk) {}
  BICYCL::JoyeLibert::SecretKey value;
};

struct bicycl_joye_libert_pk_t {
  explicit bicycl_joye_libert_pk_t(const BICYCL::JoyeLibert::PublicKey &pk) : value(pk) {}
  BICYCL::JoyeLibert::PublicKey value;
};

struct bicycl_joye_libert_ct_t {
  explicit bicycl_joye_libert_ct_t(const BICYCL::JoyeLibert::CipherText &ct) : value(ct) {}
  BICYCL::JoyeLibert::CipherText value;
};

struct bicycl_cl_hsmqk_t {
  bicycl_cl_hsmqk_t(const BICYCL::Mpz &q, const size_t k, const BICYCL::Mpz &p) : value(q, k, p) {}
  BICYCL::CL_HSMqk value;
};

struct bicycl_cl_hsmqk_sk_t {
  explicit bicycl_cl_hsmqk_sk_t(const BICYCL::CL_HSMqk::SecretKey &sk) : value(sk) {}
  BICYCL::CL_HSMqk::SecretKey value;
};

struct bicycl_cl_hsmqk_pk_t {
  explicit bicycl_cl_hsmqk_pk_t(const BICYCL::CL_HSMqk::PublicKey &pk) : value(pk) {}
  BICYCL::CL_HSMqk::PublicKey value;
};

struct bicycl_cl_hsmqk_ct_t {
  explicit bicycl_cl_hsmqk_ct_t(const BICYCL::CL_HSMqk::CipherText &ct) : value(ct) {}
  BICYCL::CL_HSMqk::CipherText value;
};

struct bicycl_cl_hsm2k_t {
  bicycl_cl_hsm2k_t(const BICYCL::Mpz &N, const size_t k) : value(N, k) {}
  BICYCL::CL_HSM2k value;
};

struct bicycl_cl_hsm2k_sk_t {
  explicit bicycl_cl_hsm2k_sk_t(const BICYCL::CL_HSM2k::SecretKey &sk) : value(sk) {}
  BICYCL::CL_HSM2k::SecretKey value;
};

struct bicycl_cl_hsm2k_pk_t {
  explicit bicycl_cl_hsm2k_pk_t(const BICYCL::CL_HSM2k::PublicKey &pk) : value(pk) {}
  BICYCL::CL_HSM2k::PublicKey value;
};

struct bicycl_cl_hsm2k_ct_t {
  explicit bicycl_cl_hsm2k_ct_t(const BICYCL::CL_HSM2k::CipherText &ct) : value(ct) {}
  BICYCL::CL_HSM2k::CipherText value;
};

struct bicycl_ecdsa_t {
  explicit bicycl_ecdsa_t(const BICYCL::SecLevel &seclevel) : value(seclevel) {}
  BICYCL::ECDSA value;
};

struct bicycl_ecdsa_sk_t {
  explicit bicycl_ecdsa_sk_t(BICYCL::ECDSA::SecretKey &&sk) : value(std::move(sk)) {}
  BICYCL::ECDSA::SecretKey value;
};

struct bicycl_ecdsa_pk_t {
  explicit bicycl_ecdsa_pk_t(BICYCL::ECDSA::PublicKey &&pk) : value(std::move(pk)) {}
  BICYCL::ECDSA::PublicKey value;
};

struct bicycl_ecdsa_sig_t {
  explicit bicycl_ecdsa_sig_t(const BICYCL::ECDSA::Signature &sig) : value(sig) {}
  BICYCL::ECDSA::Signature value;
};

struct bicycl_two_party_ecdsa_session_t {
  explicit bicycl_two_party_ecdsa_session_t(const BICYCL::SecLevel &seclevel, BICYCL::RandGen &randgen)
      : context(new BICYCL::TwoPartyECDSA(seclevel, randgen)),
        p1(new BICYCL::TwoPartyECDSA::Player1(*context)),
        p2(new BICYCL::TwoPartyECDSA::Player2(*context)) {}

  std::unique_ptr<BICYCL::TwoPartyECDSA> context;
  std::unique_ptr<BICYCL::TwoPartyECDSA::Player1> p1;
  std::unique_ptr<BICYCL::TwoPartyECDSA::Player2> p2;
  std::unique_ptr<BICYCL::HashAlgo::Digest> hashed;
  std::unique_ptr<BICYCL::Mpz> sid;
  std::unique_ptr<BICYCL::ECSignature> signature;
  unsigned int stage = 0;
};

struct bicycl_cl_dlog_session_t {
  bicycl_cl_dlog_session_t(const BICYCL::SecLevel &seclevel, BICYCL::RandGen &randgen)
      : context(seclevel, randgen) {}

  BICYCL::TwoPartyECDSA context;
  std::unique_ptr<BICYCL::CL_HSMqk::PublicKey> pk;
  std::unique_ptr<BICYCL::ECPoint> q;
  std::unique_ptr<BICYCL::CL_HSMqk::CipherText> c;
  std::unique_ptr<BICYCL::BN> witness_a;
  std::unique_ptr<BICYCL::Mpz> witness_rnd;
  std::unique_ptr<BICYCL::CLDLZKProof> proof;
  std::unique_ptr<BICYCL::CL_HSMqk> imported_cl;
};

struct bicycl_cl_dlog_message_t {
  std::string bytes;
};

struct bicycl_threshold_ecdsa_session_t {
  using TE = BICYCL::thresholdECDSA;
  using Keygen1 = TE::KeygenPart1;
  using Keygen2 = TE::KeygenPart2;
  using SecretKey = TE::SecretKey;
  using Sign1 = TE::SignPart1;
  using Sign2 = TE::SignPart2;
  using Sign3 = TE::SignPart3;
  using Sign4 = TE::SignPart4;
  using Sign5 = TE::SignPart5;
  using Sign6 = TE::SignPart6;
  using Sign7 = TE::SignPart7;
  using Sign8 = TE::SignPart8;
  using Signature = TE::Signature;

  bicycl_threshold_ecdsa_session_t(
      const BICYCL::SecLevel &seclevel,
      BICYCL::RandGen &randgen,
      unsigned int in_n,
      unsigned int in_t)
      : context(seclevel, randgen), n(in_n), t(in_t), signers() {
    for (unsigned int i = 0; i < t + 1; ++i) {
      signers.push_back(i);
    }
  }

  BICYCL::thresholdECDSA context;
  unsigned int n;
  unsigned int t;
  TE::ParticipantsList signers;
  unsigned int stage = 0;

  std::vector<Keygen1> data1;
  std::vector<Keygen2> data2;
  std::vector<SecretKey> sk;
  std::vector<std::vector<BICYCL::ECPoint>> v;
  std::unique_ptr<BICYCL::HashAlgo::Digest> hashed;

  TE::ParticipantsMap<Sign1> s1;
  TE::ParticipantsMap<Sign2> s2;
  TE::ParticipantsMap<Sign3> s3;
  TE::ParticipantsMap<Sign4> s4;
  TE::ParticipantsMap<Sign5> s5;
  TE::ParticipantsMap<Sign6> s6;
  TE::ParticipantsMap<Sign7> s7;
  TE::ParticipantsMap<Sign8> s8;
  TE::ParticipantsMap<Signature> signatures;
};

namespace {
constexpr const char *kVersion = "0.2.0-dev";

const char *status_to_message(const bicycl_status_t status) {
  switch (status) {
    case BICYCL_OK:
      return "ok";
    case BICYCL_ERR_NULL_PTR:
      return "null pointer";
    case BICYCL_ERR_INVALID_ARGUMENT:
      return "invalid argument";
    case BICYCL_ERR_ALLOCATION_FAILED:
      return "allocation failed";
    case BICYCL_ERR_INTERNAL:
      return "internal error";
    case BICYCL_ERR_BUFFER_TOO_SMALL:
      return "buffer too small";
    case BICYCL_ERR_PARSE:
      return "parse error";
    case BICYCL_ERR_INVALID_STATE:
      return "invalid protocol state";
    case BICYCL_ERR_VERIFY_FAILED:
      return "verification failed";
    case BICYCL_ERR_PROTOCOL_ABORT:
      return "protocol aborted";
    case BICYCL_ERR_CORE:
      return "core math/runtime module error";
    case BICYCL_ERR_PAILLIER:
      return "Paillier module error";
    case BICYCL_ERR_JOYE_LIBERT:
      return "Joye-Libert module error";
    case BICYCL_ERR_CL_HSMQK:
      return "CL_HSMqk module error";
    case BICYCL_ERR_CL_HSM2K:
      return "CL_HSM2k module error";
    case BICYCL_ERR_ECDSA:
      return "ECDSA module error";
    case BICYCL_ERR_TWO_PARTY_ECDSA:
      return "TwoPartyECDSA module error";
    case BICYCL_ERR_CL_THRESHOLD:
      return "CL threshold module error";
    case BICYCL_ERR_CL_DLOG:
      return "CL DLog module error";
    case BICYCL_ERR_THRESHOLD_ECDSA:
      return "threshold ECDSA module error";
    default:
      return "unknown error";
  }
}

void clear_error(bicycl_context_t *ctx) {
  if (ctx != nullptr) {
    ctx->last_error.clear();
  }
}

void set_error(bicycl_context_t *ctx, const std::string &msg) {
  if (ctx != nullptr) {
    ctx->last_error = msg;
  }
}

bicycl_status_t write_c_string(
    bicycl_context_t *ctx,
    const std::string &value,
    char *out_buf,
    size_t *inout_len) {
  if (inout_len == nullptr) {
    set_error(ctx, "output length pointer is null");
    return BICYCL_ERR_NULL_PTR;
  }

  const size_t required = value.size() + 1;
  if (out_buf == nullptr || *inout_len < required) {
    *inout_len = required;
    set_error(ctx, "output buffer too small");
    return BICYCL_ERR_BUFFER_TOO_SMALL;
  }

  for (size_t i = 0; i < value.size(); ++i) {
    out_buf[i] = value[i];
  }
  out_buf[value.size()] = '\0';
  *inout_len = required;
  return BICYCL_OK;
}

BICYCL::Mpz parse_decimal(
    bicycl_context_t *ctx,
    const char *decimal,
    const char *field_name,
    bicycl_status_t *status) {
  if (decimal == nullptr) {
    set_error(ctx, std::string(field_name) + " is null");
    *status = BICYCL_ERR_NULL_PTR;
    return BICYCL::Mpz(0UL);
  }

  try {
    *status = BICYCL_OK;
    return BICYCL::Mpz(std::string(decimal));
  } catch (const std::exception &e) {
    set_error(ctx, std::string("failed to parse ") + field_name + ": " + e.what());
    *status = BICYCL_ERR_PARSE;
    return BICYCL::Mpz(0UL);
  }
}

std::string mpz_to_string(const BICYCL::Mpz &value) {
  std::ostringstream oss;
  oss << value;
  return oss.str();
}

std::string bn_to_string(const BICYCL::BN &value) {
  return mpz_to_string(static_cast<BICYCL::Mpz>(value));
}

void split_fields(
    const std::string &input,
    char sep,
    std::vector<std::string> &out) {
  out.clear();
  size_t start = 0;
  while (start <= input.size()) {
    const size_t pos = input.find(sep, start);
    if (pos == std::string::npos) {
      out.push_back(input.substr(start));
      return;
    }
    out.push_back(input.substr(start, pos - start));
    start = pos + 1;
  }
}

std::string qfi_encode(const BICYCL::QFI &qfi) {
  return mpz_to_string(qfi.a()) + "," + mpz_to_string(qfi.b()) + "," + mpz_to_string(qfi.c());
}

bool qfi_decode(const std::string &s, BICYCL::QFI &out) {
  std::vector<std::string> f;
  split_fields(s, ',', f);
  if (f.size() != 3) {
    return false;
  }
  out = BICYCL::QFI(BICYCL::Mpz(f[0]), BICYCL::Mpz(f[1]), BICYCL::Mpz(f[2]), true);
  return true;
}

std::string ecpoint_encode(const BICYCL::ECGroup &ec, const BICYCL::ECPoint &p) {
  BICYCL::BN x(0UL), y(0UL);
  ec.coords_of_point(x, y, p);
  return bn_to_string(x) + "," + bn_to_string(y);
}

bool ecpoint_decode(const BICYCL::ECGroup &ec, const std::string &s, BICYCL::ECPoint &out) {
  std::vector<std::string> f;
  split_fields(s, ',', f);
  if (f.size() != 2) {
    return false;
  }
  out = BICYCL::ECPoint(ec, BICYCL::BN(BICYCL::Mpz(f[0])), BICYCL::BN(BICYCL::Mpz(f[1])));
  return true;
}

bicycl_status_t write_bytes(
    bicycl_context_t *ctx,
    const std::string &value,
    uint8_t *out_buf,
    size_t *inout_len) {
  if (inout_len == nullptr) {
    set_error(ctx, "output length pointer is null");
    return BICYCL_ERR_NULL_PTR;
  }
  if (out_buf == nullptr || *inout_len < value.size()) {
    *inout_len = value.size();
    set_error(ctx, "output buffer too small");
    return BICYCL_ERR_BUFFER_TOO_SMALL;
  }
  for (size_t i = 0; i < value.size(); ++i) {
    out_buf[i] = static_cast<uint8_t>(value[i]);
  }
  *inout_len = value.size();
  return BICYCL_OK;
}

bicycl_status_t invalid_stage(
    bicycl_context_t *ctx,
    const char *fn,
    unsigned int expected,
    unsigned int actual) {
  std::ostringstream oss;
  oss << fn << ": invalid stage, expected " << expected << ", got " << actual;
  set_error(ctx, oss.str());
  return BICYCL_ERR_INVALID_STATE;
}

}  // namespace

extern "C" {

uint32_t bicycl_get_abi_version(void) { return BICYCL_CAPI_VERSION; }

const char *bicycl_get_version(void) { return kVersion; }

const char *bicycl_status_message(const bicycl_status_t status) {
  return status_to_message(status);
}

bicycl_status_t bicycl_context_new(bicycl_context_t **out_ctx) {
  if (out_ctx == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }

  try {
    *out_ctx = new bicycl_context_t();
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    *out_ctx = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (...) {
    *out_ctx = nullptr;
    return BICYCL_ERR_INTERNAL;
  }
}

void bicycl_context_free(bicycl_context_t *ctx) { delete ctx; }

const char *bicycl_context_last_error(const bicycl_context_t *ctx) {
  if (ctx == nullptr) {
    return "context is null";
  }
  if (ctx->last_error.empty()) {
    return "";
  }
  return ctx->last_error.c_str();
}

void bicycl_context_clear_error(bicycl_context_t *ctx) { clear_error(ctx); }

void bicycl_zeroize(void *ptr, size_t len) {
  if (ptr == nullptr || len == 0) {
    return;
  }

  volatile unsigned char *p = static_cast<volatile unsigned char *>(ptr);
  for (size_t i = 0; i < len; ++i) {
    p[i] = 0;
  }
}

bicycl_status_t bicycl_randgen_new_from_seed_decimal(
    bicycl_context_t *ctx,
    const char *seed_decimal,
    bicycl_randgen_t **out_randgen) {
  clear_error(ctx);
  if (ctx == nullptr || out_randgen == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }

  try {
    bicycl_status_t status = BICYCL_OK;
    BICYCL::Mpz seed = parse_decimal(ctx, seed_decimal, "seed_decimal", &status);
    if (status != BICYCL_OK) {
      return status;
    }

    *out_randgen = new bicycl_randgen_t(seed);
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out_randgen = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out_randgen = nullptr;
    return BICYCL_ERR_CORE;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out_randgen = nullptr;
    return BICYCL_ERR_CORE;
  }
}

void bicycl_randgen_free(bicycl_randgen_t *randgen) { delete randgen; }

bicycl_status_t bicycl_classgroup_new_from_discriminant_decimal(
    bicycl_context_t *ctx,
    const char *discriminant_decimal,
    bicycl_classgroup_t **out_classgroup) {
  clear_error(ctx);
  if (ctx == nullptr || out_classgroup == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }

  try {
    bicycl_status_t status = BICYCL_OK;
    BICYCL::Mpz disc = parse_decimal(ctx, discriminant_decimal, "discriminant_decimal", &status);
    if (status != BICYCL_OK) {
      return status;
    }

    *out_classgroup = new bicycl_classgroup_t(disc);
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out_classgroup = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out_classgroup = nullptr;
    return BICYCL_ERR_INVALID_ARGUMENT;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out_classgroup = nullptr;
    return BICYCL_ERR_CORE;
  }
}

void bicycl_classgroup_free(bicycl_classgroup_t *classgroup) { delete classgroup; }

bicycl_status_t bicycl_classgroup_one(
    bicycl_context_t *ctx,
    const bicycl_classgroup_t *classgroup,
    bicycl_qfi_t **out_qfi) {
  clear_error(ctx);
  if (ctx == nullptr || classgroup == nullptr || out_qfi == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }

  try {
    *out_qfi = new bicycl_qfi_t(classgroup->value.one());
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out_qfi = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out_qfi = nullptr;
    return BICYCL_ERR_CORE;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out_qfi = nullptr;
    return BICYCL_ERR_CORE;
  }
}

bicycl_status_t bicycl_classgroup_nudupl(
    bicycl_context_t *ctx,
    const bicycl_classgroup_t *classgroup,
    const bicycl_qfi_t *input,
    bicycl_qfi_t **out_qfi) {
  clear_error(ctx);
  if (ctx == nullptr || classgroup == nullptr || input == nullptr || out_qfi == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }

  try {
    BICYCL::QFI out;
    classgroup->value.nudupl(out, input->value);
    *out_qfi = new bicycl_qfi_t(out);
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out_qfi = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out_qfi = nullptr;
    return BICYCL_ERR_CORE;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out_qfi = nullptr;
    return BICYCL_ERR_CORE;
  }
}

void bicycl_qfi_free(bicycl_qfi_t *qfi) { delete qfi; }

bicycl_status_t bicycl_qfi_is_one(
    bicycl_context_t *ctx,
    const bicycl_qfi_t *qfi,
    int *out_is_one) {
  clear_error(ctx);
  if (ctx == nullptr || qfi == nullptr || out_is_one == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }

  try {
    *out_is_one = qfi->value.is_one() ? 1 : 0;
    return BICYCL_OK;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_CORE;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_CORE;
  }
}

bicycl_status_t bicycl_qfi_discriminant_decimal(
    bicycl_context_t *ctx,
    const bicycl_qfi_t *qfi,
    char *out_buf,
    size_t *inout_len) {
  clear_error(ctx);
  if (ctx == nullptr || qfi == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }

  try {
    return write_c_string(ctx, mpz_to_string(qfi->value.discriminant()), out_buf, inout_len);
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_CORE;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_CORE;
  }
}

// ── QFI additional ──────────────────────────────────────────────────────

bicycl_status_t bicycl_qfi_new_from_abc_decimal(
    bicycl_context_t *ctx, const char *a, const char *b, const char *c,
    bicycl_qfi_t **out) {
  clear_error(ctx);
  if (ctx == nullptr || a == nullptr || b == nullptr || c == nullptr || out == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  try {
    bicycl_status_t status = BICYCL_OK;
    BICYCL::Mpz a_mpz = parse_decimal(ctx, a, "a", &status);
    if (status != BICYCL_OK) { return status; }
    BICYCL::Mpz b_mpz = parse_decimal(ctx, b, "b", &status);
    if (status != BICYCL_OK) { return status; }
    BICYCL::Mpz c_mpz = parse_decimal(ctx, c, "c", &status);
    if (status != BICYCL_OK) { return status; }
    BICYCL::QFI qfi_val(a_mpz, b_mpz, c_mpz, true);
    *out = new bicycl_qfi_t(qfi_val);
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out = nullptr;
    return BICYCL_ERR_CORE;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out = nullptr;
    return BICYCL_ERR_CORE;
  }
}

bicycl_status_t bicycl_qfi_a_decimal(
    bicycl_context_t *ctx, const bicycl_qfi_t *qfi, char *out_buf, size_t *inout_len) {
  clear_error(ctx);
  if (ctx == nullptr || qfi == nullptr) { return BICYCL_ERR_NULL_PTR; }
  try {
    return write_c_string(ctx, mpz_to_string(qfi->value.a()), out_buf, inout_len);
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_CORE;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_CORE;
  }
}

bicycl_status_t bicycl_qfi_b_decimal(
    bicycl_context_t *ctx, const bicycl_qfi_t *qfi, char *out_buf, size_t *inout_len) {
  clear_error(ctx);
  if (ctx == nullptr || qfi == nullptr) { return BICYCL_ERR_NULL_PTR; }
  try {
    return write_c_string(ctx, mpz_to_string(qfi->value.b()), out_buf, inout_len);
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_CORE;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_CORE;
  }
}

bicycl_status_t bicycl_qfi_c_decimal(
    bicycl_context_t *ctx, const bicycl_qfi_t *qfi, char *out_buf, size_t *inout_len) {
  clear_error(ctx);
  if (ctx == nullptr || qfi == nullptr) { return BICYCL_ERR_NULL_PTR; }
  try {
    return write_c_string(ctx, mpz_to_string(qfi->value.c()), out_buf, inout_len);
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_CORE;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_CORE;
  }
}

bicycl_status_t bicycl_qfi_equal(
    bicycl_context_t *ctx, const bicycl_qfi_t *a, const bicycl_qfi_t *b, int *out) {
  clear_error(ctx);
  if (ctx == nullptr || a == nullptr || b == nullptr || out == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  try {
    *out = (a->value == b->value) ? 1 : 0;
    return BICYCL_OK;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_CORE;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_CORE;
  }
}

bicycl_status_t bicycl_qfi_neg(
    bicycl_context_t *ctx, const bicycl_qfi_t *qfi, bicycl_qfi_t **out) {
  clear_error(ctx);
  if (ctx == nullptr || qfi == nullptr || out == nullptr) { return BICYCL_ERR_NULL_PTR; }
  try {
    BICYCL::QFI copy = qfi->value;
    copy.neg();
    *out = new bicycl_qfi_t(copy);
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out = nullptr;
    return BICYCL_ERR_CORE;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out = nullptr;
    return BICYCL_ERR_CORE;
  }
}

bicycl_status_t bicycl_qfi_lift_decimal(
    bicycl_context_t *ctx, bicycl_qfi_t *qfi, const char *conductor_decimal) {
  clear_error(ctx);
  if (ctx == nullptr || qfi == nullptr || conductor_decimal == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  try {
    bicycl_status_t status = BICYCL_OK;
    BICYCL::Mpz conductor = parse_decimal(ctx, conductor_decimal, "conductor_decimal", &status);
    if (status != BICYCL_OK) { return status; }
    qfi->value.lift(conductor);
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_CORE;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_CORE;
  }
}

bicycl_status_t bicycl_qfi_to_maximal_order_decimal(
    bicycl_context_t *ctx, bicycl_qfi_t *qfi,
    const char *conductor_decimal, const char *DeltaK_decimal, int to_neg) {
  clear_error(ctx);
  if (ctx == nullptr || qfi == nullptr || conductor_decimal == nullptr || DeltaK_decimal == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  try {
    bicycl_status_t status = BICYCL_OK;
    BICYCL::Mpz conductor = parse_decimal(ctx, conductor_decimal, "conductor_decimal", &status);
    if (status != BICYCL_OK) { return status; }
    BICYCL::Mpz DeltaK = parse_decimal(ctx, DeltaK_decimal, "DeltaK_decimal", &status);
    if (status != BICYCL_OK) { return status; }
    qfi->value.to_maximal_order(conductor, DeltaK, to_neg != 0);
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_CORE;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_CORE;
  }
}

// ── ClassGroup additional ────────────────────────────────────────────────

bicycl_status_t bicycl_classgroup_discriminant_decimal(
    bicycl_context_t *ctx, const bicycl_classgroup_t *cg, char *out_buf, size_t *inout_len) {
  clear_error(ctx);
  if (ctx == nullptr || cg == nullptr) { return BICYCL_ERR_NULL_PTR; }
  try {
    return write_c_string(ctx, mpz_to_string(cg->value.discriminant()), out_buf, inout_len);
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_CORE;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_CORE;
  }
}

bicycl_status_t bicycl_classgroup_nucomp(
    bicycl_context_t *ctx, const bicycl_classgroup_t *cg,
    const bicycl_qfi_t *f1, const bicycl_qfi_t *f2, bicycl_qfi_t **out) {
  clear_error(ctx);
  if (ctx == nullptr || cg == nullptr || f1 == nullptr || f2 == nullptr || out == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  try {
    BICYCL::QFI r;
    cg->value.nucomp(r, f1->value, f2->value);
    *out = new bicycl_qfi_t(r);
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out = nullptr;
    return BICYCL_ERR_CORE;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out = nullptr;
    return BICYCL_ERR_CORE;
  }
}

bicycl_status_t bicycl_classgroup_nucompinv(
    bicycl_context_t *ctx, const bicycl_classgroup_t *cg,
    const bicycl_qfi_t *f1, const bicycl_qfi_t *f2, bicycl_qfi_t **out) {
  clear_error(ctx);
  if (ctx == nullptr || cg == nullptr || f1 == nullptr || f2 == nullptr || out == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  try {
    BICYCL::QFI r;
    cg->value.nucompinv(r, f1->value, f2->value);
    *out = new bicycl_qfi_t(r);
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out = nullptr;
    return BICYCL_ERR_CORE;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out = nullptr;
    return BICYCL_ERR_CORE;
  }
}

bicycl_status_t bicycl_classgroup_nupow_decimal(
    bicycl_context_t *ctx, const bicycl_classgroup_t *cg,
    const bicycl_qfi_t *f, const char *n_decimal, bicycl_qfi_t **out) {
  clear_error(ctx);
  if (ctx == nullptr || cg == nullptr || f == nullptr || n_decimal == nullptr || out == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  try {
    bicycl_status_t status = BICYCL_OK;
    BICYCL::Mpz n = parse_decimal(ctx, n_decimal, "n_decimal", &status);
    if (status != BICYCL_OK) { return status; }
    BICYCL::QFI r;
    cg->value.nupow(r, f->value, n);
    *out = new bicycl_qfi_t(r);
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out = nullptr;
    return BICYCL_ERR_CORE;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out = nullptr;
    return BICYCL_ERR_CORE;
  }
}

bicycl_status_t bicycl_classgroup_nupow2_decimal(
    bicycl_context_t *ctx, const bicycl_classgroup_t *cg,
    const bicycl_qfi_t *f0, const char *n0_decimal,
    const bicycl_qfi_t *f1, const char *n1_decimal, bicycl_qfi_t **out) {
  clear_error(ctx);
  if (ctx == nullptr || cg == nullptr || f0 == nullptr || n0_decimal == nullptr ||
      f1 == nullptr || n1_decimal == nullptr || out == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  try {
    bicycl_status_t status = BICYCL_OK;
    BICYCL::Mpz n0 = parse_decimal(ctx, n0_decimal, "n0_decimal", &status);
    if (status != BICYCL_OK) { return status; }
    BICYCL::Mpz n1 = parse_decimal(ctx, n1_decimal, "n1_decimal", &status);
    if (status != BICYCL_OK) { return status; }
    BICYCL::QFI r;
    cg->value.nupow(r, f0->value, n0, f1->value, n1);
    *out = new bicycl_qfi_t(r);
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out = nullptr;
    return BICYCL_ERR_CORE;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out = nullptr;
    return BICYCL_ERR_CORE;
  }
}

bicycl_status_t bicycl_classgroup_primeform_decimal(
    bicycl_context_t *ctx, const bicycl_classgroup_t *cg,
    const char *p_decimal, bicycl_qfi_t **out) {
  clear_error(ctx);
  if (ctx == nullptr || cg == nullptr || p_decimal == nullptr || out == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  try {
    bicycl_status_t status = BICYCL_OK;
    BICYCL::Mpz p = parse_decimal(ctx, p_decimal, "p_decimal", &status);
    if (status != BICYCL_OK) { return status; }
    *out = new bicycl_qfi_t(cg->value.primeform(p));
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out = nullptr;
    return BICYCL_ERR_CORE;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out = nullptr;
    return BICYCL_ERR_CORE;
  }
}

// ── CL_HSMqk parameters ──────────────────────────────────────────────────

bicycl_status_t bicycl_cl_hsmqk_q_decimal(
    bicycl_context_t *ctx, const bicycl_cl_hsmqk_t *cl, char *out_buf, size_t *inout_len) {
  clear_error(ctx);
  if (ctx == nullptr || cl == nullptr) { return BICYCL_ERR_NULL_PTR; }
  try {
    return write_c_string(ctx, mpz_to_string(cl->value.q()), out_buf, inout_len);
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_CL_HSMQK;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_CL_HSMQK;
  }
}

bicycl_status_t bicycl_cl_hsmqk_p_decimal(
    bicycl_context_t *ctx, const bicycl_cl_hsmqk_t *cl, char *out_buf, size_t *inout_len) {
  clear_error(ctx);
  if (ctx == nullptr || cl == nullptr) { return BICYCL_ERR_NULL_PTR; }
  try {
    return write_c_string(ctx, mpz_to_string(cl->value.p()), out_buf, inout_len);
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_CL_HSMQK;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_CL_HSMQK;
  }
}

bicycl_status_t bicycl_cl_hsmqk_M_decimal(
    bicycl_context_t *ctx, const bicycl_cl_hsmqk_t *cl, char *out_buf, size_t *inout_len) {
  clear_error(ctx);
  if (ctx == nullptr || cl == nullptr) { return BICYCL_ERR_NULL_PTR; }
  try {
    return write_c_string(ctx, mpz_to_string(cl->value.M()), out_buf, inout_len);
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_CL_HSMQK;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_CL_HSMQK;
  }
}

bicycl_status_t bicycl_cl_hsmqk_DeltaK_decimal(
    bicycl_context_t *ctx, const bicycl_cl_hsmqk_t *cl, char *out_buf, size_t *inout_len) {
  clear_error(ctx);
  if (ctx == nullptr || cl == nullptr) { return BICYCL_ERR_NULL_PTR; }
  try {
    return write_c_string(ctx, mpz_to_string(cl->value.DeltaK()), out_buf, inout_len);
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_CL_HSMQK;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_CL_HSMQK;
  }
}

bicycl_status_t bicycl_cl_hsmqk_Delta_decimal(
    bicycl_context_t *ctx, const bicycl_cl_hsmqk_t *cl, char *out_buf, size_t *inout_len) {
  clear_error(ctx);
  if (ctx == nullptr || cl == nullptr) { return BICYCL_ERR_NULL_PTR; }
  try {
    return write_c_string(ctx, mpz_to_string(cl->value.Delta()), out_buf, inout_len);
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_CL_HSMQK;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_CL_HSMQK;
  }
}

bicycl_status_t bicycl_cl_hsmqk_secretkey_bound_decimal(
    bicycl_context_t *ctx, const bicycl_cl_hsmqk_t *cl, char *out_buf, size_t *inout_len) {
  clear_error(ctx);
  if (ctx == nullptr || cl == nullptr) { return BICYCL_ERR_NULL_PTR; }
  try {
    return write_c_string(ctx, mpz_to_string(cl->value.secretkey_bound()), out_buf, inout_len);
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_CL_HSMQK;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_CL_HSMQK;
  }
}

bicycl_status_t bicycl_cl_hsmqk_Cl_DeltaK(
    bicycl_context_t *ctx, const bicycl_cl_hsmqk_t *cl, bicycl_classgroup_t **out) {
  clear_error(ctx);
  if (ctx == nullptr || cl == nullptr || out == nullptr) { return BICYCL_ERR_NULL_PTR; }
  try {
    *out = new bicycl_classgroup_t(cl->value.Cl_DeltaK().discriminant());
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out = nullptr;
    return BICYCL_ERR_CL_HSMQK;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out = nullptr;
    return BICYCL_ERR_CL_HSMQK;
  }
}

bicycl_status_t bicycl_cl_hsmqk_Cl_Delta(
    bicycl_context_t *ctx, const bicycl_cl_hsmqk_t *cl, bicycl_classgroup_t **out) {
  clear_error(ctx);
  if (ctx == nullptr || cl == nullptr || out == nullptr) { return BICYCL_ERR_NULL_PTR; }
  try {
    *out = new bicycl_classgroup_t(cl->value.Cl_Delta().discriminant());
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out = nullptr;
    return BICYCL_ERR_CL_HSMQK;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out = nullptr;
    return BICYCL_ERR_CL_HSMQK;
  }
}

bicycl_status_t bicycl_cl_hsmqk_h(
    bicycl_context_t *ctx, const bicycl_cl_hsmqk_t *cl, bicycl_qfi_t **out) {
  clear_error(ctx);
  if (ctx == nullptr || cl == nullptr || out == nullptr) { return BICYCL_ERR_NULL_PTR; }
  try {
    *out = new bicycl_qfi_t(cl->value.h());
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out = nullptr;
    return BICYCL_ERR_CL_HSMQK;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out = nullptr;
    return BICYCL_ERR_CL_HSMQK;
  }
}

// ── CL_HSMqk subgroup operations ─────────────────────────────────────────

bicycl_status_t bicycl_cl_hsmqk_power_of_h_decimal(
    bicycl_context_t *ctx, const bicycl_cl_hsmqk_t *cl,
    const char *e_decimal, bicycl_qfi_t **out) {
  clear_error(ctx);
  if (ctx == nullptr || cl == nullptr || e_decimal == nullptr || out == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  try {
    bicycl_status_t status = BICYCL_OK;
    BICYCL::Mpz e = parse_decimal(ctx, e_decimal, "e_decimal", &status);
    if (status != BICYCL_OK) { return status; }
    BICYCL::QFI r;
    cl->value.power_of_h(r, e);
    *out = new bicycl_qfi_t(r);
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out = nullptr;
    return BICYCL_ERR_CL_HSMQK;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out = nullptr;
    return BICYCL_ERR_CL_HSMQK;
  }
}

bicycl_status_t bicycl_cl_hsmqk_power_of_f_decimal(
    bicycl_context_t *ctx, const bicycl_cl_hsmqk_t *cl,
    const char *m_decimal, bicycl_qfi_t **out) {
  clear_error(ctx);
  if (ctx == nullptr || cl == nullptr || m_decimal == nullptr || out == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  try {
    bicycl_status_t status = BICYCL_OK;
    BICYCL::Mpz m = parse_decimal(ctx, m_decimal, "m_decimal", &status);
    if (status != BICYCL_OK) { return status; }
    *out = new bicycl_qfi_t(cl->value.power_of_f(m));
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out = nullptr;
    return BICYCL_ERR_CL_HSMQK;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out = nullptr;
    return BICYCL_ERR_CL_HSMQK;
  }
}

bicycl_status_t bicycl_cl_hsmqk_dlog_in_F(
    bicycl_context_t *ctx, const bicycl_cl_hsmqk_t *cl,
    const bicycl_qfi_t *fm, char *out_buf, size_t *inout_len) {
  clear_error(ctx);
  if (ctx == nullptr || cl == nullptr || fm == nullptr) { return BICYCL_ERR_NULL_PTR; }
  try {
    BICYCL::Mpz result = cl->value.dlog_in_F(fm->value);
    return write_c_string(ctx, mpz_to_string(result), out_buf, inout_len);
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_CL_HSMQK;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_CL_HSMQK;
  }
}

bicycl_status_t bicycl_cl_hsmqk_from_Cl_DeltaK_to_Cl_Delta(
    bicycl_context_t *ctx, const bicycl_cl_hsmqk_t *cl, bicycl_qfi_t *f) {
  clear_error(ctx);
  if (ctx == nullptr || cl == nullptr || f == nullptr) { return BICYCL_ERR_NULL_PTR; }
  try {
    cl->value.from_Cl_DeltaK_to_Cl_Delta(f->value);
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_CL_HSMQK;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_CL_HSMQK;
  }
}

// ── CL_HSMqk key/ciphertext access ───────────────────────────────────────

bicycl_status_t bicycl_cl_hsmqk_pk_elt(
    bicycl_context_t *ctx, const bicycl_cl_hsmqk_pk_t *pk, bicycl_qfi_t **out) {
  clear_error(ctx);
  if (ctx == nullptr || pk == nullptr || out == nullptr) { return BICYCL_ERR_NULL_PTR; }
  try {
    *out = new bicycl_qfi_t(pk->value.elt());
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out = nullptr;
    return BICYCL_ERR_CL_HSMQK;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out = nullptr;
    return BICYCL_ERR_CL_HSMQK;
  }
}

bicycl_status_t bicycl_cl_hsmqk_pk_new_from_qfi(
    bicycl_context_t *ctx, const bicycl_cl_hsmqk_t *cl,
    const bicycl_qfi_t *qfi, bicycl_cl_hsmqk_pk_t **out) {
  clear_error(ctx);
  if (ctx == nullptr || cl == nullptr || qfi == nullptr || out == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  try {
    *out = new bicycl_cl_hsmqk_pk_t(BICYCL::CL_HSMqk::PublicKey(cl->value, qfi->value));
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out = nullptr;
    return BICYCL_ERR_CL_HSMQK;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out = nullptr;
    return BICYCL_ERR_CL_HSMQK;
  }
}

bicycl_status_t bicycl_cl_hsmqk_ct_c1(
    bicycl_context_t *ctx, const bicycl_cl_hsmqk_ct_t *ct, bicycl_qfi_t **out) {
  clear_error(ctx);
  if (ctx == nullptr || ct == nullptr || out == nullptr) { return BICYCL_ERR_NULL_PTR; }
  try {
    *out = new bicycl_qfi_t(ct->value.c1());
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out = nullptr;
    return BICYCL_ERR_CL_HSMQK;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out = nullptr;
    return BICYCL_ERR_CL_HSMQK;
  }
}

bicycl_status_t bicycl_cl_hsmqk_ct_c2(
    bicycl_context_t *ctx, const bicycl_cl_hsmqk_ct_t *ct, bicycl_qfi_t **out) {
  clear_error(ctx);
  if (ctx == nullptr || ct == nullptr || out == nullptr) { return BICYCL_ERR_NULL_PTR; }
  try {
    *out = new bicycl_qfi_t(ct->value.c2());
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out = nullptr;
    return BICYCL_ERR_CL_HSMQK;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out = nullptr;
    return BICYCL_ERR_CL_HSMQK;
  }
}

bicycl_status_t bicycl_cl_hsmqk_ct_new_from_c1c2(
    bicycl_context_t *ctx, const bicycl_qfi_t *c1, const bicycl_qfi_t *c2,
    bicycl_cl_hsmqk_ct_t **out) {
  clear_error(ctx);
  if (ctx == nullptr || c1 == nullptr || c2 == nullptr || out == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  try {
    *out = new bicycl_cl_hsmqk_ct_t(BICYCL::CL_HSMqk::CipherText(c1->value, c2->value));
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out = nullptr;
    return BICYCL_ERR_CL_HSMQK;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out = nullptr;
    return BICYCL_ERR_CL_HSMQK;
  }
}

bicycl_status_t bicycl_cl_hsmqk_sk_decimal(
    bicycl_context_t *ctx, const bicycl_cl_hsmqk_sk_t *sk, char *out_buf, size_t *inout_len) {
  clear_error(ctx);
  if (ctx == nullptr || sk == nullptr) { return BICYCL_ERR_NULL_PTR; }
  try {
    return write_c_string(ctx, mpz_to_string(static_cast<const BICYCL::Mpz &>(sk->value)), out_buf, inout_len);
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_CL_HSMQK;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_CL_HSMQK;
  }
}

bicycl_status_t bicycl_cl_hsmqk_sk_new_from_decimal(
    bicycl_context_t *ctx, const bicycl_cl_hsmqk_t *cl,
    const char *sk_decimal, bicycl_cl_hsmqk_sk_t **out) {
  clear_error(ctx);
  if (ctx == nullptr || cl == nullptr || sk_decimal == nullptr || out == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  try {
    bicycl_status_t status = BICYCL_OK;
    BICYCL::Mpz mpz_val = parse_decimal(ctx, sk_decimal, "sk_decimal", &status);
    if (status != BICYCL_OK) { return status; }
    BICYCL::CL_HSMqk::SecretKey sk(cl->value, mpz_val);
    *out = new bicycl_cl_hsmqk_sk_t(sk);
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out = nullptr;
    return BICYCL_ERR_CL_HSMQK;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out = nullptr;
    return BICYCL_ERR_CL_HSMQK;
  }
}

bicycl_status_t bicycl_cl_hsmqk_encrypt_decimal_with_r(
    bicycl_context_t *ctx, const bicycl_cl_hsmqk_t *cl,
    const bicycl_cl_hsmqk_pk_t *pk, const char *message_decimal,
    const char *r_decimal, bicycl_cl_hsmqk_ct_t **out_ct) {
  clear_error(ctx);
  if (ctx == nullptr || cl == nullptr || pk == nullptr || message_decimal == nullptr ||
      r_decimal == nullptr || out_ct == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  try {
    bicycl_status_t status = BICYCL_OK;
    BICYCL::Mpz message = parse_decimal(ctx, message_decimal, "message_decimal", &status);
    if (status != BICYCL_OK) { return status; }
    BICYCL::Mpz r = parse_decimal(ctx, r_decimal, "r_decimal", &status);
    if (status != BICYCL_OK) { return status; }
    BICYCL::CL_HSMqk::ClearText clear(cl->value, message);
    BICYCL::CL_HSMqk::CipherText ct = cl->value.encrypt(pk->value, clear, r);
    *out_ct = new bicycl_cl_hsmqk_ct_t(ct);
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out_ct = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out_ct = nullptr;
    return BICYCL_ERR_CL_HSMQK;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out_ct = nullptr;
    return BICYCL_ERR_CL_HSMQK;
  }
}

// ── CL_HSM2k parameters ──────────────────────────────────────────────────

bicycl_status_t bicycl_cl_hsm2k_N_decimal(
    bicycl_context_t *ctx, const bicycl_cl_hsm2k_t *cl, char *out_buf, size_t *inout_len) {
  clear_error(ctx);
  if (ctx == nullptr || cl == nullptr) { return BICYCL_ERR_NULL_PTR; }
  try {
    return write_c_string(ctx, mpz_to_string(cl->value.N()), out_buf, inout_len);
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_CL_HSM2K;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_CL_HSM2K;
  }
}

bicycl_status_t bicycl_cl_hsm2k_M_decimal(
    bicycl_context_t *ctx, const bicycl_cl_hsm2k_t *cl, char *out_buf, size_t *inout_len) {
  clear_error(ctx);
  if (ctx == nullptr || cl == nullptr) { return BICYCL_ERR_NULL_PTR; }
  try {
    return write_c_string(ctx, mpz_to_string(cl->value.M()), out_buf, inout_len);
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_CL_HSM2K;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_CL_HSM2K;
  }
}

bicycl_status_t bicycl_cl_hsm2k_DeltaK_decimal(
    bicycl_context_t *ctx, const bicycl_cl_hsm2k_t *cl, char *out_buf, size_t *inout_len) {
  clear_error(ctx);
  if (ctx == nullptr || cl == nullptr) { return BICYCL_ERR_NULL_PTR; }
  try {
    return write_c_string(ctx, mpz_to_string(cl->value.DeltaK()), out_buf, inout_len);
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_CL_HSM2K;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_CL_HSM2K;
  }
}

bicycl_status_t bicycl_cl_hsm2k_Delta_decimal(
    bicycl_context_t *ctx, const bicycl_cl_hsm2k_t *cl, char *out_buf, size_t *inout_len) {
  clear_error(ctx);
  if (ctx == nullptr || cl == nullptr) { return BICYCL_ERR_NULL_PTR; }
  try {
    return write_c_string(ctx, mpz_to_string(cl->value.Delta()), out_buf, inout_len);
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_CL_HSM2K;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_CL_HSM2K;
  }
}

bicycl_status_t bicycl_cl_hsm2k_secretkey_bound_decimal(
    bicycl_context_t *ctx, const bicycl_cl_hsm2k_t *cl, char *out_buf, size_t *inout_len) {
  clear_error(ctx);
  if (ctx == nullptr || cl == nullptr) { return BICYCL_ERR_NULL_PTR; }
  try {
    return write_c_string(ctx, mpz_to_string(cl->value.secretkey_bound()), out_buf, inout_len);
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_CL_HSM2K;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_CL_HSM2K;
  }
}

bicycl_status_t bicycl_cl_hsm2k_Cl_DeltaK(
    bicycl_context_t *ctx, const bicycl_cl_hsm2k_t *cl, bicycl_classgroup_t **out) {
  clear_error(ctx);
  if (ctx == nullptr || cl == nullptr || out == nullptr) { return BICYCL_ERR_NULL_PTR; }
  try {
    *out = new bicycl_classgroup_t(cl->value.Cl_DeltaK().discriminant());
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out = nullptr;
    return BICYCL_ERR_CL_HSM2K;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out = nullptr;
    return BICYCL_ERR_CL_HSM2K;
  }
}

bicycl_status_t bicycl_cl_hsm2k_Cl_Delta(
    bicycl_context_t *ctx, const bicycl_cl_hsm2k_t *cl, bicycl_classgroup_t **out) {
  clear_error(ctx);
  if (ctx == nullptr || cl == nullptr || out == nullptr) { return BICYCL_ERR_NULL_PTR; }
  try {
    *out = new bicycl_classgroup_t(cl->value.Cl_Delta().discriminant());
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out = nullptr;
    return BICYCL_ERR_CL_HSM2K;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out = nullptr;
    return BICYCL_ERR_CL_HSM2K;
  }
}

bicycl_status_t bicycl_cl_hsm2k_h(
    bicycl_context_t *ctx, const bicycl_cl_hsm2k_t *cl, bicycl_qfi_t **out) {
  clear_error(ctx);
  if (ctx == nullptr || cl == nullptr || out == nullptr) { return BICYCL_ERR_NULL_PTR; }
  try {
    *out = new bicycl_qfi_t(cl->value.h());
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out = nullptr;
    return BICYCL_ERR_CL_HSM2K;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out = nullptr;
    return BICYCL_ERR_CL_HSM2K;
  }
}

bicycl_status_t bicycl_cl_hsm2k_power_of_h_decimal(
    bicycl_context_t *ctx, const bicycl_cl_hsm2k_t *cl,
    const char *e_decimal, bicycl_qfi_t **out) {
  clear_error(ctx);
  if (ctx == nullptr || cl == nullptr || e_decimal == nullptr || out == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  try {
    bicycl_status_t status = BICYCL_OK;
    BICYCL::Mpz e = parse_decimal(ctx, e_decimal, "e_decimal", &status);
    if (status != BICYCL_OK) { return status; }
    BICYCL::QFI r;
    cl->value.power_of_h(r, e);
    *out = new bicycl_qfi_t(r);
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out = nullptr;
    return BICYCL_ERR_CL_HSM2K;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out = nullptr;
    return BICYCL_ERR_CL_HSM2K;
  }
}

bicycl_status_t bicycl_cl_hsm2k_power_of_f_decimal(
    bicycl_context_t *ctx, const bicycl_cl_hsm2k_t *cl,
    const char *m_decimal, bicycl_qfi_t **out) {
  clear_error(ctx);
  if (ctx == nullptr || cl == nullptr || m_decimal == nullptr || out == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  try {
    bicycl_status_t status = BICYCL_OK;
    BICYCL::Mpz m = parse_decimal(ctx, m_decimal, "m_decimal", &status);
    if (status != BICYCL_OK) { return status; }
    *out = new bicycl_qfi_t(cl->value.power_of_f(m));
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out = nullptr;
    return BICYCL_ERR_CL_HSM2K;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out = nullptr;
    return BICYCL_ERR_CL_HSM2K;
  }
}

bicycl_status_t bicycl_cl_hsm2k_dlog_in_F(
    bicycl_context_t *ctx, const bicycl_cl_hsm2k_t *cl,
    const bicycl_qfi_t *fm, char *out_buf, size_t *inout_len) {
  clear_error(ctx);
  if (ctx == nullptr || cl == nullptr || fm == nullptr) { return BICYCL_ERR_NULL_PTR; }
  try {
    BICYCL::Mpz result = cl->value.dlog_in_F(fm->value);
    return write_c_string(ctx, mpz_to_string(result), out_buf, inout_len);
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_CL_HSM2K;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_CL_HSM2K;
  }
}

bicycl_status_t bicycl_cl_hsm2k_from_Cl_DeltaK_to_Cl_Delta(
    bicycl_context_t *ctx, const bicycl_cl_hsm2k_t *cl, bicycl_qfi_t *f) {
  clear_error(ctx);
  if (ctx == nullptr || cl == nullptr || f == nullptr) { return BICYCL_ERR_NULL_PTR; }
  try {
    cl->value.from_Cl_DeltaK_to_Cl_Delta(f->value);
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_CL_HSM2K;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_CL_HSM2K;
  }
}

bicycl_status_t bicycl_cl_hsm2k_pk_elt(
    bicycl_context_t *ctx, const bicycl_cl_hsm2k_pk_t *pk, bicycl_qfi_t **out) {
  clear_error(ctx);
  if (ctx == nullptr || pk == nullptr || out == nullptr) { return BICYCL_ERR_NULL_PTR; }
  try {
    *out = new bicycl_qfi_t(pk->value.elt());
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out = nullptr;
    return BICYCL_ERR_CL_HSM2K;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out = nullptr;
    return BICYCL_ERR_CL_HSM2K;
  }
}

bicycl_status_t bicycl_cl_hsm2k_pk_new_from_qfi(
    bicycl_context_t *ctx, const bicycl_cl_hsm2k_t *cl,
    const bicycl_qfi_t *qfi, bicycl_cl_hsm2k_pk_t **out) {
  clear_error(ctx);
  if (ctx == nullptr || cl == nullptr || qfi == nullptr || out == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  try {
    *out = new bicycl_cl_hsm2k_pk_t(BICYCL::CL_HSM2k::PublicKey(cl->value, qfi->value));
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out = nullptr;
    return BICYCL_ERR_CL_HSM2K;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out = nullptr;
    return BICYCL_ERR_CL_HSM2K;
  }
}

bicycl_status_t bicycl_cl_hsm2k_ct_c1(
    bicycl_context_t *ctx, const bicycl_cl_hsm2k_ct_t *ct, bicycl_qfi_t **out) {
  clear_error(ctx);
  if (ctx == nullptr || ct == nullptr || out == nullptr) { return BICYCL_ERR_NULL_PTR; }
  try {
    *out = new bicycl_qfi_t(ct->value.c1());
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out = nullptr;
    return BICYCL_ERR_CL_HSM2K;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out = nullptr;
    return BICYCL_ERR_CL_HSM2K;
  }
}

bicycl_status_t bicycl_cl_hsm2k_ct_c2(
    bicycl_context_t *ctx, const bicycl_cl_hsm2k_ct_t *ct, bicycl_qfi_t **out) {
  clear_error(ctx);
  if (ctx == nullptr || ct == nullptr || out == nullptr) { return BICYCL_ERR_NULL_PTR; }
  try {
    *out = new bicycl_qfi_t(ct->value.c2());
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out = nullptr;
    return BICYCL_ERR_CL_HSM2K;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out = nullptr;
    return BICYCL_ERR_CL_HSM2K;
  }
}

bicycl_status_t bicycl_cl_hsm2k_ct_new_from_c1c2(
    bicycl_context_t *ctx, const bicycl_qfi_t *c1, const bicycl_qfi_t *c2,
    bicycl_cl_hsm2k_ct_t **out) {
  clear_error(ctx);
  if (ctx == nullptr || c1 == nullptr || c2 == nullptr || out == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  try {
    *out = new bicycl_cl_hsm2k_ct_t(BICYCL::CL_HSM2k::CipherText(c1->value, c2->value));
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out = nullptr;
    return BICYCL_ERR_CL_HSM2K;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out = nullptr;
    return BICYCL_ERR_CL_HSM2K;
  }
}

bicycl_status_t bicycl_cl_hsm2k_sk_decimal(
    bicycl_context_t *ctx, const bicycl_cl_hsm2k_sk_t *sk, char *out_buf, size_t *inout_len) {
  clear_error(ctx);
  if (ctx == nullptr || sk == nullptr) { return BICYCL_ERR_NULL_PTR; }
  try {
    return write_c_string(ctx, mpz_to_string(static_cast<const BICYCL::Mpz &>(sk->value)), out_buf, inout_len);
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_CL_HSM2K;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_CL_HSM2K;
  }
}

bicycl_status_t bicycl_cl_hsm2k_sk_new_from_decimal(
    bicycl_context_t *ctx, const bicycl_cl_hsm2k_t *cl,
    const char *sk_decimal, bicycl_cl_hsm2k_sk_t **out) {
  clear_error(ctx);
  if (ctx == nullptr || cl == nullptr || sk_decimal == nullptr || out == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  try {
    bicycl_status_t status = BICYCL_OK;
    BICYCL::Mpz mpz_val = parse_decimal(ctx, sk_decimal, "sk_decimal", &status);
    if (status != BICYCL_OK) { return status; }
    BICYCL::CL_HSM2k::SecretKey sk(cl->value, mpz_val);
    *out = new bicycl_cl_hsm2k_sk_t(sk);
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out = nullptr;
    return BICYCL_ERR_CL_HSM2K;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out = nullptr;
    return BICYCL_ERR_CL_HSM2K;
  }
}

bicycl_status_t bicycl_cl_hsm2k_encrypt_decimal_with_r(
    bicycl_context_t *ctx, const bicycl_cl_hsm2k_t *cl,
    const bicycl_cl_hsm2k_pk_t *pk, const char *message_decimal,
    const char *r_decimal, bicycl_cl_hsm2k_ct_t **out_ct) {
  clear_error(ctx);
  if (ctx == nullptr || cl == nullptr || pk == nullptr || message_decimal == nullptr ||
      r_decimal == nullptr || out_ct == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  try {
    bicycl_status_t status = BICYCL_OK;
    BICYCL::Mpz message = parse_decimal(ctx, message_decimal, "message_decimal", &status);
    if (status != BICYCL_OK) { return status; }
    BICYCL::Mpz r = parse_decimal(ctx, r_decimal, "r_decimal", &status);
    if (status != BICYCL_OK) { return status; }
    BICYCL::CL_HSM2k::ClearText clear(cl->value, message);
    BICYCL::CL_HSM2k::CipherText ct = cl->value.encrypt(pk->value, clear, r);
    *out_ct = new bicycl_cl_hsm2k_ct_t(ct);
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out_ct = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out_ct = nullptr;
    return BICYCL_ERR_CL_HSM2K;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out_ct = nullptr;
    return BICYCL_ERR_CL_HSM2K;
  }
}

bicycl_status_t bicycl_paillier_new(
    bicycl_context_t *ctx,
    uint32_t modulus_bits,
    bicycl_paillier_t **out_paillier) {
  clear_error(ctx);
  if (ctx == nullptr || out_paillier == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  if (modulus_bits < 32U) {
    set_error(ctx, "modulus_bits must be >= 32");
    return BICYCL_ERR_INVALID_ARGUMENT;
  }

  try {
    *out_paillier = new bicycl_paillier_t(static_cast<size_t>(modulus_bits));
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out_paillier = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out_paillier = nullptr;
    return BICYCL_ERR_PAILLIER;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out_paillier = nullptr;
    return BICYCL_ERR_PAILLIER;
  }
}

void bicycl_paillier_free(bicycl_paillier_t *paillier) { delete paillier; }

bicycl_status_t bicycl_paillier_keygen(
    bicycl_context_t *ctx,
    const bicycl_paillier_t *paillier,
    bicycl_randgen_t *randgen,
    bicycl_paillier_sk_t **out_sk,
    bicycl_paillier_pk_t **out_pk) {
  clear_error(ctx);
  if (ctx == nullptr || paillier == nullptr || randgen == nullptr || out_sk == nullptr || out_pk == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }

  try {
    BICYCL::Paillier::SecretKey sk = paillier->value.keygen(randgen->value);
    BICYCL::Paillier::PublicKey pk = paillier->value.keygen(sk);
    *out_sk = new bicycl_paillier_sk_t(sk);
    *out_pk = new bicycl_paillier_pk_t(pk);
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out_sk = nullptr;
    *out_pk = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out_sk = nullptr;
    *out_pk = nullptr;
    return BICYCL_ERR_PAILLIER;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out_sk = nullptr;
    *out_pk = nullptr;
    return BICYCL_ERR_PAILLIER;
  }
}

void bicycl_paillier_sk_free(bicycl_paillier_sk_t *sk) { delete sk; }
void bicycl_paillier_pk_free(bicycl_paillier_pk_t *pk) { delete pk; }
void bicycl_paillier_ct_free(bicycl_paillier_ct_t *ct) { delete ct; }

bicycl_status_t bicycl_paillier_encrypt_decimal(
    bicycl_context_t *ctx,
    const bicycl_paillier_t *paillier,
    const bicycl_paillier_pk_t *pk,
    bicycl_randgen_t *randgen,
    const char *message_decimal,
    bicycl_paillier_ct_t **out_ct) {
  clear_error(ctx);
  if (ctx == nullptr || paillier == nullptr || pk == nullptr || randgen == nullptr || message_decimal == nullptr || out_ct == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }

  try {
    bicycl_status_t status = BICYCL_OK;
    BICYCL::Mpz message = parse_decimal(ctx, message_decimal, "message_decimal", &status);
    if (status != BICYCL_OK) {
      return status;
    }

    BICYCL::Paillier::ClearText clear(paillier->value, pk->value, message);
    BICYCL::Paillier::CipherText ct = paillier->value.encrypt(pk->value, clear, randgen->value);
    *out_ct = new bicycl_paillier_ct_t(ct);
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out_ct = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out_ct = nullptr;
    return BICYCL_ERR_INVALID_ARGUMENT;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out_ct = nullptr;
    return BICYCL_ERR_PAILLIER;
  }
}

bicycl_status_t bicycl_paillier_decrypt_decimal(
    bicycl_context_t *ctx,
    const bicycl_paillier_t *paillier,
    const bicycl_paillier_pk_t *pk,
    const bicycl_paillier_sk_t *sk,
    const bicycl_paillier_ct_t *ct,
    char *out_buf,
    size_t *inout_len) {
  clear_error(ctx);
  if (ctx == nullptr || paillier == nullptr || pk == nullptr || sk == nullptr || ct == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }

  try {
    BICYCL::Paillier::ClearText clear = paillier->value.decrypt(pk->value, sk->value, ct->value);
    return write_c_string(ctx, mpz_to_string(clear), out_buf, inout_len);
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_PAILLIER;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_PAILLIER;
  }
}

bicycl_status_t bicycl_joye_libert_new(
    bicycl_context_t *ctx,
    uint32_t modulus_bits,
    uint32_t k,
    bicycl_joye_libert_t **out_joye_libert) {
  clear_error(ctx);
  if (ctx == nullptr || out_joye_libert == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  if (modulus_bits < 32U || k == 0U) {
    set_error(ctx, "modulus_bits must be >= 32 and k must be > 0");
    return BICYCL_ERR_INVALID_ARGUMENT;
  }

  try {
    *out_joye_libert = new bicycl_joye_libert_t(static_cast<size_t>(modulus_bits), static_cast<size_t>(k));
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out_joye_libert = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out_joye_libert = nullptr;
    return BICYCL_ERR_JOYE_LIBERT;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out_joye_libert = nullptr;
    return BICYCL_ERR_JOYE_LIBERT;
  }
}

void bicycl_joye_libert_free(bicycl_joye_libert_t *joye_libert) { delete joye_libert; }

bicycl_status_t bicycl_joye_libert_keygen(
    bicycl_context_t *ctx,
    const bicycl_joye_libert_t *joye_libert,
    bicycl_randgen_t *randgen,
    bicycl_joye_libert_sk_t **out_sk,
    bicycl_joye_libert_pk_t **out_pk) {
  clear_error(ctx);
  if (ctx == nullptr || joye_libert == nullptr || randgen == nullptr || out_sk == nullptr || out_pk == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }

  try {
    BICYCL::JoyeLibert::SecretKey sk = joye_libert->value.keygen(randgen->value);
    BICYCL::JoyeLibert::PublicKey pk = joye_libert->value.keygen(sk);
    *out_sk = new bicycl_joye_libert_sk_t(sk);
    *out_pk = new bicycl_joye_libert_pk_t(pk);
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out_sk = nullptr;
    *out_pk = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out_sk = nullptr;
    *out_pk = nullptr;
    return BICYCL_ERR_JOYE_LIBERT;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out_sk = nullptr;
    *out_pk = nullptr;
    return BICYCL_ERR_JOYE_LIBERT;
  }
}

void bicycl_joye_libert_sk_free(bicycl_joye_libert_sk_t *sk) { delete sk; }
void bicycl_joye_libert_pk_free(bicycl_joye_libert_pk_t *pk) { delete pk; }
void bicycl_joye_libert_ct_free(bicycl_joye_libert_ct_t *ct) { delete ct; }

bicycl_status_t bicycl_joye_libert_encrypt_decimal(
    bicycl_context_t *ctx,
    const bicycl_joye_libert_t *joye_libert,
    const bicycl_joye_libert_pk_t *pk,
    bicycl_randgen_t *randgen,
    const char *message_decimal,
    bicycl_joye_libert_ct_t **out_ct) {
  clear_error(ctx);
  if (ctx == nullptr || joye_libert == nullptr || pk == nullptr || randgen == nullptr || message_decimal == nullptr || out_ct == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }

  try {
    bicycl_status_t status = BICYCL_OK;
    BICYCL::Mpz message = parse_decimal(ctx, message_decimal, "message_decimal", &status);
    if (status != BICYCL_OK) {
      return status;
    }

    BICYCL::JoyeLibert::ClearText clear(joye_libert->value, message);
    BICYCL::JoyeLibert::CipherText ct = joye_libert->value.encrypt(pk->value, clear, randgen->value);
    *out_ct = new bicycl_joye_libert_ct_t(ct);
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out_ct = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out_ct = nullptr;
    return BICYCL_ERR_INVALID_ARGUMENT;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out_ct = nullptr;
    return BICYCL_ERR_JOYE_LIBERT;
  }
}

bicycl_status_t bicycl_joye_libert_decrypt_decimal(
    bicycl_context_t *ctx,
    const bicycl_joye_libert_t *joye_libert,
    const bicycl_joye_libert_sk_t *sk,
    const bicycl_joye_libert_ct_t *ct,
    char *out_buf,
    size_t *inout_len) {
  clear_error(ctx);
  if (ctx == nullptr || joye_libert == nullptr || sk == nullptr || ct == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }

  try {
    BICYCL::JoyeLibert::ClearText clear = joye_libert->value.decrypt(sk->value, ct->value);
    return write_c_string(ctx, mpz_to_string(clear), out_buf, inout_len);
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_JOYE_LIBERT;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_JOYE_LIBERT;
  }
}

bicycl_status_t bicycl_cl_hsmqk_new(
    bicycl_context_t *ctx,
    const char *q_decimal,
    uint32_t k,
    const char *p_decimal,
    bicycl_cl_hsmqk_t **out_cl) {
  clear_error(ctx);
  if (ctx == nullptr || out_cl == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  if (k == 0U) {
    set_error(ctx, "k must be > 0");
    return BICYCL_ERR_INVALID_ARGUMENT;
  }

  try {
    bicycl_status_t status = BICYCL_OK;
    BICYCL::Mpz q = parse_decimal(ctx, q_decimal, "q_decimal", &status);
    if (status != BICYCL_OK) {
      return status;
    }
    BICYCL::Mpz p = parse_decimal(ctx, p_decimal, "p_decimal", &status);
    if (status != BICYCL_OK) {
      return status;
    }

    *out_cl = new bicycl_cl_hsmqk_t(q, static_cast<size_t>(k), p);
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out_cl = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out_cl = nullptr;
    return BICYCL_ERR_INVALID_ARGUMENT;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out_cl = nullptr;
    return BICYCL_ERR_CL_HSMQK;
  }
}

void bicycl_cl_hsmqk_free(bicycl_cl_hsmqk_t *cl) { delete cl; }

bicycl_status_t bicycl_cl_hsmqk_keygen(
    bicycl_context_t *ctx,
    const bicycl_cl_hsmqk_t *cl,
    bicycl_randgen_t *randgen,
    bicycl_cl_hsmqk_sk_t **out_sk,
    bicycl_cl_hsmqk_pk_t **out_pk) {
  clear_error(ctx);
  if (ctx == nullptr || cl == nullptr || randgen == nullptr || out_sk == nullptr || out_pk == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }

  try {
    BICYCL::CL_HSMqk::SecretKey sk = cl->value.keygen(randgen->value);
    BICYCL::CL_HSMqk::PublicKey pk = cl->value.keygen(sk);
    *out_sk = new bicycl_cl_hsmqk_sk_t(sk);
    *out_pk = new bicycl_cl_hsmqk_pk_t(pk);
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out_sk = nullptr;
    *out_pk = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out_sk = nullptr;
    *out_pk = nullptr;
    return BICYCL_ERR_CL_HSMQK;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out_sk = nullptr;
    *out_pk = nullptr;
    return BICYCL_ERR_CL_HSMQK;
  }
}

void bicycl_cl_hsmqk_sk_free(bicycl_cl_hsmqk_sk_t *sk) { delete sk; }
void bicycl_cl_hsmqk_pk_free(bicycl_cl_hsmqk_pk_t *pk) { delete pk; }
void bicycl_cl_hsmqk_ct_free(bicycl_cl_hsmqk_ct_t *ct) { delete ct; }

bicycl_status_t bicycl_cl_hsmqk_encrypt_decimal(
    bicycl_context_t *ctx,
    const bicycl_cl_hsmqk_t *cl,
    const bicycl_cl_hsmqk_pk_t *pk,
    bicycl_randgen_t *randgen,
    const char *message_decimal,
    bicycl_cl_hsmqk_ct_t **out_ct) {
  clear_error(ctx);
  if (ctx == nullptr || cl == nullptr || pk == nullptr || randgen == nullptr || message_decimal == nullptr || out_ct == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }

  try {
    bicycl_status_t status = BICYCL_OK;
    BICYCL::Mpz message = parse_decimal(ctx, message_decimal, "message_decimal", &status);
    if (status != BICYCL_OK) {
      return status;
    }

    BICYCL::CL_HSMqk::ClearText clear(cl->value, message);
    BICYCL::CL_HSMqk::CipherText ct = cl->value.encrypt(pk->value, clear, randgen->value);
    *out_ct = new bicycl_cl_hsmqk_ct_t(ct);
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out_ct = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out_ct = nullptr;
    return BICYCL_ERR_INVALID_ARGUMENT;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out_ct = nullptr;
    return BICYCL_ERR_CL_HSMQK;
  }
}

bicycl_status_t bicycl_cl_hsmqk_decrypt_decimal(
    bicycl_context_t *ctx,
    const bicycl_cl_hsmqk_t *cl,
    const bicycl_cl_hsmqk_sk_t *sk,
    const bicycl_cl_hsmqk_ct_t *ct,
    char *out_buf,
    size_t *inout_len) {
  clear_error(ctx);
  if (ctx == nullptr || cl == nullptr || sk == nullptr || ct == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }

  try {
    BICYCL::CL_HSMqk::ClearText clear = cl->value.decrypt(sk->value, ct->value);
    return write_c_string(ctx, mpz_to_string(clear), out_buf, inout_len);
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_CL_HSMQK;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_CL_HSMQK;
  }
}

bicycl_status_t bicycl_cl_hsmqk_add_ciphertexts(
    bicycl_context_t *ctx,
    const bicycl_cl_hsmqk_t *cl,
    const bicycl_cl_hsmqk_pk_t *pk,
    bicycl_randgen_t *randgen,
    const bicycl_cl_hsmqk_ct_t *ca,
    const bicycl_cl_hsmqk_ct_t *cb,
    bicycl_cl_hsmqk_ct_t **out_ct) {
  clear_error(ctx);
  if (ctx == nullptr || cl == nullptr || pk == nullptr || randgen == nullptr || ca == nullptr || cb == nullptr || out_ct == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }

  try {
    BICYCL::CL_HSMqk::CipherText ct = cl->value.add_ciphertexts(pk->value, ca->value, cb->value, randgen->value);
    *out_ct = new bicycl_cl_hsmqk_ct_t(ct);
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out_ct = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out_ct = nullptr;
    return BICYCL_ERR_CL_HSMQK;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out_ct = nullptr;
    return BICYCL_ERR_CL_HSMQK;
  }
}

bicycl_status_t bicycl_cl_hsmqk_scal_ciphertext_decimal(
    bicycl_context_t *ctx,
    const bicycl_cl_hsmqk_t *cl,
    const bicycl_cl_hsmqk_pk_t *pk,
    bicycl_randgen_t *randgen,
    const bicycl_cl_hsmqk_ct_t *ct,
    const char *scalar_decimal,
    bicycl_cl_hsmqk_ct_t **out_ct) {
  clear_error(ctx);
  if (ctx == nullptr || cl == nullptr || pk == nullptr || randgen == nullptr || ct == nullptr || scalar_decimal == nullptr || out_ct == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }

  try {
    bicycl_status_t status = BICYCL_OK;
    BICYCL::Mpz scalar = parse_decimal(ctx, scalar_decimal, "scalar_decimal", &status);
    if (status != BICYCL_OK) {
      return status;
    }
    BICYCL::CL_HSMqk::CipherText out = cl->value.scal_ciphertexts(pk->value, ct->value, scalar, randgen->value);
    *out_ct = new bicycl_cl_hsmqk_ct_t(out);
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out_ct = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out_ct = nullptr;
    return BICYCL_ERR_INVALID_ARGUMENT;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out_ct = nullptr;
    return BICYCL_ERR_CL_HSMQK;
  }
}

bicycl_status_t bicycl_cl_hsmqk_addscal_ciphertexts_decimal(
    bicycl_context_t *ctx,
    const bicycl_cl_hsmqk_t *cl,
    const bicycl_cl_hsmqk_pk_t *pk,
    bicycl_randgen_t *randgen,
    const bicycl_cl_hsmqk_ct_t *ca,
    const bicycl_cl_hsmqk_ct_t *cb,
    const char *scalar_decimal,
    bicycl_cl_hsmqk_ct_t **out_ct) {
  clear_error(ctx);
  if (ctx == nullptr || cl == nullptr || pk == nullptr || randgen == nullptr || ca == nullptr || cb == nullptr || scalar_decimal == nullptr || out_ct == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }

  try {
    bicycl_status_t status = BICYCL_OK;
    BICYCL::Mpz scalar = parse_decimal(ctx, scalar_decimal, "scalar_decimal", &status);
    if (status != BICYCL_OK) {
      return status;
    }
    BICYCL::CL_HSMqk::CipherText out = cl->value.addscal_ciphertexts(pk->value, ca->value, cb->value, scalar, randgen->value);
    *out_ct = new bicycl_cl_hsmqk_ct_t(out);
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out_ct = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out_ct = nullptr;
    return BICYCL_ERR_INVALID_ARGUMENT;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out_ct = nullptr;
    return BICYCL_ERR_CL_HSMQK;
  }
}

bicycl_status_t bicycl_cl_hsm2k_new(
    bicycl_context_t *ctx,
    const char *N_decimal,
    uint32_t k,
    bicycl_cl_hsm2k_t **out_cl) {
  clear_error(ctx);
  if (ctx == nullptr || out_cl == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  if (k == 0U) {
    set_error(ctx, "k must be > 0");
    return BICYCL_ERR_INVALID_ARGUMENT;
  }

  try {
    bicycl_status_t status = BICYCL_OK;
    BICYCL::Mpz N = parse_decimal(ctx, N_decimal, "N_decimal", &status);
    if (status != BICYCL_OK) {
      return status;
    }
    *out_cl = new bicycl_cl_hsm2k_t(N, static_cast<size_t>(k));
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out_cl = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out_cl = nullptr;
    return BICYCL_ERR_INVALID_ARGUMENT;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out_cl = nullptr;
    return BICYCL_ERR_CL_HSM2K;
  }
}

void bicycl_cl_hsm2k_free(bicycl_cl_hsm2k_t *cl) { delete cl; }

bicycl_status_t bicycl_cl_hsm2k_keygen(
    bicycl_context_t *ctx,
    const bicycl_cl_hsm2k_t *cl,
    bicycl_randgen_t *randgen,
    bicycl_cl_hsm2k_sk_t **out_sk,
    bicycl_cl_hsm2k_pk_t **out_pk) {
  clear_error(ctx);
  if (ctx == nullptr || cl == nullptr || randgen == nullptr || out_sk == nullptr || out_pk == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }

  try {
    BICYCL::CL_HSM2k::SecretKey sk = cl->value.keygen(randgen->value);
    BICYCL::CL_HSM2k::PublicKey pk = cl->value.keygen(sk);
    *out_sk = new bicycl_cl_hsm2k_sk_t(sk);
    *out_pk = new bicycl_cl_hsm2k_pk_t(pk);
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out_sk = nullptr;
    *out_pk = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out_sk = nullptr;
    *out_pk = nullptr;
    return BICYCL_ERR_CL_HSM2K;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out_sk = nullptr;
    *out_pk = nullptr;
    return BICYCL_ERR_CL_HSM2K;
  }
}

void bicycl_cl_hsm2k_sk_free(bicycl_cl_hsm2k_sk_t *sk) { delete sk; }
void bicycl_cl_hsm2k_pk_free(bicycl_cl_hsm2k_pk_t *pk) { delete pk; }
void bicycl_cl_hsm2k_ct_free(bicycl_cl_hsm2k_ct_t *ct) { delete ct; }

bicycl_status_t bicycl_cl_hsm2k_encrypt_decimal(
    bicycl_context_t *ctx,
    const bicycl_cl_hsm2k_t *cl,
    const bicycl_cl_hsm2k_pk_t *pk,
    bicycl_randgen_t *randgen,
    const char *message_decimal,
    bicycl_cl_hsm2k_ct_t **out_ct) {
  clear_error(ctx);
  if (ctx == nullptr || cl == nullptr || pk == nullptr || randgen == nullptr || message_decimal == nullptr || out_ct == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }

  try {
    bicycl_status_t status = BICYCL_OK;
    BICYCL::Mpz message = parse_decimal(ctx, message_decimal, "message_decimal", &status);
    if (status != BICYCL_OK) {
      return status;
    }
    BICYCL::CL_HSM2k::ClearText clear(cl->value, message);
    BICYCL::CL_HSM2k::CipherText ct = cl->value.encrypt(pk->value, clear, randgen->value);
    *out_ct = new bicycl_cl_hsm2k_ct_t(ct);
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out_ct = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out_ct = nullptr;
    return BICYCL_ERR_INVALID_ARGUMENT;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out_ct = nullptr;
    return BICYCL_ERR_CL_HSM2K;
  }
}

bicycl_status_t bicycl_cl_hsm2k_decrypt_decimal(
    bicycl_context_t *ctx,
    const bicycl_cl_hsm2k_t *cl,
    const bicycl_cl_hsm2k_sk_t *sk,
    const bicycl_cl_hsm2k_ct_t *ct,
    char *out_buf,
    size_t *inout_len) {
  clear_error(ctx);
  if (ctx == nullptr || cl == nullptr || sk == nullptr || ct == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }

  try {
    BICYCL::CL_HSM2k::ClearText clear = cl->value.decrypt(sk->value, ct->value);
    return write_c_string(ctx, mpz_to_string(clear), out_buf, inout_len);
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_CL_HSM2K;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_CL_HSM2K;
  }
}

bicycl_status_t bicycl_cl_hsm2k_add_ciphertexts(
    bicycl_context_t *ctx,
    const bicycl_cl_hsm2k_t *cl,
    const bicycl_cl_hsm2k_pk_t *pk,
    bicycl_randgen_t *randgen,
    const bicycl_cl_hsm2k_ct_t *ca,
    const bicycl_cl_hsm2k_ct_t *cb,
    bicycl_cl_hsm2k_ct_t **out_ct) {
  clear_error(ctx);
  if (ctx == nullptr || cl == nullptr || pk == nullptr || randgen == nullptr || ca == nullptr || cb == nullptr || out_ct == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }

  try {
    BICYCL::CL_HSM2k::CipherText ct = cl->value.add_ciphertexts(pk->value, ca->value, cb->value, randgen->value);
    *out_ct = new bicycl_cl_hsm2k_ct_t(ct);
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out_ct = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out_ct = nullptr;
    return BICYCL_ERR_CL_HSM2K;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out_ct = nullptr;
    return BICYCL_ERR_CL_HSM2K;
  }
}

bicycl_status_t bicycl_cl_hsm2k_scal_ciphertext_decimal(
    bicycl_context_t *ctx,
    const bicycl_cl_hsm2k_t *cl,
    const bicycl_cl_hsm2k_pk_t *pk,
    bicycl_randgen_t *randgen,
    const bicycl_cl_hsm2k_ct_t *ct,
    const char *scalar_decimal,
    bicycl_cl_hsm2k_ct_t **out_ct) {
  clear_error(ctx);
  if (ctx == nullptr || cl == nullptr || pk == nullptr || randgen == nullptr || ct == nullptr || scalar_decimal == nullptr || out_ct == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }

  try {
    bicycl_status_t status = BICYCL_OK;
    BICYCL::Mpz scalar = parse_decimal(ctx, scalar_decimal, "scalar_decimal", &status);
    if (status != BICYCL_OK) {
      return status;
    }
    BICYCL::CL_HSM2k::CipherText out = cl->value.scal_ciphertexts(pk->value, ct->value, scalar, randgen->value);
    *out_ct = new bicycl_cl_hsm2k_ct_t(out);
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out_ct = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out_ct = nullptr;
    return BICYCL_ERR_INVALID_ARGUMENT;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out_ct = nullptr;
    return BICYCL_ERR_CL_HSM2K;
  }
}

bicycl_status_t bicycl_cl_hsm2k_addscal_ciphertexts_decimal(
    bicycl_context_t *ctx,
    const bicycl_cl_hsm2k_t *cl,
    const bicycl_cl_hsm2k_pk_t *pk,
    bicycl_randgen_t *randgen,
    const bicycl_cl_hsm2k_ct_t *ca,
    const bicycl_cl_hsm2k_ct_t *cb,
    const char *scalar_decimal,
    bicycl_cl_hsm2k_ct_t **out_ct) {
  clear_error(ctx);
  if (ctx == nullptr || cl == nullptr || pk == nullptr || randgen == nullptr || ca == nullptr || cb == nullptr || scalar_decimal == nullptr || out_ct == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }

  try {
    bicycl_status_t status = BICYCL_OK;
    BICYCL::Mpz scalar = parse_decimal(ctx, scalar_decimal, "scalar_decimal", &status);
    if (status != BICYCL_OK) {
      return status;
    }
    BICYCL::CL_HSM2k::CipherText out = cl->value.addscal_ciphertexts(pk->value, ca->value, cb->value, scalar, randgen->value);
    *out_ct = new bicycl_cl_hsm2k_ct_t(out);
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out_ct = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out_ct = nullptr;
    return BICYCL_ERR_INVALID_ARGUMENT;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out_ct = nullptr;
    return BICYCL_ERR_CL_HSM2K;
  }
}

bicycl_status_t bicycl_ecdsa_new(
    bicycl_context_t *ctx,
    uint32_t seclevel_bits,
    bicycl_ecdsa_t **out_ecdsa) {
  clear_error(ctx);
  if (ctx == nullptr || out_ecdsa == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }

  try {
    BICYCL::SecLevel seclevel(seclevel_bits);
    *out_ecdsa = new bicycl_ecdsa_t(seclevel);
    return BICYCL_OK;
  } catch (const BICYCL::InvalidSecLevelException &) {
    set_error(ctx, "invalid seclevel bits; expected one of 112, 128, 192, 256");
    *out_ecdsa = nullptr;
    return BICYCL_ERR_INVALID_ARGUMENT;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out_ecdsa = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out_ecdsa = nullptr;
    return BICYCL_ERR_ECDSA;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out_ecdsa = nullptr;
    return BICYCL_ERR_ECDSA;
  }
}

void bicycl_ecdsa_free(bicycl_ecdsa_t *ecdsa) { delete ecdsa; }

bicycl_status_t bicycl_ecdsa_keygen(
    bicycl_context_t *ctx,
    const bicycl_ecdsa_t *ecdsa,
    bicycl_randgen_t *randgen,
    bicycl_ecdsa_sk_t **out_sk,
    bicycl_ecdsa_pk_t **out_pk) {
  clear_error(ctx);
  if (ctx == nullptr || ecdsa == nullptr || randgen == nullptr || out_sk == nullptr || out_pk == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }

  try {
    BICYCL::ECDSA::SecretKey sk = ecdsa->value.keygen(randgen->value);
    BICYCL::ECDSA::PublicKey pk = ecdsa->value.keygen(sk);
    *out_sk = new bicycl_ecdsa_sk_t(std::move(sk));
    *out_pk = new bicycl_ecdsa_pk_t(std::move(pk));
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out_sk = nullptr;
    *out_pk = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out_sk = nullptr;
    *out_pk = nullptr;
    return BICYCL_ERR_ECDSA;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out_sk = nullptr;
    *out_pk = nullptr;
    return BICYCL_ERR_ECDSA;
  }
}

void bicycl_ecdsa_sk_free(bicycl_ecdsa_sk_t *sk) { delete sk; }
void bicycl_ecdsa_pk_free(bicycl_ecdsa_pk_t *pk) { delete pk; }

bicycl_status_t bicycl_ecdsa_sign_message(
    bicycl_context_t *ctx,
    const bicycl_ecdsa_t *ecdsa,
    bicycl_randgen_t *randgen,
    const bicycl_ecdsa_sk_t *sk,
    const uint8_t *msg_ptr,
    size_t msg_len,
    bicycl_ecdsa_sig_t **out_sig) {
  clear_error(ctx);
  if (ctx == nullptr || ecdsa == nullptr || randgen == nullptr || sk == nullptr || out_sig == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  if (msg_ptr == nullptr && msg_len > 0) {
    set_error(ctx, "msg_ptr is null with non-zero msg_len");
    return BICYCL_ERR_INVALID_ARGUMENT;
  }

  try {
    std::vector<unsigned char> msg;
    if (msg_len > 0) {
      msg.assign(msg_ptr, msg_ptr + msg_len);
    }
    BICYCL::HashAlgo::Digest digest = ecdsa->value.hash(msg);
    BICYCL::ECDSA::Signature sig = ecdsa->value.sign(randgen->value, sk->value, digest);
    *out_sig = new bicycl_ecdsa_sig_t(sig);
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    *out_sig = nullptr;
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    *out_sig = nullptr;
    return BICYCL_ERR_ECDSA;
  } catch (...) {
    set_error(ctx, "unknown error");
    *out_sig = nullptr;
    return BICYCL_ERR_ECDSA;
  }
}

void bicycl_ecdsa_sig_free(bicycl_ecdsa_sig_t *sig) { delete sig; }

bicycl_status_t bicycl_ecdsa_verify_message(
    bicycl_context_t *ctx,
    const bicycl_ecdsa_t *ecdsa,
    const bicycl_ecdsa_pk_t *pk,
    const uint8_t *msg_ptr,
    size_t msg_len,
    const bicycl_ecdsa_sig_t *sig,
    int *out_valid) {
  clear_error(ctx);
  if (ctx == nullptr || ecdsa == nullptr || pk == nullptr || sig == nullptr || out_valid == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  if (msg_ptr == nullptr && msg_len > 0) {
    set_error(ctx, "msg_ptr is null with non-zero msg_len");
    return BICYCL_ERR_INVALID_ARGUMENT;
  }

  try {
    std::vector<unsigned char> msg;
    if (msg_len > 0) {
      msg.assign(msg_ptr, msg_ptr + msg_len);
    }
    BICYCL::HashAlgo::Digest digest = ecdsa->value.hash(msg);
    *out_valid = ecdsa->value.verif(sig->value, pk->value, digest) ? 1 : 0;
    return BICYCL_OK;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_ECDSA;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_ECDSA;
  }
}

bicycl_status_t bicycl_ecdsa_sig_r_decimal(
    bicycl_context_t *ctx,
    const bicycl_ecdsa_sig_t *sig,
    char *out_buf,
    size_t *inout_len) {
  clear_error(ctx);
  if (ctx == nullptr || sig == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  try {
    return write_c_string(ctx, bn_to_string(sig->value.r()), out_buf, inout_len);
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_ECDSA;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_ECDSA;
  }
}

bicycl_status_t bicycl_ecdsa_sig_s_decimal(
    bicycl_context_t *ctx,
    const bicycl_ecdsa_sig_t *sig,
    char *out_buf,
    size_t *inout_len) {
  clear_error(ctx);
  if (ctx == nullptr || sig == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  try {
    return write_c_string(ctx, bn_to_string(sig->value.s()), out_buf, inout_len);
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_ECDSA;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_ECDSA;
  }
}

bicycl_status_t bicycl_two_party_ecdsa_session_new(
    bicycl_context_t *ctx,
    bicycl_randgen_t *randgen,
    uint32_t seclevel_bits,
    bicycl_two_party_ecdsa_session_t **out_session) {
  clear_error(ctx);
  if (ctx == nullptr || randgen == nullptr || out_session == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  *out_session = nullptr;
  try {
    BICYCL::SecLevel seclevel(seclevel_bits);
    *out_session = new bicycl_two_party_ecdsa_session_t(seclevel, randgen->value);
    return BICYCL_OK;
  } catch (const BICYCL::InvalidSecLevelException &) {
    set_error(ctx, "invalid seclevel bits; expected one of 112, 128, 192, 256");
    return BICYCL_ERR_INVALID_ARGUMENT;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_TWO_PARTY_ECDSA;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_TWO_PARTY_ECDSA;
  }
}

void bicycl_two_party_ecdsa_session_free(bicycl_two_party_ecdsa_session_t *session) {
  delete session;
}

bicycl_status_t bicycl_two_party_ecdsa_keygen_round1(
    bicycl_context_t *ctx,
    bicycl_two_party_ecdsa_session_t *session,
    bicycl_randgen_t *randgen) {
  clear_error(ctx);
  if (ctx == nullptr || session == nullptr || randgen == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  if (session->stage != 0) {
    return invalid_stage(ctx, "two_party_ecdsa_keygen_round1", 0, session->stage);
  }
  try {
    session->p1->KeygenPart1(*session->context, randgen->value);
    session->stage = 1;
    return BICYCL_OK;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_TWO_PARTY_ECDSA;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_TWO_PARTY_ECDSA;
  }
}

bicycl_status_t bicycl_two_party_ecdsa_keygen_round2(
    bicycl_context_t *ctx,
    bicycl_two_party_ecdsa_session_t *session,
    bicycl_randgen_t *randgen) {
  clear_error(ctx);
  if (ctx == nullptr || session == nullptr || randgen == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  if (session->stage != 1) {
    return invalid_stage(ctx, "two_party_ecdsa_keygen_round2", 1, session->stage);
  }
  try {
    session->p2->KeygenPart2(*session->context, randgen->value, session->p1->commit());
    session->stage = 2;
    return BICYCL_OK;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_TWO_PARTY_ECDSA;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_TWO_PARTY_ECDSA;
  }
}

bicycl_status_t bicycl_two_party_ecdsa_keygen_round3(
    bicycl_context_t *ctx,
    bicycl_two_party_ecdsa_session_t *session,
    bicycl_randgen_t *randgen) {
  clear_error(ctx);
  if (ctx == nullptr || session == nullptr || randgen == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  if (session->stage != 2) {
    return invalid_stage(ctx, "two_party_ecdsa_keygen_round3", 2, session->stage);
  }
  try {
    session->p1->KeygenPart3(*session->context, randgen->value, session->p2->Q2(), session->p2->zk_proof());
    session->stage = 3;
    return BICYCL_OK;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_TWO_PARTY_ECDSA;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_TWO_PARTY_ECDSA;
  }
}

bicycl_status_t bicycl_two_party_ecdsa_keygen_round4(
    bicycl_context_t *ctx,
    bicycl_two_party_ecdsa_session_t *session) {
  clear_error(ctx);
  if (ctx == nullptr || session == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  if (session->stage != 3) {
    return invalid_stage(ctx, "two_party_ecdsa_keygen_round4", 3, session->stage);
  }
  try {
    session->p2->KeygenPart4(*session->context,
                             session->p1->Q1(),
                             session->p1->Ckey(),
                             session->p1->pkcl(),
                             session->p1->commit_secret(),
                             session->p1->zk_com_proof(),
                             session->p1->proof_ckey());
    session->stage = 4;
    return BICYCL_OK;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_TWO_PARTY_ECDSA;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_TWO_PARTY_ECDSA;
  }
}

bicycl_status_t bicycl_two_party_ecdsa_sign_round1(
    bicycl_context_t *ctx,
    bicycl_two_party_ecdsa_session_t *session,
    bicycl_randgen_t *randgen,
    const uint8_t *msg_ptr,
    size_t msg_len) {
  clear_error(ctx);
  if (ctx == nullptr || session == nullptr || randgen == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  if (msg_ptr == nullptr && msg_len > 0) {
    set_error(ctx, "msg_ptr is null with non-zero msg_len");
    return BICYCL_ERR_INVALID_ARGUMENT;
  }
  if (session->stage != 4) {
    return invalid_stage(ctx, "two_party_ecdsa_sign_round1", 4, session->stage);
  }
  try {
    std::vector<unsigned char> msg;
    if (msg_len > 0) {
      msg.assign(msg_ptr, msg_ptr + msg_len);
    }
    session->hashed.reset(new BICYCL::HashAlgo::Digest(session->context->hash(msg)));
    session->sid.reset(new BICYCL::Mpz(randgen->value.random_mpz_2exp(128)));
    session->signature.reset();
    session->p1->SignPart1(*session->context, randgen->value, *session->sid);
    session->stage = 5;
    return BICYCL_OK;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_TWO_PARTY_ECDSA;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_TWO_PARTY_ECDSA;
  }
}

bicycl_status_t bicycl_two_party_ecdsa_sign_round2(
    bicycl_context_t *ctx,
    bicycl_two_party_ecdsa_session_t *session,
    bicycl_randgen_t *randgen) {
  clear_error(ctx);
  if (ctx == nullptr || session == nullptr || randgen == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  if (session->stage != 5) {
    return invalid_stage(ctx, "two_party_ecdsa_sign_round2", 5, session->stage);
  }
  if (session->sid == nullptr) {
    set_error(ctx, "missing signing sid");
    return BICYCL_ERR_INVALID_STATE;
  }
  try {
    session->p2->SignPart2(*session->context, randgen->value, session->p1->commit(), *session->sid);
    session->stage = 6;
    return BICYCL_OK;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_TWO_PARTY_ECDSA;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_TWO_PARTY_ECDSA;
  }
}

bicycl_status_t bicycl_two_party_ecdsa_sign_round3(
    bicycl_context_t *ctx,
    bicycl_two_party_ecdsa_session_t *session) {
  clear_error(ctx);
  if (ctx == nullptr || session == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  if (session->stage != 6) {
    return invalid_stage(ctx, "two_party_ecdsa_sign_round3", 6, session->stage);
  }
  if (session->sid == nullptr) {
    set_error(ctx, "missing signing sid");
    return BICYCL_ERR_INVALID_STATE;
  }
  try {
    session->p1->SignPart3(*session->context, session->p2->R2(), session->p2->zk_proof(), *session->sid);
    session->stage = 7;
    return BICYCL_OK;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_TWO_PARTY_ECDSA;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_TWO_PARTY_ECDSA;
  }
}

bicycl_status_t bicycl_two_party_ecdsa_sign_round4(
    bicycl_context_t *ctx,
    bicycl_two_party_ecdsa_session_t *session,
    bicycl_randgen_t *randgen) {
  clear_error(ctx);
  if (ctx == nullptr || session == nullptr || randgen == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  if (session->stage != 7) {
    return invalid_stage(ctx, "two_party_ecdsa_sign_round4", 7, session->stage);
  }
  if (session->sid == nullptr || session->hashed == nullptr) {
    set_error(ctx, "missing signing state");
    return BICYCL_ERR_INVALID_STATE;
  }
  try {
    session->p2->SignPart4(*session->context,
                           randgen->value,
                           *session->hashed,
                           session->p1->R1(),
                           session->p1->commit_secret(),
                           session->p1->zk_com_proof(),
                           *session->sid);
    session->stage = 8;
    return BICYCL_OK;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_TWO_PARTY_ECDSA;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_TWO_PARTY_ECDSA;
  }
}

bicycl_status_t bicycl_two_party_ecdsa_sign_finalize(
    bicycl_context_t *ctx,
    bicycl_two_party_ecdsa_session_t *session,
    int *out_valid) {
  clear_error(ctx);
  if (ctx == nullptr || session == nullptr || out_valid == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  if (session->stage != 8) {
    return invalid_stage(ctx, "two_party_ecdsa_sign_finalize", 8, session->stage);
  }
  if (session->hashed == nullptr) {
    set_error(ctx, "missing signing hash");
    return BICYCL_ERR_INVALID_STATE;
  }
  try {
    session->signature.reset(new BICYCL::ECSignature(
        session->p1->SignPart5(*session->context, *session->hashed, session->p2->C3())));
    *out_valid = session->context->verify(*session->signature, session->p1->public_key(), *session->hashed) ? 1 : 0;
    session->stage = 4;  // allow signing another message
    return BICYCL_OK;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_TWO_PARTY_ECDSA;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_TWO_PARTY_ECDSA;
  }
}

bicycl_status_t bicycl_two_party_ecdsa_run_demo(
    bicycl_context_t *ctx,
    bicycl_randgen_t *randgen,
    uint32_t seclevel_bits,
    const uint8_t *msg_ptr,
    size_t msg_len,
    int *out_valid) {
  clear_error(ctx);
  if (ctx == nullptr || randgen == nullptr || out_valid == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  if (msg_ptr == nullptr && msg_len > 0) {
    set_error(ctx, "msg_ptr is null with non-zero msg_len");
    return BICYCL_ERR_INVALID_ARGUMENT;
  }

  try {
    BICYCL::SecLevel seclevel(seclevel_bits);
    BICYCL::TwoPartyECDSA context(seclevel, randgen->value);
    BICYCL::TwoPartyECDSA::Player1 p1(context);
    BICYCL::TwoPartyECDSA::Player2 p2(context);

    p1.KeygenPart1(context, randgen->value);
    p2.KeygenPart2(context, randgen->value, p1.commit());
    p1.KeygenPart3(context, randgen->value, p2.Q2(), p2.zk_proof());
    p2.KeygenPart4(context,
                   p1.Q1(),
                   p1.Ckey(),
                   p1.pkcl(),
                   p1.commit_secret(),
                   p1.zk_com_proof(),
                   p1.proof_ckey());

    std::vector<unsigned char> msg;
    if (msg_len > 0) {
      msg.assign(msg_ptr, msg_ptr + msg_len);
    }
    BICYCL::HashAlgo::Digest hashed = context.hash(msg);
    BICYCL::Mpz sid = randgen->value.random_mpz_2exp(128);

    p1.SignPart1(context, randgen->value, sid);
    p2.SignPart2(context, randgen->value, p1.commit(), sid);
    p1.SignPart3(context, p2.R2(), p2.zk_proof(), sid);
    p2.SignPart4(context, randgen->value, hashed, p1.R1(), p1.commit_secret(), p1.zk_com_proof(), sid);
    BICYCL::ECSignature signature = p1.SignPart5(context, hashed, p2.C3());

    *out_valid = context.verify(signature, p1.public_key(), hashed) ? 1 : 0;
    return BICYCL_OK;
  } catch (const BICYCL::InvalidSecLevelException &) {
    set_error(ctx, "invalid seclevel bits; expected one of 112, 128, 192, 256");
    return BICYCL_ERR_INVALID_ARGUMENT;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_TWO_PARTY_ECDSA;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_TWO_PARTY_ECDSA;
  }
}

bicycl_status_t bicycl_cl_threshold_run_demo(
    bicycl_context_t *ctx,
    bicycl_randgen_t *randgen,
    char *out_buf,
    size_t *inout_len) {
  clear_error(ctx);
  if (ctx == nullptr || randgen == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }

  try {
    BICYCL::CL_HSMqk cl(
        BICYCL::SecLevel::_112.nbits() * 2,
        1u,
        BICYCL::SecLevel::_112,
        randgen->value);

    const unsigned int n = 3;
    const unsigned int t = 1;
    const size_t soundness = BICYCL::SecLevel::_112.nbits();
    BICYCL::CL_Threshold_Static p0(cl, n, t, 0, soundness);
    BICYCL::CL_Threshold_Static p1(cl, n, t, 1, soundness);
    BICYCL::CL_Threshold_Static p2(cl, n, t, 2, soundness);

    p0.keygen_dealing(cl, randgen->value);
    p1.keygen_dealing(cl, randgen->value);
    p2.keygen_dealing(cl, randgen->value);

    auto p0c = p0.C(); auto p1c = p1.C(); auto p2c = p2.C();
    auto p0p = p0.batch_proof(); auto p1p = p1.batch_proof(); auto p2p = p2.batch_proof();

    p1.keygen_add_commitments(0, p0c); p2.keygen_add_commitments(0, p0c);
    p0.keygen_add_commitments(1, p1c); p2.keygen_add_commitments(1, p1c);
    p0.keygen_add_commitments(2, p2c); p1.keygen_add_commitments(2, p2c);

    p1.keygen_add_proof(0, p0p); p2.keygen_add_proof(0, p0p);
    p0.keygen_add_proof(1, p1p); p2.keygen_add_proof(1, p1p);
    p0.keygen_add_proof(2, p2p); p1.keygen_add_proof(2, p2p);

    p1.keygen_add_share(0, p0.y_k(1)); p2.keygen_add_share(0, p0.y_k(2));
    p0.keygen_add_share(1, p1.y_k(0)); p2.keygen_add_share(1, p1.y_k(2));
    p0.keygen_add_share(2, p2.y_k(0)); p1.keygen_add_share(2, p2.y_k(1));

    bool success = p0.keygen_check_verify_all_players(cl)
                && p1.keygen_check_verify_all_players(cl)
                && p2.keygen_check_verify_all_players(cl);
    if (!success) {
      set_error(ctx, "CL threshold keygen check failed");
      return BICYCL_ERR_VERIFY_FAILED;
    }

    p0.keygen_extract(cl);
    p1.keygen_extract(cl);
    p2.keygen_extract(cl);

    BICYCL::CL_HSMqk::ClearText message(cl, BICYCL::Mpz("2"));
    BICYCL::CL_HSMqk::CipherText ct = cl.encrypt(p0.pk(), message, randgen->value);

    p0.decrypt_partial(cl, randgen->value, ct);
    p1.decrypt_partial(cl, randgen->value, ct);
    p1.decrypt_add_partial_dec(0, p0.part_dec());
    p0.decrypt_add_partial_dec(1, p1.part_dec());

    success = p0.decrypt_verify_batch(cl, randgen->value)
           && p1.decrypt_verify_batch(cl, randgen->value);
    if (!success) {
      set_error(ctx, "CL threshold decrypt verification failed");
      return BICYCL_ERR_VERIFY_FAILED;
    }

    BICYCL::CL_HSMqk::ClearText out;
    p0.decrypt_combine(out, cl, ct);
    return write_c_string(ctx, mpz_to_string(out), out_buf, inout_len);
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_CL_THRESHOLD;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_CL_THRESHOLD;
  }
}

bicycl_status_t bicycl_cl_dlog_proof_run_demo(
    bicycl_context_t *ctx,
    bicycl_randgen_t *randgen,
    uint32_t seclevel_bits,
    int *out_valid) {
  clear_error(ctx);
  if (ctx == nullptr || randgen == nullptr || out_valid == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }

  try {
    BICYCL::SecLevel seclevel(seclevel_bits);
    BICYCL::TwoPartyECDSA context(seclevel, randgen->value);
    const BICYCL::ECGroup &ec_group = context.ec_group();
    const BICYCL::CL_HSMqk &cl = context.CL_HSMq();

    BICYCL::CL_HSMqk::SecretKey sk = cl.keygen(randgen->value);
    BICYCL::CL_HSMqk::PublicKey pk = cl.keygen(sk);

    BICYCL::BN a = ec_group.random_mod_order(randgen->value);
    BICYCL::ECPoint q(ec_group);
    ec_group.scal_mul_gen(q, a);

    BICYCL::Mpz random = cl.encrypt_randomness_bound();
    BICYCL::CL_HSMqk::ClearText clear_a(cl, BICYCL::Mpz(a));
    BICYCL::CL_HSMqk::CipherText c(cl, pk, clear_a, random);

    BICYCL::CLDLZKProof proof(
        context.H(),
        context.ec_group(),
        a,
        q,
        cl,
        pk,
        c,
        random,
        randgen->value);

    *out_valid = proof.verify(context.H(), context.ec_group(), q, cl, pk, c) ? 1 : 0;
    return BICYCL_OK;
  } catch (const BICYCL::InvalidSecLevelException &) {
    set_error(ctx, "invalid seclevel bits; expected one of 112, 128, 192, 256");
    return BICYCL_ERR_INVALID_ARGUMENT;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_CL_DLOG;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_CL_DLOG;
  }
}

bicycl_status_t bicycl_threshold_ecdsa_run_demo(
    bicycl_context_t *ctx,
    bicycl_randgen_t *randgen,
    uint32_t seclevel_bits,
    const uint8_t *msg_ptr,
    size_t msg_len,
    int *out_valid) {
  clear_error(ctx);
  if (ctx == nullptr || randgen == nullptr || out_valid == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  if (msg_ptr == nullptr && msg_len > 0) {
    set_error(ctx, "msg_ptr is null with non-zero msg_len");
    return BICYCL_ERR_INVALID_ARGUMENT;
  }

  try {
    using TE = BICYCL::thresholdECDSA;
    using Keygen1 = TE::KeygenPart1;
    using Keygen2 = TE::KeygenPart2;
    using SecretKey = TE::SecretKey;
    using Sign1 = TE::SignPart1;
    using Sign2 = TE::SignPart2;
    using Sign3 = TE::SignPart3;
    using Sign4 = TE::SignPart4;
    using Sign5 = TE::SignPart5;
    using Sign6 = TE::SignPart6;
    using Sign7 = TE::SignPart7;
    using Sign8 = TE::SignPart8;
    using Signature = TE::Signature;

    BICYCL::SecLevel seclevel(seclevel_bits);
    TE context(seclevel, randgen->value);
    const BICYCL::ECGroup &ec = context.ec_group();

    const unsigned int n = 2;
    const unsigned int t = 1;
    TE::ParticipantsList participants{0u, 1u};

    std::vector<Keygen1> data1;
    data1.reserve(n);
    for (unsigned int i = 0; i < n; ++i) {
      data1.emplace_back(context, randgen->value, n, t, i);
    }

    std::vector<TE::Commitment> coq;
    std::vector<BICYCL::ECPoint> q_vec;
    std::vector<TE::CommitmentSecret> coqsec;
    std::vector<std::vector<BICYCL::ECPoint>> v;
    std::vector<std::vector<BICYCL::BN>> sigma(n);
    for (unsigned int i = 0; i < n; ++i) {
      coq.push_back(data1[i].commitment());
      q_vec.emplace_back(ec, data1[i].Q_part());
      coqsec.push_back(data1[i].commitment_secret());
      v.emplace_back();
      for (unsigned int k = 0; k < t; ++k) {
        v[i].emplace_back(ec, data1[i].V(k));
      }
      for (unsigned int j = 0; j < n; ++j) {
        sigma[j].push_back(data1[i].sigma(j));
      }
    }

    std::vector<Keygen2> data2;
    data2.reserve(n);
    for (unsigned int i = 0; i < n; ++i) {
      data2.emplace_back(context, data1[i], randgen->value, coq, q_vec, coqsec, v, sigma[i]);
    }

    std::vector<BICYCL::CL_HSMqk::PublicKey> pk;
    std::vector<BICYCL::ECNIZKProof> zk;
    for (unsigned int i = 0; i < n; ++i) {
      pk.push_back(data2[i].CL_public_key());
      zk.emplace_back(ec, data2[i].zk_proof());
    }

    std::vector<SecretKey> sk;
    sk.reserve(n);
    for (unsigned int i = 0; i < n; ++i) {
      sk.emplace_back(context, i, data1[i], data2[i], v, zk, pk);
    }

    std::vector<unsigned char> msg;
    if (msg_len > 0) {
      msg.assign(msg_ptr, msg_ptr + msg_len);
    }
    BICYCL::HashAlgo::Digest hashed = context.hash(msg);

    TE::ParticipantsMap<Sign1> s1;
    TE::ParticipantsMap<Sign2> s2;
    TE::ParticipantsMap<Sign3> s3;
    TE::ParticipantsMap<Sign4> s4;
    TE::ParticipantsMap<Sign5> s5;
    TE::ParticipantsMap<Sign6> s6;
    TE::ParticipantsMap<Sign7> s7;
    TE::ParticipantsMap<Sign8> s8;
    TE::ParticipantsMap<Signature> sigs;

    for (unsigned int i : participants) {
      s1.emplace(i, Sign1(context, randgen->value, i, participants, sk[i]));
    }

    TE::ParticipantsMap<TE::Commitment> co_map;
    TE::ParticipantsMap<BICYCL::CL_HSMqk::CipherText> c1;
    TE::ParticipantsMap<BICYCL::CL_HSMqk_ZKAoKProof> zk1;
    for (unsigned int i : participants) {
      co_map.emplace(i, s1.at(i).commitment());
      c1.emplace(i, s1.at(i).ciphertext());
      zk1.emplace(i, s1.at(i).zk_encrypt_proof());
    }

    for (unsigned int i : participants) {
      s2.emplace(i, Sign2(context, randgen->value, s1.at(i), sk[i], co_map, c1, zk1));
    }

    TE::ParticipantsMap<TE::ParticipantsMap<BICYCL::CL_HSMqk::CipherText>> c_kg_map;
    TE::ParticipantsMap<TE::ParticipantsMap<BICYCL::CL_HSMqk::CipherText>> c_kw_map;
    TE::ParticipantsMap<TE::ParticipantsMap<BICYCL::ECPoint>> b_map;
    for (unsigned int i : participants) {
      for (unsigned int j : participants) {
        if (i == j) {
          continue;
        }
        c_kg_map[i].emplace(j, s2.at(j).c_kg(i));
        c_kw_map[i].emplace(j, s2.at(j).c_kw(i));
        b_map[i].emplace(j, BICYCL::ECPoint(ec, s2.at(j).B(i)));
      }
    }

    for (unsigned int i : participants) {
      s3.emplace(i, Sign3(context, s1.at(i), s2.at(i), sk[i], c_kg_map.at(i), c_kw_map.at(i), b_map.at(i)));
    }

    TE::ParticipantsMap<BICYCL::BN> delta_map;
    for (unsigned int i : participants) {
      delta_map.emplace(i, s3.at(i).delta_part());
    }
    for (unsigned int i : participants) {
      s4.emplace(i, Sign4(context, s1.at(i), delta_map));
    }

    TE::ParticipantsMap<BICYCL::ECNIZKProof> zk_map;
    TE::ParticipantsMap<TE::CommitmentSecret> cos_map;
    TE::ParticipantsMap<BICYCL::ECPoint> gamma_map;
    for (unsigned int i : participants) {
      zk_map.emplace(i, BICYCL::ECNIZKProof(ec, s1.at(i).zk_gamma()));
      cos_map.emplace(i, s1.at(i).commitment_secret());
      gamma_map.emplace(i, BICYCL::ECPoint(ec, s1.at(i).Gamma()));
    }
    for (unsigned int i : participants) {
      s5.emplace(i, Sign5(context, randgen->value, s1.at(i), s2.at(i), s3.at(i), s4.at(i), hashed, gamma_map, cos_map, zk_map));
    }

    TE::ParticipantsMap<TE::Commitment> co2_map;
    for (unsigned int i : participants) {
      co2_map.emplace(i, s5.at(i).commitment());
    }
    for (unsigned int i : participants) {
      s6.emplace(i, Sign6(context, randgen->value, s5.at(i), co2_map));
    }

    TE::ParticipantsMap<BICYCL::ECNIZKAoK> aok_map;
    TE::ParticipantsMap<TE::CommitmentSecret> c2s_map;
    TE::ParticipantsMap<BICYCL::ECPoint> v_map;
    TE::ParticipantsMap<BICYCL::ECPoint> a_map;
    for (unsigned int i : participants) {
      aok_map.emplace(i, BICYCL::ECNIZKAoK(ec, s6.at(i).aok()));
      c2s_map.emplace(i, s5.at(i).commitment_secret());
      v_map.emplace(i, BICYCL::ECPoint(ec, s5.at(i).V_part()));
      a_map.emplace(i, BICYCL::ECPoint(ec, s5.at(i).A_part()));
    }
    for (unsigned int i : participants) {
      s7.emplace(i, Sign7(context, randgen->value, s1.at(i), s5.at(i), s6.at(i), sk[i], v_map, a_map, c2s_map, aok_map));
    }

    TE::ParticipantsMap<TE::Commitment> co3_map;
    TE::ParticipantsMap<TE::CommitmentSecret> c3s_map;
    TE::ParticipantsMap<BICYCL::ECPoint> u_map;
    TE::ParticipantsMap<BICYCL::ECPoint> t_map;
    for (unsigned int i : participants) {
      co3_map.emplace(i, s7.at(i).commitment());
      c3s_map.emplace(i, s7.at(i).commitment_secret());
      u_map.emplace(i, BICYCL::ECPoint(ec, s7.at(i).U_part()));
      t_map.emplace(i, BICYCL::ECPoint(ec, s7.at(i).T_part()));
    }
    for (unsigned int i : participants) {
      s8.emplace(i, Sign8(context, s1.at(i), s7.at(i), co3_map, u_map, t_map, c3s_map));
    }

    TE::ParticipantsMap<BICYCL::BN> s_map;
    for (unsigned int i : participants) {
      s_map.emplace(i, s5.at(i).s_part());
    }
    for (unsigned int i : participants) {
      sigs.emplace(i, Signature(context, s1.at(i), s5.at(i), sk[i], s_map, hashed));
    }

    bool ok = (sigs.at(0u) == sigs.at(1u));
    ok = ok && context.verify(sigs.at(0u), sk[0].public_key(), hashed);
    *out_valid = ok ? 1 : 0;
    return BICYCL_OK;
  } catch (const BICYCL::InvalidSecLevelException &) {
    set_error(ctx, "invalid seclevel bits; expected one of 112, 128, 192, 256");
    return BICYCL_ERR_INVALID_ARGUMENT;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_CL_DLOG;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_CL_DLOG;
  }
}

bicycl_status_t bicycl_cl_dlog_session_new(
    bicycl_context_t *ctx,
    bicycl_randgen_t *randgen,
    uint32_t seclevel_bits,
    bicycl_cl_dlog_session_t **out_session) {
  clear_error(ctx);
  if (ctx == nullptr || randgen == nullptr || out_session == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  *out_session = nullptr;
  try {
    BICYCL::SecLevel seclevel(seclevel_bits);
    auto *session = new bicycl_cl_dlog_session_t(seclevel, randgen->value);
    *out_session = session;
    return BICYCL_OK;
  } catch (const BICYCL::InvalidSecLevelException &) {
    set_error(ctx, "invalid seclevel bits; expected one of 112, 128, 192, 256");
    return BICYCL_ERR_INVALID_ARGUMENT;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_CL_DLOG;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_CL_DLOG;
  }
}

void bicycl_cl_dlog_session_free(bicycl_cl_dlog_session_t *session) {
  delete session;
}

bicycl_status_t bicycl_cl_dlog_session_prepare_statement(
    bicycl_context_t *ctx,
    bicycl_cl_dlog_session_t *session,
    bicycl_randgen_t *randgen) {
  clear_error(ctx);
  if (ctx == nullptr || session == nullptr || randgen == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  try {
    const BICYCL::ECGroup &ec_group = session->context.ec_group();
    const BICYCL::CL_HSMqk &cl = session->context.CL_HSMq();

    BICYCL::CL_HSMqk::SecretKey sk = cl.keygen(randgen->value);
    session->pk.reset(new BICYCL::CL_HSMqk::PublicKey(cl.keygen(sk)));

    BICYCL::BN a = ec_group.random_mod_order(randgen->value);
    std::unique_ptr<BICYCL::ECPoint> q(new BICYCL::ECPoint(ec_group));
    ec_group.scal_mul_gen(*q, a);

    BICYCL::Mpz random = cl.encrypt_randomness_bound();
    BICYCL::CL_HSMqk::ClearText clear_a(cl, BICYCL::Mpz(a));
    std::unique_ptr<BICYCL::CL_HSMqk::CipherText> c(
        new BICYCL::CL_HSMqk::CipherText(cl, *session->pk, clear_a, random));

    session->witness_a.reset(new BICYCL::BN(a));
    session->witness_rnd.reset(new BICYCL::Mpz(random));
    session->q = std::move(q);
    session->c = std::move(c);
    session->proof.reset();
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_CL_DLOG;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_CL_DLOG;
  }
}

bicycl_status_t bicycl_cl_dlog_session_prove_round(
    bicycl_context_t *ctx,
    bicycl_cl_dlog_session_t *session,
    bicycl_randgen_t *randgen) {
  clear_error(ctx);
  if (ctx == nullptr || session == nullptr || randgen == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  if (session->pk == nullptr || session->q == nullptr || session->c == nullptr
      || session->witness_a == nullptr || session->witness_rnd == nullptr) {
    set_error(ctx, "statement not initialized; run prepare_statement first");
    return BICYCL_ERR_INVALID_STATE;
  }
  try {
    session->proof.reset(new BICYCL::CLDLZKProof(
        session->context.H(),
        session->context.ec_group(),
        *session->witness_a,
        *session->q,
        session->context.CL_HSMq(),
        *session->pk,
        *session->c,
        *session->witness_rnd,
        randgen->value));
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_CL_DLOG;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_CL_DLOG;
  }
}

bicycl_status_t bicycl_cl_dlog_session_verify_round(
    bicycl_context_t *ctx,
    const bicycl_cl_dlog_session_t *session,
    int *out_valid) {
  clear_error(ctx);
  if (ctx == nullptr || session == nullptr || out_valid == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  if (session->pk == nullptr || session->q == nullptr || session->c == nullptr
      || session->proof == nullptr) {
    set_error(ctx, "proof not initialized; run prepare_statement and prove_round first");
    return BICYCL_ERR_INVALID_STATE;
  }
  try {
    const BICYCL::CL_HSMqk &cl = session->imported_cl ? *session->imported_cl : session->context.CL_HSMq();
    *out_valid = session->proof->verify(
                     session->context.H(),
                     session->context.ec_group(),
                     *session->q,
                     cl,
                     *session->pk,
                     *session->c)
                 ? 1
                 : 0;
    return BICYCL_OK;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_CL_DLOG;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_CL_DLOG;
  }
}

bicycl_status_t bicycl_cl_dlog_message_new(bicycl_cl_dlog_message_t **out_msg) {
  if (out_msg == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  *out_msg = nullptr;
  try {
    *out_msg = new bicycl_cl_dlog_message_t();
    return BICYCL_OK;
  } catch (...) {
    return BICYCL_ERR_ALLOCATION_FAILED;
  }
}

void bicycl_cl_dlog_message_free(bicycl_cl_dlog_message_t *msg) {
  delete msg;
}

bicycl_status_t bicycl_cl_dlog_message_export_bytes(
    bicycl_context_t *ctx,
    const bicycl_cl_dlog_message_t *msg,
    uint8_t *out_buf,
    size_t *inout_len) {
  clear_error(ctx);
  if (ctx == nullptr || msg == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  return write_bytes(ctx, msg->bytes, out_buf, inout_len);
}

bicycl_status_t bicycl_cl_dlog_message_import_bytes(
    bicycl_context_t *ctx,
    bicycl_cl_dlog_message_t *msg,
    const uint8_t *bytes,
    size_t len) {
  clear_error(ctx);
  if (ctx == nullptr || msg == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  if (bytes == nullptr && len > 0) {
    set_error(ctx, "bytes is null with non-zero len");
    return BICYCL_ERR_INVALID_ARGUMENT;
  }
  try {
    msg->bytes.assign(reinterpret_cast<const char *>(bytes), reinterpret_cast<const char *>(bytes) + len);
    return BICYCL_OK;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    return BICYCL_ERR_ALLOCATION_FAILED;
  }
}

bicycl_status_t bicycl_cl_dlog_session_export_statement(
    bicycl_context_t *ctx,
    const bicycl_cl_dlog_session_t *session,
    bicycl_cl_dlog_message_t *out_msg) {
  clear_error(ctx);
  if (ctx == nullptr || session == nullptr || out_msg == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  if (session->pk == nullptr || session->q == nullptr || session->c == nullptr) {
    set_error(ctx, "statement not initialized; run prepare_statement first");
    return BICYCL_ERR_INVALID_STATE;
  }
  try {
    const BICYCL::CL_HSMqk &cl = session->context.CL_HSMq();
    out_msg->bytes =
        std::string("STMT|")
        + mpz_to_string(cl.q()) + "|"
        + mpz_to_string(cl.p()) + "|"
        + mpz_to_string(BICYCL::Mpz(static_cast<unsigned long>(cl.k()))) + "|"
        + qfi_encode(session->pk->elt()) + "|"
        + qfi_encode(session->c->c1()) + "|"
        + qfi_encode(session->c->c2()) + "|"
        + ecpoint_encode(session->context.ec_group(), *session->q);
    return BICYCL_OK;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_CL_DLOG;
  }
}

bicycl_status_t bicycl_cl_dlog_session_import_statement(
    bicycl_context_t *ctx,
    bicycl_cl_dlog_session_t *session,
    const bicycl_cl_dlog_message_t *msg) {
  clear_error(ctx);
  if (ctx == nullptr || session == nullptr || msg == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  try {
    std::vector<std::string> f;
    split_fields(msg->bytes, '|', f);
    if (f.size() != 8 || f[0] != "STMT") {
      set_error(ctx, "invalid statement message format");
      return BICYCL_ERR_INVALID_ARGUMENT;
    }

    const BICYCL::Mpz q_mpz(f[1]);
    const BICYCL::Mpz p_mpz(f[2]);
    const size_t k = static_cast<size_t>(std::stoul(f[3]));

    session->imported_cl.reset(new BICYCL::CL_HSMqk(q_mpz, k, p_mpz));

    BICYCL::QFI pk_qfi;
    BICYCL::QFI c1_qfi;
    BICYCL::QFI c2_qfi;
    if (!qfi_decode(f[4], pk_qfi) || !qfi_decode(f[5], c1_qfi) || !qfi_decode(f[6], c2_qfi)) {
      set_error(ctx, "invalid QFI encoding in statement message");
      return BICYCL_ERR_INVALID_ARGUMENT;
    }
    session->pk.reset(new BICYCL::CL_HSMqk::PublicKey(*session->imported_cl, pk_qfi));
    session->c.reset(new BICYCL::CL_HSMqk::CipherText(c1_qfi, c2_qfi));

    std::unique_ptr<BICYCL::ECPoint> q(new BICYCL::ECPoint(session->context.ec_group()));
    if (!ecpoint_decode(session->context.ec_group(), f[7], *q)) {
      set_error(ctx, "invalid EC point encoding in statement message");
      return BICYCL_ERR_INVALID_ARGUMENT;
    }
    session->q = std::move(q);
    session->proof.reset();
    return BICYCL_OK;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_CL_DLOG;
  }
}

bicycl_status_t bicycl_cl_dlog_session_export_proof(
    bicycl_context_t *ctx,
    const bicycl_cl_dlog_session_t *session,
    bicycl_cl_dlog_message_t *out_msg) {
  clear_error(ctx);
  if (ctx == nullptr || session == nullptr || out_msg == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  if (session->proof == nullptr) {
    set_error(ctx, "proof not initialized; run prove_round first");
    return BICYCL_ERR_INVALID_STATE;
  }
  try {
    out_msg->bytes =
        std::string("PROOF|")
        + ecpoint_encode(session->context.ec_group(), session->proof->R()) + "|"
        + mpz_to_string(session->proof->u1()) + "|"
        + mpz_to_string(session->proof->u2()) + "|"
        + mpz_to_string(session->proof->chl());
    return BICYCL_OK;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_CL_DLOG;
  }
}

bicycl_status_t bicycl_cl_dlog_session_import_proof(
    bicycl_context_t *ctx,
    bicycl_cl_dlog_session_t *session,
    const bicycl_cl_dlog_message_t *msg) {
  clear_error(ctx);
  if (ctx == nullptr || session == nullptr || msg == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  try {
    std::vector<std::string> f;
    split_fields(msg->bytes, '|', f);
    if (f.size() != 5 || f[0] != "PROOF") {
      set_error(ctx, "invalid proof message format");
      return BICYCL_ERR_INVALID_ARGUMENT;
    }
    BICYCL::ECPoint r(session->context.ec_group());
    if (!ecpoint_decode(session->context.ec_group(), f[1], r)) {
      set_error(ctx, "invalid EC point encoding in proof message");
      return BICYCL_ERR_INVALID_ARGUMENT;
    }
    session->proof.reset(new BICYCL::CLDLZKProof(
        session->context.ec_group(), r, BICYCL::Mpz(f[2]), BICYCL::Mpz(f[3]), BICYCL::Mpz(f[4])));
    return BICYCL_OK;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_CL_DLOG;
  }
}

bicycl_status_t bicycl_threshold_ecdsa_session_new(
    bicycl_context_t *ctx,
    bicycl_randgen_t *randgen,
    uint32_t seclevel_bits,
    uint32_t n_players,
    uint32_t threshold_t,
    bicycl_threshold_ecdsa_session_t **out_session) {
  clear_error(ctx);
  if (ctx == nullptr || randgen == nullptr || out_session == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  if (n_players < 2 || threshold_t < 1 || threshold_t >= n_players) {
    set_error(ctx, "invalid threshold parameters: require n>=2 and 1<=t<n");
    return BICYCL_ERR_INVALID_ARGUMENT;
  }
  *out_session = nullptr;
  try {
    BICYCL::SecLevel seclevel(seclevel_bits);
    auto *session = new bicycl_threshold_ecdsa_session_t(
        seclevel, randgen->value, static_cast<unsigned int>(n_players), static_cast<unsigned int>(threshold_t));
    *out_session = session;
    return BICYCL_OK;
  } catch (const BICYCL::InvalidSecLevelException &) {
    set_error(ctx, "invalid seclevel bits; expected one of 112, 128, 192, 256");
    return BICYCL_ERR_INVALID_ARGUMENT;
  } catch (const std::bad_alloc &) {
    set_error(ctx, "allocation failed");
    return BICYCL_ERR_ALLOCATION_FAILED;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_THRESHOLD_ECDSA;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_THRESHOLD_ECDSA;
  }
}

void bicycl_threshold_ecdsa_session_free(bicycl_threshold_ecdsa_session_t *session) {
  delete session;
}

bicycl_status_t bicycl_threshold_ecdsa_keygen_round1(
    bicycl_context_t *ctx,
    bicycl_threshold_ecdsa_session_t *session,
    bicycl_randgen_t *randgen) {
  clear_error(ctx);
  if (ctx == nullptr || session == nullptr || randgen == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  if (session->stage != 0) {
    return invalid_stage(ctx, "threshold_ecdsa_keygen_round1", 0, session->stage);
  }
  try {
    session->data1.clear();
    session->data2.clear();
    session->sk.clear();
    session->v.clear();
    session->hashed.reset();
    session->s1.clear();
    session->s2.clear();
    session->s3.clear();
    session->s4.clear();
    session->s5.clear();
    session->s6.clear();
    session->s7.clear();
    session->s8.clear();
    session->signatures.clear();

    session->data1.reserve(session->n);
    for (unsigned int i = 0; i < session->n; ++i) {
      session->data1.emplace_back(session->context, randgen->value, session->n, session->t, i);
    }
    session->stage = 1;
    return BICYCL_OK;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_THRESHOLD_ECDSA;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_THRESHOLD_ECDSA;
  }
}

bicycl_status_t bicycl_threshold_ecdsa_keygen_round2(
    bicycl_context_t *ctx,
    bicycl_threshold_ecdsa_session_t *session,
    bicycl_randgen_t *randgen) {
  clear_error(ctx);
  if (ctx == nullptr || session == nullptr || randgen == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  if (session->stage != 1) {
    return invalid_stage(ctx, "threshold_ecdsa_keygen_round2", 1, session->stage);
  }
  try {
    const BICYCL::ECGroup &ec = session->context.ec_group();
    std::vector<BICYCL::thresholdECDSA::Commitment> coq;
    std::vector<BICYCL::ECPoint> q_vec;
    std::vector<BICYCL::thresholdECDSA::CommitmentSecret> coqsec;
    std::vector<std::vector<BICYCL::ECPoint>> v;
    std::vector<std::vector<BICYCL::BN>> sigma(session->n);

    coq.reserve(session->n);
    q_vec.reserve(session->n);
    coqsec.reserve(session->n);
    v.reserve(session->n);

    for (unsigned int i = 0; i < session->n; ++i) {
      coq.push_back(session->data1[i].commitment());
      q_vec.emplace_back(ec, session->data1[i].Q_part());
      coqsec.push_back(session->data1[i].commitment_secret());
      v.emplace_back();
      for (unsigned int k = 0; k < session->t; ++k) {
        v[i].emplace_back(ec, session->data1[i].V(k));
      }
      for (unsigned int j = 0; j < session->n; ++j) {
        sigma[j].push_back(session->data1[i].sigma(j));
      }
    }

    session->data2.clear();
    session->data2.reserve(session->n);
    for (unsigned int i = 0; i < session->n; ++i) {
      session->data2.emplace_back(
          session->context, session->data1[i], randgen->value, coq, q_vec, coqsec, v, sigma[i]);
    }
    session->v = std::move(v);
    session->stage = 2;
    return BICYCL_OK;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_THRESHOLD_ECDSA;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_THRESHOLD_ECDSA;
  }
}

bicycl_status_t bicycl_threshold_ecdsa_keygen_finalize(
    bicycl_context_t *ctx,
    bicycl_threshold_ecdsa_session_t *session) {
  clear_error(ctx);
  if (ctx == nullptr || session == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  if (session->stage != 2) {
    return invalid_stage(ctx, "threshold_ecdsa_keygen_finalize", 2, session->stage);
  }
  try {
    const BICYCL::ECGroup &ec = session->context.ec_group();
    std::vector<BICYCL::CL_HSMqk::PublicKey> pk;
    std::vector<BICYCL::ECNIZKProof> zk;
    pk.reserve(session->n);
    zk.reserve(session->n);
    for (unsigned int i = 0; i < session->n; ++i) {
      pk.push_back(session->data2[i].CL_public_key());
      zk.emplace_back(ec, session->data2[i].zk_proof());
    }

    session->sk.clear();
    session->sk.reserve(session->n);
    for (unsigned int i = 0; i < session->n; ++i) {
      session->sk.emplace_back(
          session->context, i, session->data1[i], session->data2[i], session->v, zk, pk);
    }
    session->stage = 3;
    return BICYCL_OK;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_THRESHOLD_ECDSA;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_THRESHOLD_ECDSA;
  }
}

bicycl_status_t bicycl_threshold_ecdsa_sign_round1(
    bicycl_context_t *ctx,
    bicycl_threshold_ecdsa_session_t *session,
    bicycl_randgen_t *randgen,
    const uint8_t *msg_ptr,
    size_t msg_len) {
  clear_error(ctx);
  if (ctx == nullptr || session == nullptr || randgen == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  if (msg_ptr == nullptr && msg_len > 0) {
    set_error(ctx, "msg_ptr is null with non-zero msg_len");
    return BICYCL_ERR_INVALID_ARGUMENT;
  }
  if (session->stage != 3) {
    return invalid_stage(ctx, "threshold_ecdsa_sign_round1", 3, session->stage);
  }
  try {
    std::vector<unsigned char> msg;
    if (msg_len > 0) {
      msg.assign(msg_ptr, msg_ptr + msg_len);
    }
    session->hashed.reset(new BICYCL::HashAlgo::Digest(session->context.hash(msg)));

    session->s1.clear();
    for (unsigned int i : session->signers) {
      session->s1.emplace(i, bicycl_threshold_ecdsa_session_t::Sign1(
                                 session->context, randgen->value, i, session->signers, session->sk[i]));
    }
    session->stage = 4;
    return BICYCL_OK;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_THRESHOLD_ECDSA;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_THRESHOLD_ECDSA;
  }
}

bicycl_status_t bicycl_threshold_ecdsa_sign_round2(
    bicycl_context_t *ctx,
    bicycl_threshold_ecdsa_session_t *session,
    bicycl_randgen_t *randgen) {
  clear_error(ctx);
  if (ctx == nullptr || session == nullptr || randgen == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  if (session->stage != 4) {
    return invalid_stage(ctx, "threshold_ecdsa_sign_round2", 4, session->stage);
  }
  try {
    BICYCL::thresholdECDSA::ParticipantsMap<BICYCL::thresholdECDSA::Commitment> co_map;
    BICYCL::thresholdECDSA::ParticipantsMap<BICYCL::CL_HSMqk::CipherText> c1;
    BICYCL::thresholdECDSA::ParticipantsMap<BICYCL::CL_HSMqk_ZKAoKProof> zk1;
    for (unsigned int i : session->signers) {
      co_map.emplace(i, session->s1.at(i).commitment());
      c1.emplace(i, session->s1.at(i).ciphertext());
      zk1.emplace(i, session->s1.at(i).zk_encrypt_proof());
    }

    session->s2.clear();
    for (unsigned int i : session->signers) {
      session->s2.emplace(
          i,
          bicycl_threshold_ecdsa_session_t::Sign2(
              session->context, randgen->value, session->s1.at(i), session->sk[i], co_map, c1, zk1));
    }
    session->stage = 5;
    return BICYCL_OK;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_THRESHOLD_ECDSA;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_THRESHOLD_ECDSA;
  }
}

bicycl_status_t bicycl_threshold_ecdsa_sign_round3(
    bicycl_context_t *ctx,
    bicycl_threshold_ecdsa_session_t *session) {
  clear_error(ctx);
  if (ctx == nullptr || session == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  if (session->stage != 5) {
    return invalid_stage(ctx, "threshold_ecdsa_sign_round3", 5, session->stage);
  }
  try {
    const BICYCL::ECGroup &ec = session->context.ec_group();
    BICYCL::thresholdECDSA::ParticipantsMap<
        BICYCL::thresholdECDSA::ParticipantsMap<BICYCL::CL_HSMqk::CipherText>>
        c_kg_map;
    BICYCL::thresholdECDSA::ParticipantsMap<
        BICYCL::thresholdECDSA::ParticipantsMap<BICYCL::CL_HSMqk::CipherText>>
        c_kw_map;
    BICYCL::thresholdECDSA::ParticipantsMap<
        BICYCL::thresholdECDSA::ParticipantsMap<BICYCL::ECPoint>>
        b_map;

    for (unsigned int i : session->signers) {
      for (unsigned int j : session->signers) {
        if (i == j) {
          continue;
        }
        c_kg_map[i].emplace(j, session->s2.at(j).c_kg(i));
        c_kw_map[i].emplace(j, session->s2.at(j).c_kw(i));
        b_map[i].emplace(j, BICYCL::ECPoint(ec, session->s2.at(j).B(i)));
      }
    }

    session->s3.clear();
    for (unsigned int i : session->signers) {
      session->s3.emplace(
          i,
          bicycl_threshold_ecdsa_session_t::Sign3(
              session->context,
              session->s1.at(i),
              session->s2.at(i),
              session->sk[i],
              c_kg_map.at(i),
              c_kw_map.at(i),
              b_map.at(i)));
    }
    session->stage = 6;
    return BICYCL_OK;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_THRESHOLD_ECDSA;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_THRESHOLD_ECDSA;
  }
}

bicycl_status_t bicycl_threshold_ecdsa_sign_round4(
    bicycl_context_t *ctx,
    bicycl_threshold_ecdsa_session_t *session) {
  clear_error(ctx);
  if (ctx == nullptr || session == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  if (session->stage != 6) {
    return invalid_stage(ctx, "threshold_ecdsa_sign_round4", 6, session->stage);
  }
  try {
    BICYCL::thresholdECDSA::ParticipantsMap<BICYCL::BN> delta_map;
    for (unsigned int i : session->signers) {
      delta_map.emplace(i, session->s3.at(i).delta_part());
    }

    session->s4.clear();
    for (unsigned int i : session->signers) {
      session->s4.emplace(
          i, bicycl_threshold_ecdsa_session_t::Sign4(session->context, session->s1.at(i), delta_map));
    }
    session->stage = 7;
    return BICYCL_OK;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_THRESHOLD_ECDSA;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_THRESHOLD_ECDSA;
  }
}

bicycl_status_t bicycl_threshold_ecdsa_sign_round5(
    bicycl_context_t *ctx,
    bicycl_threshold_ecdsa_session_t *session,
    bicycl_randgen_t *randgen) {
  clear_error(ctx);
  if (ctx == nullptr || session == nullptr || randgen == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  if (session->stage != 7) {
    return invalid_stage(ctx, "threshold_ecdsa_sign_round5", 7, session->stage);
  }
  if (session->hashed == nullptr) {
    set_error(ctx, "missing hashed message");
    return BICYCL_ERR_INVALID_ARGUMENT;
  }
  try {
    const BICYCL::ECGroup &ec = session->context.ec_group();
    BICYCL::thresholdECDSA::ParticipantsMap<BICYCL::ECNIZKProof> zk_map;
    BICYCL::thresholdECDSA::ParticipantsMap<BICYCL::thresholdECDSA::CommitmentSecret> cos_map;
    BICYCL::thresholdECDSA::ParticipantsMap<BICYCL::ECPoint> gamma_map;
    for (unsigned int i : session->signers) {
      zk_map.emplace(i, BICYCL::ECNIZKProof(ec, session->s1.at(i).zk_gamma()));
      cos_map.emplace(i, session->s1.at(i).commitment_secret());
      gamma_map.emplace(i, BICYCL::ECPoint(ec, session->s1.at(i).Gamma()));
    }

    session->s5.clear();
    for (unsigned int i : session->signers) {
      session->s5.emplace(
          i,
          bicycl_threshold_ecdsa_session_t::Sign5(
              session->context,
              randgen->value,
              session->s1.at(i),
              session->s2.at(i),
              session->s3.at(i),
              session->s4.at(i),
              *session->hashed,
              gamma_map,
              cos_map,
              zk_map));
    }
    session->stage = 8;
    return BICYCL_OK;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_THRESHOLD_ECDSA;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_THRESHOLD_ECDSA;
  }
}

bicycl_status_t bicycl_threshold_ecdsa_sign_round6(
    bicycl_context_t *ctx,
    bicycl_threshold_ecdsa_session_t *session,
    bicycl_randgen_t *randgen) {
  clear_error(ctx);
  if (ctx == nullptr || session == nullptr || randgen == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  if (session->stage != 8) {
    return invalid_stage(ctx, "threshold_ecdsa_sign_round6", 8, session->stage);
  }
  try {
    BICYCL::thresholdECDSA::ParticipantsMap<BICYCL::thresholdECDSA::Commitment> co2_map;
    for (unsigned int i : session->signers) {
      co2_map.emplace(i, session->s5.at(i).commitment());
    }

    session->s6.clear();
    for (unsigned int i : session->signers) {
      session->s6.emplace(
          i, bicycl_threshold_ecdsa_session_t::Sign6(session->context, randgen->value, session->s5.at(i), co2_map));
    }
    session->stage = 9;
    return BICYCL_OK;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_THRESHOLD_ECDSA;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_THRESHOLD_ECDSA;
  }
}

bicycl_status_t bicycl_threshold_ecdsa_sign_round7(
    bicycl_context_t *ctx,
    bicycl_threshold_ecdsa_session_t *session,
    bicycl_randgen_t *randgen) {
  clear_error(ctx);
  if (ctx == nullptr || session == nullptr || randgen == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  if (session->stage != 9) {
    return invalid_stage(ctx, "threshold_ecdsa_sign_round7", 9, session->stage);
  }
  try {
    const BICYCL::ECGroup &ec = session->context.ec_group();
    BICYCL::thresholdECDSA::ParticipantsMap<BICYCL::ECNIZKAoK> aok_map;
    BICYCL::thresholdECDSA::ParticipantsMap<BICYCL::thresholdECDSA::CommitmentSecret> c2s_map;
    BICYCL::thresholdECDSA::ParticipantsMap<BICYCL::ECPoint> v_map;
    BICYCL::thresholdECDSA::ParticipantsMap<BICYCL::ECPoint> a_map;
    for (unsigned int i : session->signers) {
      aok_map.emplace(i, BICYCL::ECNIZKAoK(ec, session->s6.at(i).aok()));
      c2s_map.emplace(i, session->s5.at(i).commitment_secret());
      v_map.emplace(i, BICYCL::ECPoint(ec, session->s5.at(i).V_part()));
      a_map.emplace(i, BICYCL::ECPoint(ec, session->s5.at(i).A_part()));
    }

    session->s7.clear();
    for (unsigned int i : session->signers) {
      session->s7.emplace(
          i,
          bicycl_threshold_ecdsa_session_t::Sign7(
              session->context,
              randgen->value,
              session->s1.at(i),
              session->s5.at(i),
              session->s6.at(i),
              session->sk[i],
              v_map,
              a_map,
              c2s_map,
              aok_map));
    }
    session->stage = 10;
    return BICYCL_OK;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_THRESHOLD_ECDSA;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_THRESHOLD_ECDSA;
  }
}

bicycl_status_t bicycl_threshold_ecdsa_sign_round8(
    bicycl_context_t *ctx,
    bicycl_threshold_ecdsa_session_t *session) {
  clear_error(ctx);
  if (ctx == nullptr || session == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  if (session->stage != 10) {
    return invalid_stage(ctx, "threshold_ecdsa_sign_round8", 10, session->stage);
  }
  try {
    const BICYCL::ECGroup &ec = session->context.ec_group();
    BICYCL::thresholdECDSA::ParticipantsMap<BICYCL::thresholdECDSA::Commitment> co3_map;
    BICYCL::thresholdECDSA::ParticipantsMap<BICYCL::thresholdECDSA::CommitmentSecret> c3s_map;
    BICYCL::thresholdECDSA::ParticipantsMap<BICYCL::ECPoint> u_map;
    BICYCL::thresholdECDSA::ParticipantsMap<BICYCL::ECPoint> t_map;
    for (unsigned int i : session->signers) {
      co3_map.emplace(i, session->s7.at(i).commitment());
      c3s_map.emplace(i, session->s7.at(i).commitment_secret());
      u_map.emplace(i, BICYCL::ECPoint(ec, session->s7.at(i).U_part()));
      t_map.emplace(i, BICYCL::ECPoint(ec, session->s7.at(i).T_part()));
    }

    session->s8.clear();
    for (unsigned int i : session->signers) {
      session->s8.emplace(
          i,
          bicycl_threshold_ecdsa_session_t::Sign8(
              session->context, session->s1.at(i), session->s7.at(i), co3_map, u_map, t_map, c3s_map));
    }
    session->stage = 11;
    return BICYCL_OK;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_THRESHOLD_ECDSA;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_THRESHOLD_ECDSA;
  }
}

bicycl_status_t bicycl_threshold_ecdsa_sign_finalize(
    bicycl_context_t *ctx,
    bicycl_threshold_ecdsa_session_t *session) {
  clear_error(ctx);
  if (ctx == nullptr || session == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  if (session->stage != 11) {
    return invalid_stage(ctx, "threshold_ecdsa_sign_finalize", 11, session->stage);
  }
  if (session->hashed == nullptr) {
    set_error(ctx, "missing hashed message");
    return BICYCL_ERR_INVALID_ARGUMENT;
  }
  try {
    BICYCL::thresholdECDSA::ParticipantsMap<BICYCL::BN> s_map;
    for (unsigned int i : session->signers) {
      s_map.emplace(i, session->s5.at(i).s_part());
    }

    session->signatures.clear();
    for (unsigned int i : session->signers) {
      session->signatures.emplace(
          i,
          bicycl_threshold_ecdsa_session_t::Signature(
              session->context, session->s1.at(i), session->s5.at(i), session->sk[i], s_map, *session->hashed));
    }
    session->stage = 12;
    return BICYCL_OK;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_THRESHOLD_ECDSA;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_THRESHOLD_ECDSA;
  }
}

bicycl_status_t bicycl_threshold_ecdsa_signature_valid(
    bicycl_context_t *ctx,
    const bicycl_threshold_ecdsa_session_t *session,
    int *out_valid) {
  clear_error(ctx);
  if (ctx == nullptr || session == nullptr || out_valid == nullptr) {
    return BICYCL_ERR_NULL_PTR;
  }
  if (session->stage != 12) {
    return invalid_stage(ctx, "threshold_ecdsa_signature_valid", 12, session->stage);
  }
  try {
    bool ok = true;
    const unsigned int first = session->signers[0];
    for (unsigned int i : session->signers) {
      ok = ok && (session->signatures.at(i) == session->signatures.at(first));
      ok = ok && session->context.verify(
                     session->signatures.at(i),
                     session->sk[i].public_key(),
                     *session->hashed);
    }
    *out_valid = ok ? 1 : 0;
    return BICYCL_OK;
  } catch (const std::exception &e) {
    set_error(ctx, e.what());
    return BICYCL_ERR_THRESHOLD_ECDSA;
  } catch (...) {
    set_error(ctx, "unknown error");
    return BICYCL_ERR_THRESHOLD_ECDSA;
  }
}

}  // extern "C"
