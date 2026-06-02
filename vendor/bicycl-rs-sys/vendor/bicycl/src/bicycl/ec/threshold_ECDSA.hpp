/*
 * BICYCL Implements CryptographY in CLass groups
 * Copyright (C) 2022  Cyril Bouvier <cyril.bouvier@lirmm.fr>
 *                     Guilhem Castagnos <guilhem.castagnos@math.u-bordeaux.fr>
 *                     Laurent Imbert <laurent.imbert@lirmm.fr>
 *                     Fabien Laguillaumie <fabien.laguillaumie@lirmm.fr>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
#ifndef BICYCL_EC_THRESHOLD_ECDSA_HPP
#define BICYCL_EC_THRESHOLD_ECDSA_HPP

#include <iostream>
#include <stdexcept>
#include <string>
#include <tuple>
#include <unordered_map>
#include <vector>

#include "bicycl/arith/gmp_extras.hpp"
#include "bicycl/arith/openssl_wrapper.hpp"
#include "bicycl/ec/proofs.hpp"
#include "bicycl/ec/signature.hpp"
#include "bicycl/cl/CL_HSMqk.hpp"
#include "bicycl/parallelism.hpp"

/**
 * @defgroup ECDSA_THRESHOLD Threshold ECDSA
 * @ingroup ECDSA
 * T-out-of-N threshold ECDSA using class groups.
 *
 */

namespace BICYCL
{
  /****/
  /**
   * @ingroup ECDSA_THRESHOLD
   */
  class thresholdECDSA
  {
    public:
      using PublicKey = ECPoint;
      using Commitment = HashAlgo::Digest;
      using CommitmentSecret = std::vector<unsigned char>;
      using ParticipantsList = std::vector<unsigned int>;
      template <class T>
      using ParticipantsMap = std::unordered_map<unsigned int, T>;

      class ProtocolAbortError : public std::runtime_error
      {
        public:
          using runtime_error::runtime_error;
      };

      class SetupPart1
      {
        public:
          /* ctor */
          SetupPart1(SecLevel seclevel,
                     RandGen & randgen,
                     unsigned int n,
                     unsigned int i);

          /* getters */
          const Commitment & commitment () const;
          const CommitmentSecret & commitment_secret () const;
          const Mpz & rho_part () const;

        private:
          Mpz rho_part_;
          CommitmentSecret cs_;
          Commitment c_;
      };

      class SetupPart2
      {
        public:
          /* ctor */
          SetupPart2(SecLevel seclevel,
                     unsigned int n,
                     const std::vector<Mpz> & rho_parts,
                     const std::vector<Commitment> & commitments,
                     const std::vector<CommitmentSecret> & commitment_secrets);

          /* getters */
          const Mpz & rho () const;
        private:
          Mpz rho_;
      };

      /* */
      class KeygenPart1
      {
        public:
          /* ctor */
          KeygenPart1 (const thresholdECDSA &C, RandGen & randgen, unsigned int n, unsigned int t,
                       unsigned int i);

          /* getters */
          unsigned int n () const;
          unsigned int t () const;
          unsigned int i () const;
          const ECPoint & Q_part () const;
          const BN & u_part () const;
          const Commitment & commitment () const;
          const CommitmentSecret & commitment_secret () const;
          const ECPoint & V (size_t k) const;
          const BN & sigma (size_t j) const;

        private:
          unsigned int i_;
          BN u_;
          ECPoint Q_; /* Q_i = [u_i] P */
          Commitment c_;
          CommitmentSecret cs_;
          std::vector<BN> a_; /* t scalars a_i,k */
          std::vector<ECPoint> V_; /* V_i,k = [a_i,k] P */
          std::vector<BN> sigma_; /* n scalars corresponding to
                                            * evaluations of the polynomial
                                            * u_i + sum_{k=1}^{t}{a_i,k X^k}
                                            */
      }; /* KeygenPart1 */

      /* */
      class KeygenPart2
      {
        public:
          /* ctor */
          KeygenPart2 (const thresholdECDSA &C, const KeygenPart1 &data1,
                       RandGen &randgen, const std::vector<Commitment> &Co,
                       const std::vector<ECPoint> &Q,
                       const std::vector<CommitmentSecret> &CoSec,
                       const std::vector<std::vector<ECPoint>> &V,
                       const std::vector<BN> &Sigma);

          /* getters */
          const ECPoint & Q () const;
          const BN & x () const;
          const ECNIZKProof & zk_proof () const;
          const CL_HSMqk::SecretKey & CL_secret_key () const;
          const CL_HSMqk::PublicKey & CL_public_key () const;

        private:
          ECPoint Q_;
          BN x_;
          ECNIZKProof zk_proof_;
          CL_HSMqk::SecretKey sk_;
          CL_HSMqk::PublicKey pk_;
      }; /* KeygenPart2 */

      /* */
      class SecretKey
      {
        public:
          /* ctor */
          SecretKey (const thresholdECDSA &C, unsigned int i,
                     const KeygenPart1 &data1, const KeygenPart2 &data2,
                     const std::vector<std::vector<ECPoint>> &V,
                     const std::vector<ECNIZKProof> &ZK,
                     const std::vector<CL_HSMqk::PublicKey> &PK);

          /* getters */
          const PublicKey & public_key () const;
          const CL_HSMqk::SecretKey & CL_secret_key () const;
          const CL_HSMqk::PublicKey & CL_public_key (unsigned int) const;
          const ECPoint & X (unsigned int) const;
          const BN & x_part () const;

        private:
          CL_HSMqk::SecretKey sk_;
          BN x_;
          std::vector<CL_HSMqk::PublicKey> PK_;
          std::vector<ECPoint> X_;
          ECPoint Q_;
      }; /* Secret Key */

      /* */
      class SignPart1
      {
        public:
          /* ctor */
          SignPart1 (const thresholdECDSA &C, RandGen &randgen,
                     unsigned int i, const ParticipantsList &S,
                     const thresholdECDSA::SecretKey &sk );

          /* getters */
          const ParticipantsList & S () const;
          const BN & gamma () const;
          const ECPoint & Gamma () const;
          const ECNIZKProof & zk_gamma () const;
          const Commitment & commitment () const;
          const CommitmentSecret & commitment_secret () const;
          unsigned int i () const;
          const BN & omega() const;
          const Mpz & k_part () const;
          const CL_HSMqk::CipherText & ciphertext () const;
          const CL_HSMqk_ZKAoKProof & zk_encrypt_proof () const;

        private:
          unsigned int i_;
          ParticipantsList S_;
          BN omega_;
          BN gamma_;
          ECPoint Gamma_;
          ECNIZKProof zk_gamma_;
          Commitment co_;
          CommitmentSecret cos_;
          CL_HSMqk::ClearText k_;
          Mpz r_;
          CL_HSMqk::CipherText c_;
          CL_HSMqk_ZKAoKProof zk_encrypt_;
      }; /* SignPart1 */

      /* */
      class SignPart2
      {
        public:
          SignPart2 (const thresholdECDSA &C, RandGen &randgen,
                     const SignPart1 &data,
                     const thresholdECDSA::SecretKey &sk,
                     const ParticipantsMap<Commitment> & commitment_map,
                     const ParticipantsMap<CL_HSMqk::CipherText> &c_map,
                     const ParticipantsMap<CL_HSMqk_ZKAoKProof> &zk_map);

          /* getters */
          const Commitment & commitment (unsigned int j) const;
          const BN & nu (unsigned int j) const;
          const ECPoint & B (unsigned int j) const;
          const CL_HSMqk::ClearText & beta (unsigned int j) const;
          const CL_HSMqk::CipherText & c_kg (unsigned int j) const;
          const CL_HSMqk::CipherText & c_kw (unsigned int j) const;

        protected:
        /* Sign part 2 without checking proofs, for benchmark use only */
          SignPart2(const thresholdECDSA & C,
                    RandGen & randgen,
                    const SignPart1 & data,
                    const thresholdECDSA::SecretKey &sk,
                    const ParticipantsMap<Commitment> & commitment_map,
                    const ParticipantsMap<CL_HSMqk::CipherText> & c_map);

        private:
          ParticipantsMap<Commitment> commitment_map_;
          ParticipantsMap<BN> nu_map_;
          ParticipantsMap<ECPoint> B_map_;
          ParticipantsMap<CL_HSMqk::ClearText> beta_map_;
          ParticipantsMap<CL_HSMqk::CipherText> c_kg_map_;
          ParticipantsMap<CL_HSMqk::CipherText> c_kw_map_;
      }; /* SignPart2 */

      /* */
      class SignPart3
      {
        public:
          SignPart3 (const thresholdECDSA &C, const SignPart1 &data1,
                     const SignPart2 &data2,
                     const thresholdECDSA::SecretKey &sk,
                     const ParticipantsMap<CL_HSMqk::CipherText> &c_kg_map,
                     const ParticipantsMap<CL_HSMqk::CipherText> &c_kw_map,
                     const ParticipantsMap<ECPoint> &B_map);

          const BN & delta_part () const;
          const BN & sigma_part () const;

        private:
          BN delta_;
          BN sigma_;
      }; /* SignPart3 */

      /* */
      class SignPart4
      {
        public:
          SignPart4 (const thresholdECDSA &C, const SignPart1 &data1,
                     const ParticipantsMap<BN> &delta_map);

          const BN & delta () const;

        private:
          BN delta_;
      }; /* SignPart4 */

      /* */
      class SignPart5
      {
        public:
          SignPart5(const thresholdECDSA & C,
                    RandGen & randgen,
                    const SignPart1 & data1,
                    const SignPart2 & data2,
                    const SignPart3 & data3,
                    const SignPart4 & data4,
                    const HashAlgo::Digest & m,
                    const ParticipantsMap<ECPoint> & Gamma_map,
                    const ParticipantsMap<CommitmentSecret> & CoSec_map,
                    const ParticipantsMap<ECNIZKProof> & zk_proof_map);

          /* getters */
          const ECPoint & R () const;
          const BN & r () const;
          const BN & z () const;
          const BN & s_part () const;
          const ECPoint & V_part () const;
          const BN & ell () const;
          const BN & rho () const;
          const ECPoint & A_part () const;
          const Commitment & commitment () const;
          const CommitmentSecret & commitment_secret () const;

        private:
          ECPoint R_;
          BN r_;
          BN z_;
          BN s_;
          BN ell_;
          BN rho_;
          ECPoint V_;
          ECPoint A_;
          Commitment c_;
          CommitmentSecret cs_;
      }; /* SignPart5 */

      /* */
      class SignPart6
      {
        public:
          SignPart6(const thresholdECDSA & C,
                    RandGen & randgen,
                    const SignPart5 & data5,
                    const ParticipantsMap<Commitment> & Co_map);

          /* getters */
          const Commitment & commitment (unsigned int j) const;
          const ECNIZKAoK & aok () const;

        private:
          ParticipantsMap<Commitment> commitment_map_;
          ECNIZKAoK zk_aok_;
      }; /* SignPart6 */

      /* */
      class SignPart7
      {
        public:
          SignPart7 (const thresholdECDSA &C, RandGen & randgen,
                    const SignPart1 &data1, const SignPart5 &data5,
                    const SignPart6 &data6, const thresholdECDSA::SecretKey &sk,
                    const ParticipantsMap<ECPoint> &V_map,
                    const ParticipantsMap<ECPoint> &A_map,
                    const ParticipantsMap<CommitmentSecret> &CoSec_map,
                    const ParticipantsMap<ECNIZKAoK> &zk_aok_map);

          /* getters */
          const Commitment & commitment () const;
          const CommitmentSecret & commitment_secret () const;
          const ECPoint & U_part () const;
          const ECPoint & T_part () const;

        private:
          ECPoint U_;
          ECPoint T_;
          Commitment c_;
          CommitmentSecret cs_;
      }; /* SignPart7 */

      /* */
      class SignPart8
      {
        public:
          SignPart8 (const thresholdECDSA &C, const SignPart1 &data1,
                     const SignPart7 &data7,
                     const ParticipantsMap<Commitment> &Co_map,
                     const ParticipantsMap<ECPoint> &U_map,
                     const ParticipantsMap<ECPoint> &T_map,
                     const ParticipantsMap<CommitmentSecret> &CoSec_map);
      }; /* SignPart8 */

      /* */
      class Signature : public ECSignature
      {
        public:
          Signature (const thresholdECDSA &C, const SignPart1 &data1,
                     const SignPart5 &data5, const SecretKey &sk,
                     const ParticipantsMap<BN> &s_map,
                     const HashAlgo::Digest &m);
      }; /* Signature */

      /* constructors */
      thresholdECDSA(SecLevel seclevel, RandGen &randgen);
      /* With interractive setup */
      thresholdECDSA(SecLevel seclevel,
                     const thresholdECDSA::SetupPart2 & setup);

      /* getters */
      const ECGroup & ec_group () const;
      const CL_HSMqk & CL () const;

      /* utils */
      std::tuple<Commitment, CommitmentSecret>
      commit (const ECPoint & Q, RandGen & randgen) const;
      std::tuple<Commitment, CommitmentSecret>
      commit (const ECPoint & Q1, const ECPoint & Q2, RandGen & randgen) const;

      bool open (const Commitment &c, const ECPoint &Q,
                                      const CommitmentSecret &r) const;
      bool open (const Commitment &c, const ECPoint &Q1,
                                      const ECPoint &Q2,
                                      const CommitmentSecret &r) const;

      HashAlgo::Digest hash(std::vector<unsigned char> m) const;

      /* crypto */
      bool verify (const Signature &s, const PublicKey &Q,
                                       const HashAlgo::Digest &m) const;

      /* utils */
      BN lagrange_at_zero (const ParticipantsList &S,
                                    unsigned int i) const;

      friend std::ostream & operator<< (std::ostream &o,
                                        const thresholdECDSA &C);

    protected:
      /* setup */
      CL_HSMqk GenCL(const Mpz & rho);

    private:
      /* utils */
      BN sum (const std::vector<BN> &Operands) const;

      const SecLevel seclevel_;
      const ECGroup ec_group_;
      CL_HSMqk CL_HSMq_;
      mutable HashAlgo H_;

#ifdef BICYCL_WITH_PTHREADS
      static const unsigned int NB_THREADS_ = 4u;
#endif //BICYCL_WITH_PTHREADS
  };

} /* BICYCL namespace */

#include "threshold_ECDSA.inl"  // IWYU pragma: keep

#endif /* BICYCL_EC_THRESHOLD_ECDSA_HPP */
