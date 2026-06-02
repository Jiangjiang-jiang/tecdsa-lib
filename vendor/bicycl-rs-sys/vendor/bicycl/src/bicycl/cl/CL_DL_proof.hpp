/*
 * BICYCL Implements CryptographY in CLass groups
 * Copyright (C) 2024  Cyril Bouvier <cyril.bouvier@lirmm.fr>
 *                     Guilhem Castagnos <guilhem.castagnos@math.u-bordeaux.fr>
 *                     Laurent Imbert <laurent.imbert@lirmm.fr>
 *                     Fabien Laguillaumie <fabien.laguillaumie@lirmm.fr>
 *                     Quentin Combal <quentin.combal@lirmm.fr>
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
#ifndef BICYCL_CL_CL_DL_PROOF_HPP
#define BICYCL_CL_CL_DL_PROOF_HPP

#include "bicycl/arith/openssl_wrapper.hpp"
#include "bicycl/cl/CL_HSMqk.hpp"

namespace BICYCL
{
  /************************************************************************/
  /**
   * @brief Proof of knowledge of:
   * - the randomness @p r used for encryption
   * - @p x, which is encrypted in @p c and the D-Log of @p Q
   * @details
   * It proves the following relation :\n
   * \f$ R_{CL-DL} := \{(pk, (c_1,c_2), Q);(x, r) | c_1=h^r \land c_2={f^x}{pk}^r \land Q=xP\}\f$\n\n
   * With :
   *  - \f$(h, f, pk)\f$ the public parameters of \f$\CL\f$
   *  - \f$x_k \in \Z/q\Z\f$ the secret value
   *  - \f$r\f$ the randomness used in the encryption
   *  - \f$c = (c_1, c_2) = Enc(r; (pk, x))\f$ the encrypted \f$x\f$
   *  - \f$P\f$ the generator of the elliptic curve
   *  - \f$Q\f$ an EC point
   *
   * @ingroup ECDSA_TWOPARTY PROOFS
   */
  class CLDLZKProof
  {
    public:
      using SecretValue = BN;
      using PublicValue = ECPoint;

      /* Ctor */
      explicit CLDLZKProof(const ECGroup & E);

      CLDLZKProof(const ECGroup & E,
                  const ECPoint & R,
                  const Mpz & u1,
                  const Mpz & u2,
                  const Mpz & chl);

      CLDLZKProof(HashAlgo & H,
                  const ECGroup & E,
                  const SecretValue & x,
                  const PublicValue & Q,
                  const CL_HSMqk & cryptosystem,
                  const CL_HSMqk::PublicKey & pk,
                  const CL_HSMqk::CipherText & c,
                  const Mpz & r,
                  RandGen & randgen);

#ifdef BICYCL_WITH_PTHREADS
      CLDLZKProof(HashAlgo & H,
                  const ECGroup & E,
                  const SecretValue & x,
                  const PublicValue & Q,
                  const CL_HSMqk & cryptosystem,
                  const CL_HSMqk::PublicKey & pk,
                  const CL_HSMqk::CipherText & c,
                  const Mpz & r,
                  RandGen & randgen,
                  std::thread & thread_ckey);
#endif

      /* Getters */
      const ECPoint & R() const;
      const Mpz & u1() const;
      const Mpz & u2() const;
      const Mpz & chl() const;

      /* verify */
      bool verify (HashAlgo & H,
                   const ECGroup & E,
                   const PublicValue & Q,
                   const CL_HSMqk & C,
                   const CL_HSMqk::PublicKey & pk,
                   const CL_HSMqk::CipherText & c) const;


    private:
      /* util */
      Mpz hash_for_challenge (HashAlgo & H,
                              const ECGroup & E,
                              const PublicValue & Q,
                              const CL_HSMqk::PublicKey & pk,
                              const CL_HSMqk::CipherText & c,
                              const QFI & t1,
                              const QFI & t2) const;

      ECPoint R_;
      Mpz u1_;
      Mpz u2_;
      Mpz chl_;
  }; /* CLDLZKProof */

} /* namespace BICYCL */

#include "CL_DL_proof.inl" // IWYU pragma: keep

#endif /* BICYCL_CL_CL_DL_PROOF_HPP */