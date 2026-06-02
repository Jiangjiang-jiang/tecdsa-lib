/*
 * BICYCL Implements CryptographY in CLass groups
 * Copyright (C) 2025  Cyril Bouvier <cyril.bouvier@lirmm.fr>
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
/**
 * @defgroup PROOFS Proofs
 */

#ifndef BICYCL_EC_PROOFS_HPP
#define BICYCL_EC_PROOFS_HPP

#include "bicycl/arith/openssl_wrapper.hpp"

namespace BICYCL
{
  /*****/
  /**
   * @brief Proof of knowledge of the dscrete log of an elliptic curve point.
   * @details Proves following relation :
   * \f$ R_{DL} := \{(Q,s)|Q=sP\}\f$\n
   * With :
   *  - \f$s\f$ the secret value
   *  - \f$P\f$ the generator of the elliptic curve
   *  - \f$Q\f$ an EC point
   * @ingroup ECDSA_THRESHOLD ECDSA_TWOPARTY PROOFS
   */
  class ECNIZKProof
  {
    public:
      using SecretValue = BN;
      using PublicValue = ECPoint;

      ECNIZKProof (const ECGroup &E, HashAlgo &H, RandGen & randgen,
                   const SecretValue &s, const PublicValue &Q,
                   const Mpz & sid = Mpz{0UL});
      ECNIZKProof (const ECGroup &E, HashAlgo &H, RandGen & randgen,
                   const SecretValue &s);
      ECNIZKProof(const ECGroup & E,
                  const ECPoint & R,
                  const BN & z);
      ECNIZKProof(const ECGroup & E,
                  const BN & Rx,
                  const BN & Ry,
                  const BN & z);
      ECNIZKProof (const ECGroup &E, const ECNIZKProof &p);
      explicit ECNIZKProof (const ECGroup &E);

      const ECPoint & R() const;
      const BN & z() const;

      bool verify (const ECGroup &E, HashAlgo &H,
                   const PublicValue &Q, const Mpz & sid = Mpz{0UL}) const;

    protected:
      static BN hash_for_challenge (HashAlgo & H,
                                    const ECGroup & E,
                                    const ECPoint & R,
                                    const ECPoint & Q,
                                    const Mpz & sid);
      static ECPoint compute_Q_from_secret (const ECGroup &E,
                                                     const SecretValue &s);

    private:
      ECPoint R_;
      BN z_;
  }; /* ECNIZKProof */

  /*****/
  /**
   * @ingroup ECDSA_THRESHOLD PROOFS
   */
   // TODO doc
  class ECNIZKAoK
  {
    public:
      using SecretValue = BN;
      using PublicValue = ECPoint;

      ECNIZKAoK (const ECGroup &E, HashAlgo &H, RandGen & randgen,
                 const ECPoint &R, const SecretValue &x,
                 const SecretValue &y, const SecretValue &rho,
                 const PublicValue &V, const PublicValue &A);
      ECNIZKAoK (const ECGroup &E, const ECNIZKAoK &p);

      bool verify (const ECGroup &E, HashAlgo &H,
                   const ECPoint &R, const PublicValue &V,
                   const PublicValue &A) const;

    protected:
      static BN hash_for_challenge (HashAlgo &Hash,
                                             const ECGroup &E,
                                             const ECPoint &R,
                                             const ECPoint &V,
                                             const ECPoint &A,
                                             const ECPoint &H);

    private:
      ECPoint H_;
      BN t1_;
      BN t2_;
  }; /* ECNIZKAoK */

} /* Namespace BICYCL */

#include "proofs.inl" // IWYU pragma: keep

#endif /* BICYCL_EC_PROOFS_HPP */