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
#ifndef BICYCL_EC_ECDSA_HPP
#define BICYCL_EC_ECDSA_HPP

#include <functional>
#include <tuple>

#include "bicycl/seclevel.hpp"
#include "bicycl/arith/gmp_extras.hpp"
#include "bicycl/arith/openssl_wrapper.hpp"
#include "bicycl/ec/signature.hpp"

/**
  * @defgroup ECDSA ECDSA
  * Implementation of ECDSA and CL based variations
  *
  * @defgroup ECDSA_CLASSIC Classic ECDSA
  * @ingroup ECDSA
  * Implementation the ECDSA algorithm
  */

namespace BICYCL
{
  /*****/
  /**
   * @ingroup ECDSA_CLASSIC
   */
  class ECDSA
  {
    public:
      using PublicKey = ECPoint;

      /*** SecretKey ***/
      class SecretKey
      {
        public:
          explicit SecretKey (const ECDSA &C, RandGen & randgen);

          const BN & d () const;
          const ECPoint & Q () const;

        private:
          BN d_;
          ECPoint Q_;
      };

      /*** Signature ***/
      class Signature : public ECSignature
      {
        public:
          Signature(const ECDSA & C,
                    RandGen & randgen,
                    const SecretKey & sk,
                    const HashAlgo::Digest & m);
      };

      /* constructors */
      explicit ECDSA (SecLevel seclevel);

      /* crypto protocol */
      SecretKey keygen (RandGen & randgen) const;
      PublicKey keygen (const SecretKey &sk) const;
      Signature sign (RandGen & randgen, const SecretKey &sk, const HashAlgo::Digest &m) const;
      bool verif (const Signature &s, const PublicKey &Q,
                                      const HashAlgo::Digest &m) const;
      HashAlgo::Digest hash (const std::vector<unsigned char> & m) const;

    private:
      const ECGroup ec_group_;
      mutable HashAlgo H_;
  }; /* ECDSA */

} /* BICYCL namespace */

#include "ecdsa.inl" // IWYU pragma: keep

#endif /* BICYCL_EC_ECDSA_HPP */
