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
#ifndef BICYCL_EC_INL
#define BICYCL_EC_INL

#include "bicycl/ec/ecdsa.hpp"

namespace BICYCL
{
  /******************************************************************************/
  /* */
  inline
  ECDSA::SecretKey::SecretKey (const ECDSA &C, RandGen & randgen)
    : d_(C.ec_group_.random_mod_order(randgen)),
      Q_(C.ec_group_, d_)
  {
  }

  /* */
  inline
  const BN & ECDSA::SecretKey::d () const
  {
    return d_;
  }

  /* */
  inline
  const ECPoint & ECDSA::SecretKey::Q () const
  {
    return Q_;
  }

  /* */
  inline
  ECDSA::ECDSA (SecLevel seclevel) : ec_group_(seclevel), H_(seclevel)
  {
  }

  /* */
  inline
  ECDSA::SecretKey ECDSA::keygen (RandGen & randgen) const
  {
    return SecretKey (*this, randgen);
  }

  /* */
  inline
  ECDSA::PublicKey ECDSA::keygen (const SecretKey &sk) const
  {
    return PublicKey (ec_group_, sk.Q());
  }

  inline
  HashAlgo::Digest ECDSA::hash (const std::vector<unsigned char> & m) const
  {
    return H_(m);
  }

  /* */
  inline ECDSA::Signature ECDSA::sign(RandGen & randgen,
                                      const SecretKey & sk,
                                      const HashAlgo::Digest & m) const
  {
    return Signature (*this, randgen, sk, m);
  }

  /* */
  inline
  ECDSA::Signature::Signature(const ECDSA & C,
                              RandGen & randgen,
                              const SecretKey & sk,
                              const HashAlgo::Digest & m)
  {
    BN z{m};

    do
    {
      BN k (C.ec_group_.random_mod_order(randgen));
      if (k.is_zero())
        continue;

      ECPoint K (C.ec_group_, k);
      BN tmp;
      C.ec_group_.x_coord_of_point (tmp, K);
      C.ec_group_.mod_order (r_, tmp); /* r = x([k] P) mod n */
      if (r_.is_zero())
        continue;

      C.ec_group_.mul_mod_order (s_, r_, sk.d());

      BN::add (s_, s_, z);

      C.ec_group_.inverse_mod_order (tmp, k);
      C.ec_group_.mul_mod_order (s_, s_, tmp); /* s = k^(-1)*(z + r*d) */
    } while (s_.is_zero());
  }

  /* */
  inline bool ECDSA::verif(const Signature & signature,
                           const PublicKey & Q,
                           const HashAlgo::Digest & m) const
  {
    return signature.verify (ec_group_, Q, m);
  }

} /* BICYCL namespace */

#endif /* BICYCL_EC_INL */