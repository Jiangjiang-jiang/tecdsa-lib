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
#ifndef BICYCL_EC_SIGNATURE_INL
#define BICYCL_EC_SIGNATURE_INL

#include "signature.hpp"

namespace BICYCL
{
  /**
   * ECSignature constructor with BN params
   *
   **/
  inline
  ECSignature::ECSignature(const BN & r,
                          const BN & s)
    : r_{r},
      s_{s}
  {
    // Nothing to do
  }

  /**
   * ECSignature constructor with Mpz params
   *
   **/
  inline
  ECSignature::ECSignature(const Mpz & r, const Mpz & s)
    : r_{r},
      s_{s}
  {
    // Nothing to do
  }

  inline const BN & ECSignature::r() const
  {
    return r_;
  }

  inline const BN & ECSignature::s() const
  {
    return s_;
  }

  /* */
  inline
  bool ECSignature::verify(const ECGroup & E,
                         const PublicKey & Q,
                         const HashAlgo::Digest & m) const
  {

    /* Check correctness of parameters */
    if (!E.has_correct_prime_order (Q)) /* check that Q has order n */
      return false;

    if (!E.is_positive_less_than_order (r_))
      return false;

    if (!E.is_positive_less_than_order (s_))
      return false;

    bool verified = true;

    ECPoint T (E);
    BN sinv, u1, u2, x1, tmp;
    E.inverse_mod_order (sinv, s_);
    E.mul_mod_order (u1, sinv, BN (m)); /* u1 = s^-1 * H(m) */
    E.mul_mod_order (u2, sinv, r_);            /* u2 = s^-1 * r    */

    E.scal_mul (T, u1, u2, Q); /* T = u1*G + u2*Q */

    if (E.is_at_infinity (T))
      verified = false;
    else
    {
      /* Check that x coord of T gives r_ */
      E.x_coord_of_point (tmp, T);
      E.mod_order (x1, tmp);

      verified = (x1 == r_);
    }

    return verified;
  }

    /* */
  inline
  bool ECSignature::operator== (const ECSignature &other) const
  {
    return r_ == other.r_ && s_ == other.s_;
  }

  /* */
  inline
  bool ECSignature::operator!= (const ECSignature &other) const
  {
    return !(*this == other);
  }

  /* */
  inline
  std::ostream & operator<< (std::ostream &o, const ECSignature &s)
  {
    return o << "(" << s.r_ << ", " << s.s_ << ")";
  }

} /* namespace BICYCL */

#endif /* BICYCL_EC_SIGNATURE_INL */