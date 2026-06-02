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
#ifndef BICYCL_EC_SIGNATURE_HPP
#define BICYCL_EC_SIGNATURE_HPP

#include "bicycl/arith/openssl_wrapper.hpp"

namespace BICYCL
{
  /**
   * @brief Generic ECDSA signature class
   *
   * Implement members and functions that are common to ECDSA and its variations
   * Specifically, a ECSignature is always :
   *   - defined by \f$r\f$ and \f$s\f$, both in \f$\Z/{q\Z}\f$ (with \f$q\f$ the order of the Elliptic Curve)
   *   - verified using the ECDSA verification algorithm
   *
   * @ingroup ECDSA_CLASSIC
   */
  class ECSignature
  {
    public:
      using PublicKey = ECPoint;
      using Message = std::vector<unsigned char>;

      /* ctor */
      ECSignature() = default;
      ECSignature(const BN & r, const BN & s);
      ECSignature(const Mpz & r, const Mpz & s);

      /* Getters */
      const BN & r() const;
      const BN & s() const;

      /* Verify */
      bool verify ( const ECGroup & E,
                    const PublicKey & Q,
                    const HashAlgo::Digest & m) const;

      /* Compare */
      bool operator== (const ECSignature &other) const;
      bool operator!= (const ECSignature &other) const;

      friend std::ostream & operator<< (std::ostream&, const ECSignature&);

    protected:
      /* Members */
      BN r_;
      BN s_;
  }; /* ECSignature */

} /* namespace BICYCL */

#include "signature.inl" // IWYU pragma: keep

#endif /* BICYCL_EC_SIGNATURE_HPP */