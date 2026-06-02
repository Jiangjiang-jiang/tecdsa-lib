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
#ifndef BICYCL_SECLEVEL_HPP
#define BICYCL_SECLEVEL_HPP

#include <array>
#include <iostream>
#include <stdexcept>
#include <string>

namespace BICYCL
{
  /*****/
  class InvalidSecLevelException : public std::invalid_argument
  {
    public:
      InvalidSecLevelException() : std::invalid_argument("not a valid SecLevel")
      {
      }
  };

  /*****/
  class SecLevel
  {
    public:
      static const SecLevel _112;
      static const SecLevel _128;
      static const SecLevel _192;
      static const SecLevel _256;
      static const std::array<SecLevel, 4> All ();

      SecLevel() = delete;
      explicit SecLevel (unsigned int s);
      explicit SecLevel (const std::string &s);

      size_t nbits() const { return value_; }

      /* */
      explicit operator bool() = delete;

      /* */
      size_t RSA_modulus_bitsize () const;
      size_t discriminant_bitsize () const;
      size_t soundness () const;
      size_t statistical () const;
      int elliptic_curve_openssl_nid () const;
      int sha3_openssl_nid () const;

      /* */
      friend std::ostream & operator<< (std::ostream &o, SecLevel seclevel);
      friend std::string to_string (SecLevel seclevel);

    protected:
      unsigned int value_;
  };
} /* BICYCL namespace */


#endif /* BICYCL_SECLEVEL_HPP */
