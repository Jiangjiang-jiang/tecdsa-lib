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
#ifndef BICYCL_SECLEVEL_INL
#define BICYCL_SECLEVEL_INL

/* */
const SecLevel SecLevel::_112 {112u};
const SecLevel SecLevel::_128 {128u};
const SecLevel SecLevel::_192 {192u};
const SecLevel SecLevel::_256 {256u};

/* */
inline
const std::array<SecLevel, 4> SecLevel::All ()
{
  return { _112, _128, _192, _256 };
}

/* */
inline
SecLevel::SecLevel (unsigned int s) : value_{s}
{
  if (s != 112u && s != 128u && s != 192u && s != 256) {
    throw InvalidSecLevelException();
  }
}

/* */
inline
SecLevel::SecLevel (const std::string &s)
{
  if (s == "112")       value_ = 112u;
  else if (s == "128")  value_ = 128u;
  else if (s == "192")  value_ = 192u;
  else if (s == "256")  value_ = 256u;
  else                  throw InvalidSecLevelException();
}

/* */
inline
size_t SecLevel::RSA_modulus_bitsize () const
{
  if (value_ == 112u)        return 2048;
  else if (value_ == 128u)   return 3072;
  else if (value_ == 192u)   return 7680;
  else if (value_ == 256u)   return 15360;
  else                       throw InvalidSecLevelException();
}

/* */
inline
size_t SecLevel::discriminant_bitsize () const
{
  if (value_ == 112u)        return 1348;
  else if (value_ == 128u)   return 1827;
  else if (value_ == 192u)   return 3598;
  else if (value_ == 256u)   return 5971;
  else                       throw InvalidSecLevelException();
}

/* */
inline
size_t SecLevel::soundness () const
{
  return value_;
}

inline
size_t SecLevel::statistical () const
{
  /*
   * Statistical security parameter to satisfy the requirements for the
   * NIST's First Call for Multi-party Threshold schemes (+2 to be used as CL
   * statistical distance).
   */
  if (value_ <= 128u)      return 42;
  else if (value_ <= 256u) return 66;
  else                     throw InvalidSecLevelException();
}

/* */
inline
int SecLevel::elliptic_curve_openssl_nid () const
{
  if (value_ == 112u)        return ECGroup::P224;
  else if (value_ == 128u)   return ECGroup::P256;
  else if (value_ == 192u)   return ECGroup::P384;
  else if (value_ == 256u)   return ECGroup::P521;
  else                       throw InvalidSecLevelException();
}

/* */
inline
int SecLevel::sha3_openssl_nid () const
{
  if (value_ == 112u)        return HashAlgo::SHA3_224;
  else if (value_ == 128u)   return HashAlgo::SHA3_256;
  else if (value_ == 192u)   return HashAlgo::SHA3_384;
  else if (value_ == 256u)   return HashAlgo::SHA3_512;
  else                       throw InvalidSecLevelException();
}

/* */
inline
std::ostream & operator<< (std::ostream &o, SecLevel seclevel)
{
  return o << seclevel.value_;
}
#endif /* BICYCL_SECLEVEL_INL */
