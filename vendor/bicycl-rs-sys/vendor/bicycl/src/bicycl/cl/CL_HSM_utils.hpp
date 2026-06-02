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
#ifndef BICYCL_CL_CL_HSM_UTILS_HPP
#define BICYCL_CL_CL_HSM_UTILS_HPP

#ifdef BICYCL_WITH_PTHREADS
#include <thread>
#endif

#include "bicycl/arith/gmp_extras.hpp"
#include "bicycl/arith/qfi.hpp"

namespace BICYCL
{
  /**
    * Class to represent default parameters of CL cryptosystems.
    */
  struct CL_Params
  {
    CL_Params() = default;
    CL_Params(size_t d, bool b): distance(d), compact_variant(b) { }
    explicit CL_Params(size_t d) : distance(d) { }
    explicit CL_Params(bool b) : compact_variant(b) { }

    /** The default value for statistical distance is 42 to get 40 bits of
        statistical security. */
    size_t distance = 42;
    /** By default, the compact variant is not used. */
    bool compact_variant = false;
  };
} /* BICYCL namespace */

namespace BICYCL { namespace _Utils
{
  /**
    * Class to represent secret key of CL_HSM cryptosystems
    */
  template <class Cryptosystem>
  class CL_HSM_SecretKey : public Mpz
  {
    public:
      /* constructors */
      CL_HSM_SecretKey () = default;
      CL_HSM_SecretKey (const Cryptosystem &, const Mpz &);
      CL_HSM_SecretKey (const Cryptosystem &, RandGen &);
  };

  /**
    * Class to represent public key of CL_HSM cryptosystems
    */
  template <class Cryptosystem>
  class CL_HSM_PublicKey
  {
    protected:
      /** The actual public key: a QFI */
      QFI pk_;
      /** Precomputation data: pk_^(2^e_), pk_^(2^d_), pk_^(d_+e_) */
      QFIPrecomp pk_precomp_;

    public:
      /* constructors */
      CL_HSM_PublicKey () = default;
      CL_HSM_PublicKey (const Cryptosystem &,
                        const CL_HSM_SecretKey<Cryptosystem> &);
      CL_HSM_PublicKey (const Cryptosystem &,
                        const QFI &);

      /* getters */
      const QFI & elt () const;

      /* */
      void exponentiation (const Cryptosystem &C, QFI &r, const Mpz &n) const;

      /* I/O */
      template <class C>
      friend std::ostream & operator<< (std::ostream &,
                                        const CL_HSM_PublicKey<C> &);
  };

  /* Forward declaration */
  template <class Cryptosystem> class CL_HSM_CipherText;

  /**
    * Class to represent clear text of CL_HSM cryptosystems
    */
  template <class Cryptosystem>
  class CL_HSM_ClearText : public Mpz
  {
    public:
      /* constructors */
      CL_HSM_ClearText () = default;
      CL_HSM_ClearText (const Cryptosystem &, const Mpz &);
      CL_HSM_ClearText (const Cryptosystem &, RandGen &);
      CL_HSM_ClearText (const Cryptosystem &,
                        const CL_HSM_SecretKey<Cryptosystem> &,
                        const CL_HSM_CipherText<Cryptosystem> &);
      CL_HSM_ClearText (const Cryptosystem &,
                        const CL_HSM_ClearText<Cryptosystem> &,
                        const CL_HSM_ClearText<Cryptosystem> &);
      CL_HSM_ClearText (const Cryptosystem &,
                        const CL_HSM_ClearText<Cryptosystem> &,
                        const Mpz &);
  };

  /**
    * Class to represent cipher text of CL_HSM cryptosystems
    */
  template <class Cryptosystem>
  class CL_HSM_CipherText
  {
    protected:
      /** two QFIs */
      QFI c1_, c2_;

    public:
      /* constructors */
      CL_HSM_CipherText() = default;

      CL_HSM_CipherText (const Cryptosystem &,
                          const CL_HSM_PublicKey<Cryptosystem> &,
                          const CL_HSM_ClearText<Cryptosystem> &,
                          const Mpz &);
      CL_HSM_CipherText (const Cryptosystem &,
                          const CL_HSM_PublicKey<Cryptosystem> &,
                          const CL_HSM_CipherText &,
                          const CL_HSM_CipherText &,
                          const Mpz &);
      CL_HSM_CipherText (const Cryptosystem &,
                          const CL_HSM_PublicKey<Cryptosystem> &,
                          const CL_HSM_CipherText &,
                          const Mpz &,
                          const Mpz &);
      CL_HSM_CipherText(const Cryptosystem &,
                        const CL_HSM_PublicKey<Cryptosystem> &,
                        const CL_HSM_CipherText &,
                        const CL_HSM_CipherText &,
                        const Mpz &,
                        const Mpz &);
      CL_HSM_CipherText (const QFI & c1, const QFI & c2);

      /* getters */
      const QFI & c1 () const;
      const QFI & c2 () const;
  };

} /* _Utils namespace */ } /* BICYCL namespace */

#include "CL_HSM_utils.inl" // IWYU pragma: keep

#endif /* BICYCL_CL_CL_HSM_UTILS_HPP */
