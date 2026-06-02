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

/**
 * @example CL_HSMqk_example.cpp
 * This file is an example of how to use the BICYCL::CL_HSMqk class.\n
 * It shows how to setup the CL cryptosystem, and perform encryption and decryption.
 *
 * @defgroup CL_THRESHOLD Threshold decryption
 * @ingroup CL
 * T-out-of-N threshold decryption using class groups
 */


#ifndef BICYCL_CL_CL_HSMQK_HPP
#define BICYCL_CL_CL_HSMQK_HPP

#include <iostream>
#include <tuple>

#include "bicycl/arith/openssl_wrapper.hpp"
#include "bicycl/arith/gmp_extras.hpp"
#include "bicycl/arith/qfi.hpp"
#include "bicycl/cl/CL_HSM_utils.hpp"
#include "bicycl/seclevel.hpp"

/**
 * @defgroup CL Class Groups
 * Set of classes for cryptography based on the hidden subgroup membership problem.
 *
 * @defgroup CL_ENCRYPTION Encryption
 * @ingroup CL
 * Encryption using class groups
 */
namespace BICYCL
{
  /**
   * Class for the cryptosystem based on the hidden subgroup membership problem.
   *
   * Ref: ??
   * @ingroup CL_ENCRYPTION
   * @nosubgrouping
   */
  class CL_HSMqk
  {
    protected:
      /** an odd prime. */
      Mpz q_;

      /** an positive integer */
      size_t k_;

      /** an odd prime or 1. */
      Mpz p_;

      /** q^k */
      Mpz M_;

      /** \f$ \ClDeltaK \f$ : the class group of the maximal order.
       * Its discriminant is equal to \f$ -p \times q \f$.
       */
      ClassGroup Cl_DeltaK_;

      /** \f$ \ClDelta \f$: the class group of the order of conductor
       * \f$M=q^k\f$.
       * Its discriminant is equal to \f$ -p \times q^{2k+1} \f$.
       * It contains the subgroup \f$F\f$.
       */
      ClassGroup Cl_Delta_;

      /** \c true if the compact variant is used, \c false otherwise. */
      bool compact_variant_;

      /** \c true if the large-message variant is used, \c false otherwise. */
      bool large_message_variant_;

      /** The generator of the group \f$H\f$.
       * If the compact variant is not used, the generator is an element of
       * \f$ \ClDelta \f$, else it is an element of \f$ \ClDeltaK \f$.
       */
      QFI h_;

      /** The distance parameter used to produce a almost uniform distribution.
       * Given a bound on the class number of \f$ \ClDeltaK \f$, this bound is
       * multiplied by 2^(distance_-2) to produce a random distribution that
       * is at distance 2^(distance_) of being uniform.
       */
      size_t distance_;

      /** Actual bound use to draw random values
       * It is equal to 2^(distance_-2) times Cl_Delta_.class_number_bound_
       */
      Mpz exponent_bound_;

      /** Precomputation data: h_^(2^e_), h_^(2^d_), h_^(d_+e_) */
      QFIPrecomp h_precomp_;

    public:
      /** Class used to represent a secret key of the cryptosystem */
      using SecretKey = _Utils::CL_HSM_SecretKey<CL_HSMqk>;
      /** Class used to represent a public key of the cryptosystem */
      using PublicKey = _Utils::CL_HSM_PublicKey<CL_HSMqk>;
      /** Class used to represent a cleartext for the cryptosystem */
      using ClearText = _Utils::CL_HSM_ClearText<CL_HSMqk>;
      /** Class used to represent a ciphertext for the cryptosystem */
      using CipherText = _Utils::CL_HSM_CipherText<CL_HSMqk>;
      /** Type to store the genus of of an element of the class group */
      using Genus = std::tuple<int, int>;

      /**
       * @name Constructors
       *
       * Setup of the cryptosystem
       *
       *@{
       */
      /**
       * Setup of the cryptosystem given @p q, @p k and @p p.
       */
      CL_HSMqk (const Mpz &q, size_t k, const Mpz &p, const CL_Params params={});
      /**
       * Copy constructor, only the value of compact variant can be changed.
       */
      CL_HSMqk (const CL_HSMqk &C, bool compact_variant);
      /**
       * Setup of the cryptosystem given @p q and the size of \f$\Delta_K\f$@p.
       */
      CL_HSMqk (const Mpz &q, size_t k, size_t DeltaK_nbits, RandGen &randgen,
                const CL_Params params={});
      /**
       * Setup of the cryptosystem given the size of @p q and the size of
       * \f$\Delta_K\f$@p.
       */
      CL_HSMqk (size_t q_nbits, size_t k, size_t DeltaK_nbits, RandGen &randgen,
                const CL_Params params={});
      /**
       * Setup of the cryptosystem given @p q and the desired security level.
       *
       * The equivalence between security level and the size of \f$\Delta_K\f$
       * can be found in the class \ref SecLevel.
       */
      CL_HSMqk (const Mpz &q, size_t k, SecLevel seclevel, RandGen &randgen,
                const CL_Params params={});
      /**
       * Setup of the cryptosystem given the size of @p q and the desired
       * security level.
       *
       * The equivalence between security level and the size of \f$\Delta_K\f$
       * can be found in the class \ref SecLevel.
       */
      CL_HSMqk (size_t q_nbits, size_t k, SecLevel seclevel, RandGen &randgen,
                const CL_Params params={});
      /**@}*/

      /**
       * @name Public methods to retrieve the public parameters
       *@{
       */
      /** Return k */
      size_t k () const;
      /** Return q, the cardinality of the subgroup \f$F\f$ is \f$M=q^k\f$. */
      const Mpz & q () const;
      /** Return p, a odd prime or 1. */
      const Mpz & p () const;
      /** Return \f$M=q^{k}\f$, the conductor of \f$\Delta\f$. */
      const Mpz & M () const;
      /** Return \f$\Delta_K = -pq\f$. */
      const Mpz & DeltaK () const;
      /** Return \f$\Delta = -pq^{2k+1}\f$. */
      const Mpz & Delta () const;
      /**
       * Return \f$\ClDeltaK\f$: the class group of discriminant
       * \f$\Delta_K = -pq\f$.
       */
      const ClassGroup & Cl_DeltaK () const;
      /**
       * Return \f$\ClDelta\f$: the class group of discriminant
       * \f$\Delta = -pq^{2k+1}\f$.
       */
      const ClassGroup & Cl_Delta () const;
      const ClassGroup & Cl_G () const;
      /** Return \f$h\f$, the generator of the cyclic subgroup \f$H\f$ */
      const QFI & h () const;
      /** Return whether the compact variant is used or not */
      bool compact_variant () const;
      /** Return whether the large message variant is used or not */
      bool large_message_variant () const;
      /** Return the bound for secret keys: the bound on the size of \f$H\f$ */
      const Mpz & secretkey_bound () const;
      /** Return the bound for cleartexts: \f$M=q^k\f$ */
      const Mpz & cleartext_bound () const;
      /** Return the bound for random exponents: same as #secretkey_bound */
      const Mpz & encrypt_randomness_bound () const;
      /** Return the distance */
      size_t lambda_distance () const;
      /**@}*/

      /**
       * @name Public methods for computation in subgroups
       *@{
       */
      /** Set @p r to \f$h^e\f$, where #h is the generator of \f$H\f$. */
      void power_of_h (QFI &r, const Mpz &e) const;
      /** Return \f$f^m\f$, where `f` is the generator of \f$F\f$. */
      QFI power_of_f (const Mpz &m) const;
      /** Return the discrete logarithm of the form @p fm. */
      Mpz dlog_in_F (const QFI &fm) const;
      /**
       * Compute \f$\psi_{q^k}(f)\f$ to move @p f from \f$\Delta_K\f$ to
       * \f$\Delta\f$.
       */
      void from_Cl_DeltaK_to_Cl_Delta (QFI &f) const;
      /** Compute the genus of the form f */
      Genus genus (const QFI &f) const;
      /**@}*/

      /**
       * @name Public methods implementing the cryptographic functionalities
       *@{
       */
      /** Generate a random secret key */
      SecretKey keygen (RandGen &randgen) const;
      /** Compute the public key associated to a secret key */
      PublicKey keygen (const SecretKey &sk) const;
      /** Encrypt @p m using public key @p pk */
      CipherText encrypt (const PublicKey &pk, const ClearText &m,
                          RandGen &randgen) const;
      /** Encrypt @p m using public key @p pk and randomness @p r */
      CipherText encrypt (const PublicKey &pk, const ClearText &m,
                          const Mpz&r) const;
      /** Decrypt @p c using secret key @p sk */
      ClearText decrypt (const SecretKey &sk, const CipherText &c) const;
      /** Homomorphically add ciphertexts @p ca and @p cb */
      CipherText add_ciphertexts (const PublicKey &pk, const CipherText &ca,
                                  const CipherText &cb, RandGen &randgen) const;
      /** Homomorphically add ciphertexts @p ca and @p cb using @p r */
      CipherText add_ciphertexts (const PublicKey &pk, const CipherText &ca,
                                  const CipherText &cb, const Mpz &r) const;
      /** Add the two cleartexts @p ma and @p mb */
      ClearText add_cleartexts (const ClearText &ma, const ClearText &mb) const;
      /** Homomorphically compute @p s times @p c */
      CipherText scal_ciphertexts (const PublicKey &pk, const CipherText &c,
                                   const Mpz &s, RandGen &randgen) const;
      /** Homomorphically compute @p s times @p c using @p r */
      CipherText scal_ciphertexts (const PublicKey &pk, const CipherText &c,
                                   const Mpz &s, const Mpz &r) const;
      /** Compute @p s times @p m */
      ClearText scal_cleartexts (const ClearText &m, const Mpz &s) const;
      /** Homomorphically compute  @p ca plsu @p s times @p cb  */
      CipherText addscal_ciphertexts (const PublicKey &pk, const CipherText &ca,
                                  const CipherText &cb, const Mpz &s, RandGen &randgen) const;
      /** Homomorphically compute  @p ca plsu @p s times @p cb using @p r  */
      CipherText addscal_ciphertexts (const PublicKey &pk, const CipherText &ca,
                                  const CipherText &cb, const Mpz &s, Mpz & r) const;

      /**@}*/

      /** Print the public parameters of the cryptosystem */
      friend std::ostream & operator<< (std::ostream &, const CL_HSMqk &);

    protected:
      /* utils for ctor */
      static Mpz random_p (RandGen &randgen, const Mpz &q, size_t DeltaK_nbits);
      static Mpz compute_DeltaK (const Mpz &, const Mpz &);
      static Mpz compute_Delta (const Mpz &, const Mpz &, size_t);
      /* utils */
      void raise_to_power_M (const ClassGroup &Cl, QFI &f) const;
      void F_kerphi_pow (Mpz &, const Mpz &, const Mpz &) const;
      size_t F_kerphi_div (Mpz &, const Mpz &, size_t, const Mpz &) const;
  };

  /****/
  class CL_HSMqk_ZKAoKProof
  {
    public:
      CL_HSMqk_ZKAoKProof (const CL_HSMqk &C, HashAlgo &H,
                           const CL_HSMqk::PublicKey &pk,
                           const CL_HSMqk::CipherText &c,
                           const CL_HSMqk::ClearText &a,
                           const Mpz &r, RandGen &randgen);

      bool verify (const CL_HSMqk &C, HashAlgo &H,
                   const CL_HSMqk::PublicKey &pk,
                   const CL_HSMqk::CipherText &c) const;

    private:
      Mpz k_from_hash (HashAlgo &H, const CL_HSMqk::PublicKey &pk,
                       const CL_HSMqk::CipherText &c,
                       const QFI &t1, const QFI &t2) const;

      Mpz u1_;
      Mpz u2_;
      Mpz k_;
  };


} /* BICYCL namespace */

#include "CL_HSMqk.inl" // IWYU pragma: keep

#endif /* BICYCL_CL_CL_HSMQK_HPP */
