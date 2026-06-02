/*
 * BICYCL Implements CryptographY in CLass groups
 * Copyright (C) 2024  Cyril Bouvier <cyril.bouvier@lirmm.fr>
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
#include <iostream>

#include "bicycl.hpp"

int main()
{
  /* This prime q will be used to build a CL cryptosystem. */
  BICYCL::Mpz q("0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d");

  /* A random generator. */
  BICYCL::RandGen randgen;

  /* For reproducibility, the seed is fixed. */
  BICYCL::Mpz seed(42UL);
  randgen.set_seed(seed);

  /* The desired security level. */
  BICYCL::SecLevel seclevel(112);

  /* C is a HSM cryptosystem for q with k=1 (the second parameter). The
   * prime p will be generated at random according to the given security
   * level.
   */
  BICYCL::CL_HSMqk C(q, 1, seclevel, randgen);

  /* Print some details about the cryptosystem C. */
  std::cout << C << std::endl;

  /* Keygen */
  BICYCL::CL_HSMqk::SecretKey sk = C.keygen(randgen);
  BICYCL::CL_HSMqk::PublicKey pk = C.keygen(sk);
  std::cout << "public key = " << pk << std::endl;

  /* m is the cleartext, it contains the value 14 (modulo q) */
  BICYCL::CL_HSMqk::ClearText m(C, BICYCL::Mpz("14"));
  std::cout << "message = " << m << std::endl;

  /* The cleartext is encrypted using the public key pk. */
  BICYCL::CL_HSMqk::CipherText c = C.encrypt(pk, m, randgen);
  std::cout << "ciphertext = " << c.c1() << std::endl << c.c2() << std::endl;

  /* The ciphertext is decrypted using the corresponding secret key sk. */
  BICYCL::CL_HSMqk::ClearText m2 = C.decrypt(sk, c);
  std::cout << "decrypted cyphertext = " << m2 << std::endl;

  return EXIT_SUCCESS;
}
