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

#include <iostream>

#include "bicycl.hpp"

int main ()
{
  /* A random generator. */
  BICYCL::RandGen randgen;

  /* For reproducibility, the seed is fixed. */
  BICYCL::Mpz seed(42UL);
  randgen.set_seed(seed);

  /* The desired security level. */
  BICYCL::SecLevel seclevel(112);

  /* Two Party ECDSA:
   * Public parameters of CL and EC are generated according to the given
   * security level.
   */
  BICYCL::TwoPartyECDSA context(seclevel, randgen);

  /* Print some details about the cryptosystem CL. */
  std::cout << "--- CL ---\n" << context.CL_HSMq() << std::endl;

  /* Print some details about the Elliptic Curve. */
  std::cout << "--- Elliptic Curve ---\n" << context.ec_group() << std::endl;

  /* Two Party signature :
   * Initialize players with the generatd context.
   * There MUST be one "Player1" and one "Player2", their computations are
   * asymmetric
   */

  BICYCL::TwoPartyECDSA::Player1 P1(context);
  BICYCL::TwoPartyECDSA::Player2 P2(context);

  /* Keygen */
  std::cout << "\nP1 and P2 perform keygen" << std::endl;

  /* If any player is dishonest, a ProtocolAbortError exception is raised. */
  try
  {
    P1.KeygenPart1(context, randgen);

    /* P1 --- com-proof(Q1) ---> P2 */
    P2.KeygenPart2(context, randgen, P1.commit());

    /* P1 < --- (Q2, zk-proof(Q2)) --- P2 */
    P1.KeygenPart3(context,
                    randgen,
                    P2.Q2(),
                    P2.zk_proof());

    /* P1 --- (Q1, pk, Ckey, decomp-proof(Q1)) ---> P2 */
    P2.KeygenPart4(context,
                    P1.Q1(),
                    P1.Ckey(),
                    P1.pkcl(),
                    P1.commit_secret(),
                    P1.zk_com_proof(),
                    P1.proof_ckey());

    std::cout << "Keygen is done" << '\n' << std::endl;
  }
  catch (const BICYCL::TwoPartyECDSA::ProtocolAbortError& e)
  {
    std::cout << "Keygen failed !" << '\n' << std::endl;
    return EXIT_FAILURE;
  }

  /* Both players know the public key */
  BICYCL::BN Qx, Qy;
  context.ec_group().coords_of_point(Qx, Qy, P1.public_key()/*Or P2.public_key()*/);

  std::cout << "public key Q = (" << Qx << ", " << Qy << ")" << std::endl;


  /* Sign */

  /* m is the message, it contains 16 random bytes */
  std::vector<unsigned char> m(randgen.random_bytes (16));

  std::cout << "\nmessage = " << std::hex;
  for (unsigned char byte : m) {
    std::cout <<  static_cast<unsigned int>(byte);
  }
  std::cout << std::endl;

  /* Hash message */
  BICYCL::HashAlgo::Digest hashed{context.hash(m)};

  /* Generate random 128-bit sid */
  BICYCL::Mpz sid{randgen.random_mpz_2exp(128)};

  /* P1 starts */
  P1.SignPart1(context, randgen, sid);

  /* P1 --- com-proof(R1) ---> P2 */
  P2.SignPart2(context, randgen, P1.commit(), sid);

  /* P1 < --- (R2, zk-proof(R2)) --- P2 */
  P1.SignPart3(context, P2.R2(), P2.zk_proof(), sid);

  /* P1 --- (R1, decomp-proof(R1)) --- > P2 */
  P2.SignPart4(
      context, randgen, hashed, P1.R1(), P1.commit_secret(), P1.zk_com_proof(), sid);

  /* P1 < --- C3 --- P2 */
  BICYCL::ECSignature signature = P1.SignPart5(context, hashed, P2.C3());

  std::cout << "\nSignature: " << signature << std::endl;

  bool verif_success = context.verify(signature, P1.public_key(), hashed);

  std::cout << "\nECDSA signature verification: "
            << (verif_success ? "OK" : "KO")
            << std::endl;

  return EXIT_SUCCESS;
}
