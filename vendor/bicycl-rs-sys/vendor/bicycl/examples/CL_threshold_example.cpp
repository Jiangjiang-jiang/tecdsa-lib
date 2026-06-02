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
  /* This prime q will be used to build a CL cryptosystem. */
  BICYCL::Mpz q("0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d");

  /* A random generator. */
  BICYCL::RandGen randgen;

  /* For reproducibility, the seed is fixed. */
  BICYCL::Mpz seed(42UL);
  randgen.set_seed(seed);

  /* The desired security level. */
  BICYCL::SecLevel seclevel(112);

  /* The desired statistical security */
  size_t stat_security = 112;

  /* The desired soundness parameter */
  size_t soundness = 112;

  /* C is a HSM cryptosystem for q with k=1 (the second parameter). The
   * prime p will be generated at random according to the given security
   * level.
   */
  BICYCL::CL_HSMqk CL(q, 1, seclevel, randgen, BICYCL::CL_Params{stat_security});

  /* Print some details about the cryptosystem CL. */
  std::cout << "--- CL ---\n" << CL << std::endl;

  /* Threshold Decryption :
   * 3 Players taking part in a 2-out-of-3 decryption scheme.
   * Players IDs are 0, 1, and 2
   */
  const unsigned int N = 3;   // N = 3 players
  const unsigned int T = 1;   // Threshold is T+1 = 2
  BICYCL::CL_Threshold_Static P0(CL,N,T,0, soundness);
  BICYCL::CL_Threshold_Static P1(CL,N,T,1, soundness);
  BICYCL::CL_Threshold_Static P2(CL,N,T,2, soundness);

  std::cout << "--- Threshold Decryption with CL ---\n";
  std::cout << "N = " << N << "\nT+1 = " << T+1 << '\n';
  std::cout << "Players IDs are " << P0.i() << ", " << P1.i() << ", and " << P2.i()
            << std::endl;

  /* Keygen */
  std::cout << "\nP0, P1 and P2 perform keygen" << std::endl;

  /* Players generate their shares and commitments */
  P0.keygen_dealing(CL, randgen);
  P1.keygen_dealing(CL, randgen);
  P2.keygen_dealing(CL, randgen);

  /* Players broadcast their public values */
  auto P0_commitments = P0.C();     /* P0 ----- C0 ----> broadcast */
  auto P0_proof = P0.batch_proof(); /* P0 -- Proof_0 --> broadcast */
  auto P1_commitments = P1.C();     /* P1 ----- C1 ----> broadcast */
  auto P1_proof = P1.batch_proof(); /* P1 -- Proof_1 --> broadcast */
  auto P2_commitments = P2.C();     /* P2 ----- C2 ----> broadcast */
  auto P2_proof = P2.batch_proof(); /* P2 -- Proof_2 --> broadcast */

  P1.keygen_add_commitments(0, P0_commitments); /* broadcast -- C0 --> P1 */
  P2.keygen_add_commitments(0, P0_commitments); /* broadcast -- C0 --> P2 */
  P0.keygen_add_commitments(1, P1_commitments); /* broadcast -- C1 --> P0 */
  P2.keygen_add_commitments(1, P1_commitments); /* broadcast -- C1 --> P2 */
  P0.keygen_add_commitments(2, P2_commitments); /* broadcast -- C2 --> P0 */
  P1.keygen_add_commitments(2, P2_commitments); /* broadcast -- C2 --> P1 */

  P1.keygen_add_proof(0, P0_proof); /* broadcast -- Proof_0 --> P1 */
  P2.keygen_add_proof(0, P0_proof); /* broadcast -- Proof_0 --> P2 */
  P0.keygen_add_proof(1, P1_proof); /* broadcast -- Proof_1 --> P0 */
  P2.keygen_add_proof(1, P1_proof); /* broadcast -- Proof_1 --> P2 */
  P0.keygen_add_proof(2, P2_proof); /* broadcast -- Proof_2 --> P0 */
  P1.keygen_add_proof(2, P2_proof); /* broadcast -- Proof_2 --> P1 */

  /* Players send private shares over Peer-2-Peer channels */
  P1.keygen_add_share(0, P0.y_k(1));  /* P0 -- y01 --> P1 */
  P2.keygen_add_share(0, P0.y_k(2));  /* P0 -- y02 --> P2 */
  P0.keygen_add_share(1, P1.y_k(0));  /* P1 -- y10 --> P0 */
  P2.keygen_add_share(1, P1.y_k(2));  /* P1 -- y12 --> P2 */
  P0.keygen_add_share(2, P2.y_k(0));  /* P2 -- y20 --> P0 */
  P1.keygen_add_share(2, P2.y_k(1));  /* P2 -- y21 --> P1 */


  /* Players check each other's shares and proofs */
  bool success;
  success  = P0.keygen_check_verify_all_players(CL);
  success &= P1.keygen_check_verify_all_players(CL);
  success &= P2.keygen_check_verify_all_players(CL);

  std::cout << std::boolalpha;
  std::cout << "Keygen check is successful: " << success << std::endl;

  /* Players extract the implicit values after sharing */
  P0.keygen_extract(CL);
  P1.keygen_extract(CL);
  P2.keygen_extract(CL);

  std::cout << "Keygen is done" << '\n' << std::endl;

  /* All players know the public key */
  auto pk = P0.pk(); /* Or P1.pk(), or P2.pk() */

  std::cout << "public key = " << pk << std::endl;

  /* Decrypt */

  /* m is the cleartext, it contains the value 14 (modulo q) */
  BICYCL::CL_HSMqk::ClearText m(CL, BICYCL::Mpz("14"));
  std::cout << "\nmessage = " << m << std::endl;

  /* The cleartext is encrypted using the public key pk. */
  BICYCL::CL_HSMqk::CipherText ct = CL.encrypt(pk, m, randgen);
  std::cout << "ciphertext = " << ct.c1() << std::endl << ct.c2() << std::endl;

  /* To decrypt the ciphertext, 2 players are needed (T=1 so threshold is 2)
   * P0 and P1 each perform partial decryption locally
   */
  std::cout << "\nP0 and P1 perform decryption" << std::endl;
  P0.decrypt_partial(CL, randgen, ct);
  P1.decrypt_partial(CL, randgen, ct);

  /* P0 and P1 broadcast their partial decryptions */
  P1.decrypt_add_partial_dec(0, P0.part_dec()); /* P0 -- C0 (broadcast) --> P1 */
  P0.decrypt_add_partial_dec(1, P1.part_dec()); /* P1 -- C1 (broadcast) --> P0 */

  /* P0 and P1 verify each other's decryptions */
  success = P0.decrypt_verify_batch(CL, randgen);
  success &= P1.decrypt_verify_batch(CL, randgen);

  std::cout << "Decryption verif. is successful: " << success << std::endl;

  /* Finally, P0 and P1 perfom complete decryption seperately */
  BICYCL::CL_HSMqk::ClearText m0, m1;
  P0.decrypt_combine(m0, CL, ct);
  P1.decrypt_combine(m1, CL, ct);

  std::cout << "decrypted cyphertext from P0 = " << m0 << std::endl;
  std::cout << "decrypted cyphertext from P1 = " << m1 << std::endl;

  /* Same output if P0 and P2 decrypt */
  std::cout << "\nP0 and P2 perform decryption" << std::endl;
  P0.decrypt_partial(CL, randgen, ct);
  P2.decrypt_partial(CL, randgen, ct);

  P2.decrypt_add_partial_dec(0, P0.part_dec());
  P0.decrypt_add_partial_dec(2, P2.part_dec());

  success = P0.decrypt_verify_batch(CL, randgen);
  success &= P2.decrypt_verify_batch(CL, randgen);
  std::cout << "Decryption verif. is successful: " << success << std::endl;

  BICYCL::CL_HSMqk::ClearText m2;
  P0.decrypt_combine(m0, CL, ct);
  P2.decrypt_combine(m2, CL, ct);

  std::cout << "decrypted cyphertext from P0 = " << m0 << std::endl;
  std::cout << "decrypted cyphertext from P2 = " << m2 << std::endl;

  /* Same output if P1 and P2 decrypt */
  std::cout << "\nP1 and P2 perform decryption" << std::endl;
  P1.decrypt_partial(CL, randgen, ct);
  P2.decrypt_partial(CL, randgen, ct);

  P2.decrypt_add_partial_dec(1, P1.part_dec());
  P1.decrypt_add_partial_dec(2, P2.part_dec());

  success = P1.decrypt_verify_batch(CL, randgen);
  success &= P2.decrypt_verify_batch(CL, randgen);
  std::cout << "Decryption verif. is successful: " << success << std::endl;

  P1.decrypt_combine(m1, CL, ct);
  P2.decrypt_combine(m2, CL, ct);

  std::cout << "decrypted cyphertext from P1 = " << m1 << std::endl;
  std::cout << "decrypted cyphertext from P2 = " << m2 << std::endl;

  return EXIT_SUCCESS;
}
