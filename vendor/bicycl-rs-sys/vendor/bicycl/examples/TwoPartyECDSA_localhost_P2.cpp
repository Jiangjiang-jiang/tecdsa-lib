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

#include "bicycl.hpp"
#include "network_helper.hpp"

#define PORTIN 8080
#define PORTOUT 8080

/* Aliases */
using namespace BICYCL;
using BICYCL::ECPoint;

/* Global vars */
int udp_socket_fd;

/* Main */
int main ()
{
  std::cout << "Two Party ECDSA P2\n" << std::endl;

  //*********************** UDP COM init *************************//
  struct sockaddr_in P1_addr, P2_addr;

  // Creating socket file descriptor
  if ((udp_socket_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
  {
    perror("socket creation failed");
    exit(EXIT_FAILURE);
  }

  // Filling P1 information
  P1_addr.sin_family = AF_INET;
  P1_addr.sin_addr.s_addr = 0x0100007f;
  P1_addr.sin_port = htons(PORTOUT);

  // Filling P2 information
  P2_addr.sin_family = AF_INET;
  P2_addr.sin_addr.s_addr = 0x0200007f;
  P2_addr.sin_port = htons(PORTIN);

  // Bind the socket with the server address
  if (bind(udp_socket_fd, (const struct sockaddr *)&P2_addr, sizeof(P2_addr))
      < 0)
  {
    perror("bind failed");
    exit(EXIT_FAILURE);
  }
  std::cout << "UDP socket open\n" << std::endl;


  //*********************** 2P protocol init *************************//

  std::cout << "Init: Waiting for seed... " << std::flush;
  Mpz seed = receive_mpz(P1_addr);
  std::cout << " OK" << std::endl;
  std::cout << "Seed received: " << seed << std::endl;

  /* A random generator. */
  RandGen randgen_public, randgen_private;
  randgen_public.set_seed(seed);

  /* The desired security level. */
  SecLevel seclevel(128);

  /* Hash function with the desired soundness */
  HashAlgo H(seclevel);

  /* Two Party ECDSA:
   * Public parameters of CL and EC are generated according to the given
   * security level.
   */
  std::cout << "Init: init CL..." << std::flush;
  TwoPartyECDSA context(seclevel, randgen_public);
  std::cout << " OK\n" << std::endl;

  TwoPartyECDSA::Player2 P2(context);

  //*********************** KEYGEN *************************//
  /* Keygen Round 1 */
  /* P1 --- com-proof(Q1) ---> P2 */
  std::cout << "Keygen Round 1: P1 --- com-proof(Q1) ---> P2" << std::endl;
  std::cout << "Keygen Round 1: waiting for P1..." << std::flush;
  TwoPartyECDSA::Commitment P1_commit = receive_bytes(P1_addr);
  std::cout << " OK" << std::endl;

  /* Keygen Round 2 */
  std::cout << "Keygen Round 2: computing..." << std::flush;
  P2.KeygenPart2(context, randgen_private ,P1_commit);
  std::cout << "  done" << std::endl;

  /* P1 < --- (Q2, zk-proof(Q2)) --- P2 */
  std::cout << "Keygen Round 2: P1 < --- (Q2, zk-proof(Q2)) --- P2" << std::endl;
  std::cout << "Keygen Round 2: sending..." << std::flush;
  send(P1_addr, context.ec_group(), P2.Q2());
  send(P1_addr, context.ec_group(), P2.zk_proof());
  std::cout << " OK" << std::endl;

  /* Keygen round 3 */
  /* P1 --- (Q1, pk, Ckey, decomp-proof(Q1)) ---> P2 */
  std::cout << "Keygen Round 3: P1 --- (Q1, pk, Ckey, decomp-proof(Q1)) ---> P2" << std::endl;
  std::cout << "Keygen Round 3: waiting for P1..." << std::flush;
  ECPoint Q1 = receive_ECPoint(P1_addr, context.ec_group());
  QFI f = receive_qfi(P1_addr, true, context.CL_HSMq().Delta());
  TwoPartyECDSA::CLCipherText Ckey = receive_CLcipher(P1_addr, true, context.CL_HSMq().Delta());
  TwoPartyECDSA::CommitmentSecret com_sec = receive_bytes(P1_addr);
  ECNIZKProof zk_com_proof = receive_ECNIZKproof(P1_addr, context.ec_group());
  CLDLZKProof proof_ckey = receive_CLDLproof(P1_addr, context.ec_group());
  std::cout << " OK" << std::endl;

  /* Keygen round 4 */
  std::cout << "Keygen Round 4: computing..." << std::flush;
  TwoPartyECDSA::CLPublicKey pkcl{context.CL_HSMq(), f};
  P2.KeygenPart4(context, Q1, Ckey, pkcl, com_sec, zk_com_proof, proof_ckey);
  std::cout << " OK" << std::endl;

  std::cout << "\nKeygen done successfully for P2" << std::endl;

  //*********************** SIGN *************************//
  /* The sid */
  BICYCL::Mpz sid2{randgen_private.random_mpz_2exp(128)};
  Mpz sid1{receive_mpz(P1_addr)};
  send(P1_addr, sid2);
  Mpz sid{H(sid1, sid2)};

  /* Receive message generated by P1 */
  std::vector<uint8_t> m = receive_bytes(P1_addr);
  HashAlgo::Digest hashed{context.hash(m)};

  std::cout << "\nmessage = '";
  for (char c : m)
    std::cout << c;
  std::cout << "'\n" << std::endl;

  /* P1 starts: Sign Round 1  */
  /* P1 --- com-proof(R1) ---> P2 */
  std::cout << "Sign Round 1: P1 --- com-proof(R1) ---> P2" << std::endl;
  std::cout << "Sign Round 1: waiting for P1..." << std::flush;
  P1_commit = receive_bytes(P1_addr);
  std::cout << " OK" << std::endl;

  /* Sign Round 2 */
  std::cout << "Sign Round 2: computing..." << std::flush;
  P2.SignPart2(context, randgen_private, P1_commit, sid);
  std::cout << " OK" << std::endl;
  /* P1 < --- (R2, zk-proof(R2)) --- P2 */
  std::cout << "Sign Round 2: P1 < --- (R2, zk-proof(R2)) --- P2" << std::endl;
  std::cout << "Sign Round 2: sending..." << std::flush;
  send(P1_addr, context.ec_group(), P2.R2());
  send(P1_addr, context.ec_group(), P2.zk_proof());
  std::cout << " OK" << std::endl;

  /* Sign Round 3 */
  /* P1 --- (R1, decomp-proof(R1)) --- > P2 */
  std::cout << "Sign Round 3: P1 --- (R1, decomp-proof(R1)) ---> P2" << std::endl;
  std::cout << "Sign Round 3: waiting for P1..." << std::flush;
  Q1 = receive_ECPoint(P1_addr, context.ec_group());
  com_sec = receive_bytes(P1_addr);
  zk_com_proof = receive_ECNIZKproof(P1_addr, context.ec_group());
  std::cout << " OK" << std::endl;

  /* Sign round 4 */
  std::cout << "Sign Round 4: computing..." << std::flush;
  P2.SignPart4(context, randgen_private, hashed, Q1, com_sec, zk_com_proof, sid);
  std::cout << " OK" << std::endl;
  /* P1 < --- C3 --- P2 */
  std::cout << "Sign Round 4: P1 < --- C3 --- P2" << std::endl;
  std::cout << "Sign Round 4: sending..." << std::flush;
  send(P1_addr, P2.C3(), true);
  std::cout << " OK" << std::endl;

  std::cout << "\nSignature done successfully for P2" << std::endl;

  close(udp_socket_fd);
  std::cout << "\nUDP socket closed\n" << std::endl;
  return 0;
}