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
#include <sstream>
#include <string>

#include "bicycl.hpp"
#include "internals.hpp"

using std::string;

using namespace BICYCL;
using BICYCL::Bench::ms;
using BICYCL::Bench::us;

/* */
void two_party_ECDSA_benchs_CL_DL_Proof ( const TwoPartyECDSA & context,
                                          RandGen & randgen,
                                          const string & pre)
{
  const size_t niter = 100;

  const ECGroup & ec_group{context.ec_group()};
  const CL_HSMqk & CL_HSMq{context.CL_HSMq()};

  std::stringstream desc;
  desc << pre;

  // Generate CL_HSM keys
  CL_HSMqk::SecretKey sk = CL_HSMq.keygen(randgen); // Public key
  CL_HSMqk::PublicKey pk = CL_HSMq.keygen(sk);      // Private key from public

  // Sample a and compute Q
  BN a = ec_group.random_mod_order(randgen);
  ECPoint Q{ec_group};
  ec_group.scal_mul_gen(Q, a);

  // Sample r and encrypt a
  Mpz random = CL_HSMq.encrypt_randomness_bound();
  CL_HSMqk::ClearText aClearText{CL_HSMq, Mpz(a)};
  CL_HSMqk::CipherText c{CL_HSMq, pk, aClearText, random};

  /***** Compute CL DL Proof ***********************************************************/
  auto compute_proof = [&context, &a, &Q, &pk, &c, &random, &randgen] () {
    // Compute proof of knowledge of a
    CLDLZKProof proof{context.H(),
                      context.ec_group(),
                      a,
                      Q,
                      context.CL_HSMq(),
                      pk,
                      c,
                      random,
                      randgen};

  };
  Bench::one_function<ms, ms>(compute_proof, niter, "Compute proof", desc.str());

  /***** Verify CL DL Proof ***********************************************************/
  CLDLZKProof proof{context.H(),
                    context.ec_group(),
                    a,
                    Q,
                    context.CL_HSMq(),
                    pk,
                    c,
                    random,
                    randgen};

  auto verify_proof = [&context, &proof, &Q, &pk, &c] () {
    // Compute proof of knowledge of a
    (void) proof.verify(
        context.H(), context.ec_group(), Q, context.CL_HSMq(), pk, c);

  };
  Bench::one_function<ms, ms>(verify_proof, niter, "Verify proof", desc.str());
}

/* */
int main (int argc, char * argv[])
{
  RandGen randgen;
  randseed_from_argv(randgen, argc, argv);

  Bench::print_thread_info();

  std::cout << "security level  |    operation    |   time   "
            << "|  time per op.  | std. dev." << std::endl;

  for (const SecLevel seclevel : SecLevel::All())
  {
    std::stringstream desc;
    desc << "  " << seclevel << " bits     ";

    /* With a random q twice as big as the security level */
    TwoPartyECDSA C(seclevel, randgen);

    two_party_ECDSA_benchs_CL_DL_Proof(C, randgen, desc.str());

    std::cout << std::endl;
  }

  return EXIT_SUCCESS;
}
