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

#include <assert.h>
#include <sstream>
#include <string>

#include "bicycl.hpp"
#include "internals.hpp"

using std::string;
using namespace BICYCL;

class LogicalError : public std::runtime_error
{
  public:
    using runtime_error::runtime_error;
};

/**
 * @brief Test class to access TwoPartyECDSA's protected methods
 */
class TestTwoPartyECDSA : public TwoPartyECDSA
{
  public:
    using TwoPartyECDSA::TwoPartyECDSA;
    using TwoPartyECDSA::commit;
    using TwoPartyECDSA::open;
};

/*******************************************************************************
 *  Test TwoPartyECDSA proof-commitment scheme
 *
 ******************************************************************************/
bool test_commitment_proof (const TestTwoPartyECDSA & context,
                            size_t niter,
                            const string & pre,
                            RandGen & randgen)
{
  bool ret = true;

  TestTwoPartyECDSA::Commitment c;
  TestTwoPartyECDSA::CommitmentSecret r;

  for (size_t i = 0; i < niter; i++)
  {
    // k in Z/qZ, Q = [k] P
    BN k(context.ec_group().random_mod_order(randgen));
    ECPoint Q(context.ec_group(), k);

    // Compute proof of knowledge of k
    ECNIZKProof commit_proof{context.ec_group(), context.H(), randgen, k, Q};

    // Compute commitment value
    tie(c, r) = context.commit(randgen, commit_proof);

    // Open commitment and check it
    ret &= context.open(c, commit_proof, r);

    // Verify proof
    ret &= commit_proof.verify(context.ec_group(), context.H(), Q);
  }

  string line(pre + " commitment-proof");
  Test::result_line(line, ret);
  return ret;
}

/*******************************************************************************
 *  Test TwoPartyECDSA CL Discrete Log proof scheme
 ******************************************************************************/
bool test_CL_DL_proof (const TestTwoPartyECDSA & context,
                       size_t niter,
                       RandGen & randgen,
                       const string & pre)
{
  bool ret = true;

  const ECGroup & ec_group{context.ec_group()};
  const CL_HSMqk & CL_HSMq{context.CL_HSMq()};

  ECPoint Q{ec_group};

  for (size_t i = 0; i < niter; i++)
  {
    // Generate CL_HSM keys
    CL_HSMqk::SecretKey sk = CL_HSMq.keygen(randgen); // Public key
    CL_HSMqk::PublicKey pk = CL_HSMq.keygen(sk);      // Private key from public

    // Sample a and compute Q
    BN a = ec_group.random_mod_order(randgen);
    ec_group.scal_mul_gen(Q, a);

    // Sample r and encrypt a
    Mpz random = CL_HSMq.encrypt_randomness_bound();
    CL_HSMqk::ClearText aClearText{CL_HSMq, Mpz(a)};
    CL_HSMqk::CipherText c{CL_HSMq, pk, aClearText, random};

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

    // Verify proof
    ret &= proof.verify(
        context.H(), context.ec_group(), Q, context.CL_HSMq(), pk, c);
  }

  string line(pre + " CL-DL proof");
  Test::result_line(line, ret);
  return ret;
}

/*******************************************************************************
 *  Test TwoPartyECDSA signing protocol
 ******************************************************************************/
bool test_sign (const TestTwoPartyECDSA & context,
                size_t niter,
                RandGen & randgen,
                const string & pre)
{
  bool ret = true;

  const ECGroup & ec_group = context.ec_group();

  for (size_t iter = 0; iter < niter; iter++)
  {
    try
    {
      // ------ Init Players ------ //
      TwoPartyECDSA::Player1 P1(context);
      TwoPartyECDSA::Player2 P2(context);

      // ------ Simulate exchange ------ //

      // ---- Keygen
      P1.KeygenPart1(context, randgen);

      // P1 --- com-proof(Q1) ---> P2
      P2.KeygenPart2(context, randgen, P1.commit());

      // P1 < --- (Q2, zk-proof(Q2)) --- P2
      P1.KeygenPart3(context,
                     randgen,
                     P2.Q2(),
                     P2.zk_proof());

      // P1 --- (Q1, pk, Ckey, decomp-proof(Q1)) ---> P2
      P2.KeygenPart4(context,
                     P1.Q1(),
                     P1.Ckey(),
                     P1.pkcl(),
                     P1.commit_secret(),
                     P1.zk_com_proof(),
                     P1.proof_ckey());

      // Check Q is the same value for P1 and P2
      if (false == ec_group.ec_point_eq(P1.public_key(), P2.public_key()))
      {
        throw LogicalError("P1 and P2 have a different Q");
      }

      /* Generate random 128-bit sid */
      Mpz sid{randgen.random_mpz_2exp(128)};

      /* Message */
      std::vector<unsigned char> msg = random_message(randgen);
      BICYCL::HashAlgo::Digest hashed{context.hash(msg)};

      // ---- Sign
      P1.SignPart1(context, randgen, sid);

      // P1 --- com-proof(R1) ---> P2
      P2.SignPart2(context, randgen, P1.commit(), sid);

      // P1 < --- (R2, zk-proof(R2)) --- P2
      P1.SignPart3(context, P2.R2(), P2.zk_proof(), sid);

      // P1 --- (R1, decomp-proof(R1)) --- > P2
      P2.SignPart4(context,
                   randgen,
                   hashed,
                   P1.R1(),
                   P1.commit_secret(),
                   P1.zk_com_proof(),
                   sid);

      // P1 < --- C3 --- P2
      ECSignature signature = P1.SignPart5(context, hashed, P2.C3());

      // ------ Verify signature ------ //
      if ( not context.verify(signature, P1.public_key(), hashed))
          throw LogicalError("signature could not be veirifed");
    }
    catch (LogicalError & e)
    {
      std::cerr << iter << ": LogicalError, " << e.what() << std::endl;
      ret = false;
    }
    catch (TwoPartyECDSA::ProtocolAbortError & e)
    {
      std::cerr << iter << ": ProtocolAbortError, " << e.what() << std::endl;
      ret = false;
    }
  }

  Test::result_line(pre, ret);
  return ret;
}

/*******************************************************************************
 *  Test TwoPartyECDSA protocol w/ offline pre-signing step
 ******************************************************************************/
bool test_offline_presign (const TestTwoPartyECDSA & context,
                size_t niter,
                RandGen & randgen,
                const string & pre)
{
  using P1PresignData = TwoPartyECDSA::Player1::PresignData;
  using P2PresignData = TwoPartyECDSA::Player2::PresignData;


  bool ret = true;
  for (size_t iter = 0; iter < niter; iter++)
  {
    try
    {
      // ------ Init Players ------ //
      TwoPartyECDSA::Player1 P1(context);
      TwoPartyECDSA::Player2 P2(context);

      // ------ Simulate exchange ------ //

      // ---- Keygen
      P1.KeygenPart1(context, randgen);

      // P1 --- com-proof(Q1) ---> P2
      P2.KeygenPart2(context, randgen, P1.commit());

      // P1 < --- (Q2, zk-proof(Q2)) --- P2
      P1.KeygenPart3(context,
                     randgen,
                     P2.Q2(),
                     P2.zk_proof());

      // P1 --- (Q1, pk, Ckey, decomp-proof(Q1)) ---> P2
      P2.KeygenPart4(context,
                     P1.Q1(),
                     P1.Ckey(),
                     P1.pkcl(),
                     P1.commit_secret(),
                     P1.zk_com_proof(),
                     P1.proof_ckey());

      // Generate random 128-bit sid
      Mpz sid{randgen.random_mpz_2exp(128)};

      // ---- Sign 1, 2, and 3 offline
      unsigned int nb_presign = 1 + randgen.random_ui(9u);
      std::vector<P1PresignData> p1_presign; p1_presign.reserve(nb_presign);
      std::vector<P2PresignData> p2_presign; p2_presign.reserve(nb_presign);
      for (unsigned int i = 0U; i < nb_presign; ++i)
      {
        P1.SignPart1(context, randgen, sid);
        // P1 --- com-proof(R1) ---> P2
        P2.SignPart2(context, randgen, P1.commit(), sid);

        // P1 < --- (R2, zk-proof(R2)) --- P2
        p1_presign.push_back(P1.SignPart3(context, P2.R2(), P2.zk_proof(), sid));

        p2_presign.push_back(P2.SignPart4_offline(
            context, randgen, P1.R1(), P1.commit_secret(), P1.zk_com_proof(), sid));
      }

      // ---- Receive message to sign
      std::vector<unsigned char> msg = random_message(randgen);
      HashAlgo::Digest hashed{context.hash(msg)};

      // ---- Sign 4 and 5 online
      for (unsigned int i = 0U; i < nb_presign; ++i)
      {
        P2.SignPart4_online(context, hashed, p2_presign.at(i));

        ECSignature sig = P1.SignPart5(context, hashed, P2.C3(), p1_presign.at(i));

        // ------ Verify signature ------ //
        if ( not context.verify(sig, P1.public_key(), hashed))
          throw LogicalError("signature could not be veirifed");
      }
    }
    catch (LogicalError & e)
    {
      std::cerr << iter << ": LogicalError, " << e.what() << std::endl;
      ret = false;
    }
    catch (TwoPartyECDSA::ProtocolAbortError & e)
    {
      std::cerr << iter << ": ProtocolAbortError, " << e.what() << std::endl;
      ret = false;
    }
  }

  string line(pre + " Offline Presigning");
  Test::result_line(line, ret);
  return ret;
}

/******************************************************************************/
bool check (SecLevel seclevel, RandGen & randgen, size_t niter)
{
  bool success = true;

  std::stringstream desc;
  desc << "security " << seclevel << " bits Two-Party ECDSA";

  // Init context
  TestTwoPartyECDSA context(seclevel, randgen);

  success &= test_commitment_proof(context, niter, desc.str(), randgen);
  success &= test_CL_DL_proof(context, niter, randgen, desc.str());
  success &= test_sign(context, niter, randgen, desc.str());
  success &= test_offline_presign(context, niter, randgen, desc.str());

  return success;
}

/******************************************************************************/

int main (int argc, char * argv[])
{
  bool success = true;

  // Init RNG
  RandGen randgen;
  randseed_from_argv(randgen, argc, argv);

  // Test with security levels from 112 to 256
  success &= check(SecLevel::_112, randgen, 10);
  success &= check(SecLevel::_128, randgen, 5);
  success &= check(SecLevel::_192, randgen, 3);
  success &= check(SecLevel::_256, randgen, 1);

  return success ? EXIT_SUCCESS : EXIT_FAILURE;
}
