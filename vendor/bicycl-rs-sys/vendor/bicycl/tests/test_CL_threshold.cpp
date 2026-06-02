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

#include <assert.h>
#include <sstream>
#include <string>

#include "bicycl.hpp"
#include "internals.hpp"

using std::string;

using namespace BICYCL;

/* */
class LogicalError : public std::runtime_error
{
  public:
    using runtime_error::runtime_error;
};

/**
 * @brief Testing class to create CL_Batch_Dlog_AoK proofs that are invalid
 */
class CL_Batch_Dlog_AoK_Wrong : public CL_Batch_Dlog_AoK
{
  public:
    CL_Batch_Dlog_AoK_Wrong(const Mpz & u, const QFI & R) : CL_Batch_Dlog_AoK(u, R) {};
};

/******************************************************************************/
CL_Batch_Dlog_AoK get_random_proof (const CL_HSMqk & CL,
                                    const SecLevel & seclevel,
                                    RandGen & randgen)
{
  QFI R;
  CL.power_of_h(R, randgen.random_mpz_2exp(seclevel.nbits()));
  return CL_Batch_Dlog_AoK_Wrong(randgen.random_mpz_2exp(seclevel.nbits()), R);
}

/******************************************************************************/
Mpz get_random_share (const SecLevel & seclevel, RandGen & randgen)
{
  return randgen.random_mpz_2exp(seclevel.nbits());
}


struct TestParams
{
  TestParams(SecLevel comp, unsigned int n, unsigned int t)
  : comp_seclevel(comp), soundness(comp.nbits()), n(n), t(t) {}

  TestParams(SecLevel comp, unsigned int n, unsigned int t, bool dishonest)
  : comp_seclevel(comp), soundness(comp.nbits()), n(n), t(t), with_dishonest_players(dishonest) {}

  TestParams(SecLevel comp, size_t soundness, unsigned int n, unsigned int t)
  : comp_seclevel(comp), soundness(soundness), n(n), t(t) {}

  SecLevel comp_seclevel;
  size_t soundness;
  unsigned int n;
  unsigned int t;
  bool with_dishonest_players = false;
  size_t niter = 1;
};

/******************************************************************************/
bool test_CL_threshold (const string & pre,
                        const TestParams & params,
                        RandGen & randgen,
                        const CL_HSMqk & CL)
{
  SecLevel seclevel = params.comp_seclevel;
  unsigned int n = params.n;
  unsigned int t = params.t;
  bool with_dishonest_players= params.with_dishonest_players;
  size_t niter = params.niter;

  std::stringstream print;
  print << pre << std::setw(2) << t + 1
        << " out of " << std::setw(2) << n;
  if(with_dishonest_players)
    print << " w/ some dishonest players";

  bool success = true;
  for (size_t iter = 0; (iter < niter) && (success == true); iter++)
  {
    try
    {
      std::vector<CL_Threshold_Static> P;
      for (unsigned int i = 0; i < n; i++)
      {
        P.emplace_back(CL, n, t, i, params.soundness);
      }

      /*************************** KEYGEN DEALING *****************************/
      // Each P generates its shares
      for (auto & player : P)
      {
        player.keygen_dealing(CL, randgen);
      }

      // OPTIONAL: Simulate three dishonest players
      // First dishonest player provides an ill-formed share
      // Second dishonest player provides an ill-formed proof
      // Third dishonest player does an honest keygen, but provides an ill-formed partial decryption
      // Ensure P0 is honest
      unsigned int player_with_bad_proof = 0u, player_with_bad_share = 0u,
                   player_with_bad_decryption = 0u;
      if (with_dishonest_players)
      {
        do
        {
          player_with_bad_share = randgen.random_ui(n);
        }
        while (player_with_bad_share == 0u);
        do
        {
          player_with_bad_proof = randgen.random_ui(n);
        }
        while ((player_with_bad_proof == 0u)
               || (player_with_bad_proof == player_with_bad_share));
        do
        {
          player_with_bad_decryption = randgen.random_ui(n);
        }
        while ((player_with_bad_decryption == 0u)
               || (player_with_bad_decryption == player_with_bad_share)
               || (player_with_bad_decryption == player_with_bad_proof));
      }

      // Simulate communication: each Pi receives from Pj yji, Cj, and a proof
      for (unsigned int i = 0; i < n; i++)
      {
        for (unsigned int j = 0; j < n; j++)
        {
          // From every other player
          if (j == i) continue;

          // Get y_ji (P2P)
          if ((with_dishonest_players) && (j == player_with_bad_share))
            P[i].keygen_add_share(j, randgen.random_mpz_2exp(seclevel.nbits()));
          else
            P[i].keygen_add_share(j, P[j].y_k(i));

          // Get C_j (broadcast)
          P[i].keygen_add_commitments(j, P[j].C());

          // Get Pj's batch proof (broadcast)
          if ((with_dishonest_players) && (j == player_with_bad_proof))
            P[i].keygen_add_proof(
                j, get_random_proof(CL, seclevel, randgen));
          else
            P[i].keygen_add_proof(j, P[j].batch_proof());
        }
      }

      /**************************** KEYGEN CHECK ******************************/
      // Each player checks other's shares
      for (unsigned int i = 0; i < n; i++)
      {
        bool check_pass = P[i].keygen_check_verify_all_players(CL);
        if (with_dishonest_players && check_pass)
        {
          // Some players are dishonest, so it is expected that check fails
          throw LogicalError("Check verify passed when it should have failed (keygen)");

        }
        if (!with_dishonest_players && !check_pass)
        {
          throw LogicalError("Check verify failed when it should have passed (keygen)");
        }
      }

      if (with_dishonest_players)
      {
        // Ensure dishonest players were caught, check that :
        // - The player with dishonest proof, and only this player, was removed from Q
        // - The player with dishonest share, and only this player, was added to Complaints
        auto Q = P[0].QualifiedPlayerSet();
        auto Complaints = P[0].ComplaintsSet();
        if ((Q.size() != n-1u) ||
            (Q.find(player_with_bad_proof) != Q.end()) ||
            (Complaints.size() != 1u) ||
            (Complaints.find(player_with_bad_share) == Complaints.end()))
        {
          throw LogicalError("Dishonest players could not be identified (keygen)");
        }

        // Disqualify the player with bad share, "second chance" not tested
        for (unsigned int i = 0; i < n; i++)
        {
          if (i == player_with_bad_share) continue;
          P[i].keygen_disqualify_player(player_with_bad_share);
        }
      }

      /*************************** KEYGEN EXTRACT *****************************/
      // Each P computes its share of sk, and pk
      for (auto & player : P) player.keygen_extract(CL);

      // Check all (honest) players have the same public key
      auto & pk = P[0].pk();
      for (unsigned int i = 1; i < n; ++i)
      {
        if (with_dishonest_players
            and ((i == player_with_bad_proof) or (i == player_with_bad_share)))
          continue;

        if (!(pk.elt() == P[i].pk().elt()))
          throw LogicalError("Public Keys do not match for all players");
      }

      /*************************** DECRYPT PARTIAL ****************************/
      // First encrypt random message
      CL_Threshold_Static::ClearText message{CL, randgen};
      CL_Threshold_Static::CipherText ct{
          CL,
          P.begin()->pk(),
          message,
          randgen.random_mpz(CL.encrypt_randomness_bound())};

      // Randomly select t+1 decryption players from Q (t+2 if one player is dishonest)
      CL_Threshold_Static::ParticipantsSet DecryptionPlayers(P[0].QualifiedPlayerSet());
      while (DecryptionPlayers.size() > t + (with_dishonest_players ? 2 : 1))
      {
        auto it  = DecryptionPlayers.begin();
        unsigned int offset = randgen.random_ui(DecryptionPlayers.size());
        std::advance(it, offset);
        // Ensure the dishonest player (if there is one) takes part in decryption
        if (!with_dishonest_players || (*it != player_with_bad_decryption))
          DecryptionPlayers.erase(it);
      }

      // Then partially decrypt
      for (unsigned int i : DecryptionPlayers)
      {
        if (with_dishonest_players && (i == player_with_bad_decryption))
        {
          // Dishonest / erroneous partial decrypt.
          // Simulate this behaviour by using a different ciphertext for this player.
          CL_Threshold_Static::CipherText ct_bad{
              CL,
              P[i].pk(),
              CL_Threshold_Static::ClearText(CL, randgen),
              randgen.random_mpz(CL.encrypt_randomness_bound())};
          P[i].decrypt_partial(CL, randgen, ct_bad);
        }
        else
        {
          // Honest partial decrypt
          P[i].decrypt_partial(CL, randgen, ct);
        }
      }

      // Then players broadcast their w
      // Simulate communication:
      for (unsigned int i : DecryptionPlayers)
      {
        for (unsigned int j : DecryptionPlayers)
        {
          if (j == i) continue;    // From every other player
          P[i].decrypt_add_partial_dec(
              j, P[j].part_dec()); // Pi gets w_j, proof_j (broadcast)
        }
      }

      /*************************** DECRYPT VERIFY *****************************/
      // Honest players check decryption proofs of the other players
      // First, a batch verification is performed to check all players in one go
      // If it fails, individual verification is done over all players to
      // identify the dishonest one
      for (unsigned int i : DecryptionPlayers)
      {
        if (with_dishonest_players && (i == player_with_bad_decryption))
          continue;

        bool batch_verif_success = P[i].decrypt_verify_batch(CL, randgen);
        if (with_dishonest_players)
        {
          // NOTE:
          // Batch_verif checks only the t+1 first decryptions.
          // The way the part decs are added to each player's map results in
          // each player's own decryption being last in the map.
          // So when t+2 decryptions are present, each player will effectively
          // perform batch verif on the t+1 other players, excluding themselves.
          // Consequently, the honest players will always include the one dishonest
          // player in their batch verification, so it should fail

          // One player is dishonest, check that batch verif failed
          if (batch_verif_success)
          {
            throw LogicalError("Batch verify passed when it should have failed (decrypt)");
          }
          // Check that the dishonest player can be identified through individual
          // proof verification
          bool identification_success = true;
          for (unsigned int j : DecryptionPlayers)
          {
            if (i == j) continue;
            bool j_verif_success = P[i].decrypt_verify_player_decryption(CL, j);
            // Verif should fail only for dishonest player
            if (j == player_with_bad_decryption)
              identification_success &= !j_verif_success;
            else
              identification_success &= j_verif_success;
          }
          if (!identification_success)
          {
            throw LogicalError("Dishonest player could not be identified (decrypt)");
          }
        }
        else if (!batch_verif_success)
        {
          // All players are honest, batch verif should pass
          throw LogicalError("Batch verify failed when it should have passed (decrypt)");
        }
      }

      if (with_dishonest_players)
        DecryptionPlayers.erase(player_with_bad_decryption);

      /*************************** DECRYPT COMBINE ****************************/
      // Finally all players perform complete decryption separately
      bool decrypt_combine_success = true;
      for (unsigned int i : DecryptionPlayers)
      {
        CL_Threshold_Static::ClearText recovered_msg;
        P[i].decrypt_combine(recovered_msg, CL, ct);
        if (message != recovered_msg) decrypt_combine_success = false;
      }
      if (!decrypt_combine_success)
      {
        success = false;
        std::cout << "Decrypt Combine Failed" << std::endl;
      }
    }
    catch (std::invalid_argument & e)
    {
      std::cerr << "Invlid Argument, " << e.what() << std::endl;
      success = false;
    }
    catch (LogicalError &e)
    {
      std::cerr << "LogicalError, " << e.what() << std::endl;
      success = false;
    }
    catch (CL_Threshold_Static::ProtocolLogicError & e)
    {
      std::cerr << "Protocol Logic Error, " << e.what() << std::endl;
      success = false;
    }
    catch (CL_Threshold_Static::ProtocolAbortError & e)
    {
      std::cerr << "Protocol Abort Error, " << e.what() << std::endl;
      success = false;
    }
    catch (std::system_error & e)
    {
      std::cerr << "System Error (errcode " << e.code() << ") " << e.what()
                << std::endl;
      success = false;
    }
  }

  Test::result_line(print.str(), success);
  return success;
}

/******************************************************************************/
int main (int argc, char * argv[])
{
  bool success = true;

  // Init RNG
  RandGen randgen;
  randseed_from_argv(randgen, argc, argv);

  /* Init CL framework, with a random q twice as big as the security level,
   * and statistical security equal to security level.
   */
  CL_HSMqk CL{SecLevel::_112.nbits() * 2, 1u, SecLevel::_112, randgen};


  /*
   * Test with various "t out of n" values
   */
  std::cout << "Threshold CL, security " << SecLevel::_112
            << " bits, threshold test:" << std::endl;

  struct nt_param {unsigned int n,t;};
  nt_param nt_values[] = {{2, 1},
                          {3, 1},
                          {5, 2},
                          {5, 4},
                          {7, 2},
                          {7, 4},
                          {7, 6},
                          {10, 2},
                          {10, 4},
                          {10, 9},
                          {20, 9}};
  for (auto param : nt_values) {
    success &= test_CL_threshold(
        "", {SecLevel::_112, param.n, param.t}, randgen, CL);
  }

  /*
   * Test with dishonest players
   */
  std::cout << "\nThreshold CL, security " << SecLevel::_112
            << " bits, dishonest test:" << std::endl;

  nt_param nt_values_dishonest[] = {{5, 1},
                                    {7, 1},
                                    {7, 3},
                                    {10, 1},
                                    {10, 2},
                                    {10, 4},
                                    {10, 6}};
  for (auto param : nt_values_dishonest) {
    success &= test_CL_threshold(
        "", {SecLevel::_112, param.n, param.t, true}, randgen, CL);
  }

  /*
   * Test with security parameters from 112 to 192
   */
  std::cout << "\nThreshold CL, security parameters test (computational, statistical, soundness):"
            << std::endl;

  SecLevel comp_sec_values[] = {SecLevel::_112, SecLevel::_128, SecLevel::_192};
  size_t stat_security_values[] = {40, 64, 112};
  size_t soundness_values[] = {112, 128, 192};
  for (SecLevel comp_security : comp_sec_values) {
    for (size_t stat_security : stat_security_values) {
      if (stat_security > comp_security.nbits()) continue;
      CL = {comp_security.nbits(),
            1u,
            comp_security,
            randgen,
            CL_Params{stat_security+2u}};
      for (size_t soundness : soundness_values) {
          if (soundness > comp_security.nbits()) continue;
          std::stringstream pre;
          pre << '(' << std::setw(3) << comp_security << ", "
                     << std::setw(3) << stat_security << ", "
                     << std::setw(3) << soundness << "): ";
          TestParams params{comp_security, soundness, 3, 1};
          success &= test_CL_threshold(pre.str(), params, randgen, CL);
      }
    }
  }
  // Test with security parameters (256, 112, 256)
  CL = {SecLevel::_256.nbits(),
        1u,
        SecLevel::_256,
        randgen,
        CL_Params{112ul}};
  success &= test_CL_threshold(
      "(256, 112, 256): ", {SecLevel::_256, 256ul, 3, 1}, randgen, CL);

  return success ? EXIT_SUCCESS : EXIT_FAILURE;
}
