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
#include <sstream>
#include <string>

#include "bicycl.hpp"
#include "internals.hpp"

using std::string;

using namespace BICYCL;
using BICYCL::Bench::ms;
using BICYCL::Bench::s;
using BICYCL::Bench::us;

class CL_Threshold_Static_Bench : public CL_Threshold_Static
{
  public:
  using CL_Threshold_Static::CL_Threshold_Static;
  using CL_Threshold_Static::keygen_extract_for_benchs;
};

struct BenchParam
{
    /* bench with t = ceil(n / 2) - 1 */
    BenchParam(SecLevel seclevel,
               size_t stat_dist,
               size_t soundness_bits,
               unsigned int n,
               size_t iterations)
      : seclevel{seclevel},
        stat_dist(stat_dist),
        soundness_bits{soundness_bits},
        n{n},
        t{(n + 1) / 2 - 1},
        iterations{iterations} {};

    SecLevel seclevel;
    size_t stat_dist;
    size_t soundness_bits;
    unsigned int n;
    unsigned int t;
    size_t iterations;
};

////////////////////////////////////////////////////////////////////////////////
//****************************************************************************//
////////////////////////////////////////////////////////////////////////////////

void CL_Threshold_bench_protocol_per_part (BenchParam params,
                                           RandGen & randgen,
                                           const string & pre)
{
  unsigned int n = params.n;
  unsigned int t = params.t;
  unsigned int niter = params.iterations;

  std::stringstream desc;
  desc << pre;

  /* Bench init */
  auto init = [&randgen, n, t, &params] {
    CL_HSMqk CL{params.seclevel.nbits() * 2,
                1u,
                params.seclevel,
                randgen,
                CL_Params{params.stat_dist + 2u}};
    CL_Threshold_Static_Bench Player{CL, n, t, n - 1, params.soundness_bits/8u};
  };
  Bench::one_function<ms, ms>(init, niter, "Init", desc.str());

  /* Init CL framework
   * With a random q twice as big as the security level,
   * and statistical security equal to security level.
   */
  CL_HSMqk CL{params.seclevel.nbits() * 2,
              1u,
              params.seclevel,
              randgen,
              CL_Params{params.seclevel.nbits()}};

  /* Init players */
  std::vector<CL_Threshold_Static_Bench> P;
  for (unsigned int i = 0; i < n; i++)
  {
    P.emplace_back(CL, n, t, i, params.soundness_bits / 8u);
  }

  // Computing time is measured for a single player

  /**************************** KEYGEN DEALING ******************************/
  auto keygen_deal = [&P, &CL, &randgen] {
    // Player 0 generate it's shares
    P[0].keygen_dealing(CL, randgen);
  };
  Bench::one_function<ms, ms>(keygen_deal, niter, "Keygen Deal", desc.str());

  // The other Players generate their shares
  for (unsigned int i = 1; i < n; i++)
  {
    P[i].keygen_dealing(CL, randgen);
  }

  /************************* KEYGEN COMMUNICATION ***************************/
  /* Simulate broadcast communication: each Pi broadcasts its C and proof */
  size_t C_comm_size_bits = 0UL, batch_proof_comm_size_bits = 0UL;
  for (unsigned int i = 0; i < n; i++)
  {
    const std::vector<QFI> & Ci = P[i].C();
    const CL_Batch_Dlog_AoK & proof_i = P[i].batch_proof();

    /* Each other player gets Ci from the broadcast */
    /*
     * In real execution each other player should get Ci from the broadcast
     * Here to speed up the bench, only P0 to Pt+1 get Ci, needed to execute
     * keygen_extract, in turn needed to have t+1 players to bench decrypt phase
     */
    for (unsigned int j = 0; j < t+1u; j++)
    {
      if (j == i) continue;
      P[j].keygen_add_commitments(i, Ci);
    }
    /*
     * In real execution each other player should get proof_i from the broadcast
     * Here to speed up the bench, only P0 gets proof_i, needed to measure
     * keygen check afterwards
     */
    if (i != 0u)
      P[0].keygen_add_proof(i, proof_i);

    /* Compute broadcast size */
    for (unsigned int u = 0u; u < t+1u; ++u){
      C_comm_size_bits += Ci[u].compressed_repr().nbits();
    }
    batch_proof_comm_size_bits += P[i].batch_proof().u().nbits();
    batch_proof_comm_size_bits
        += P[i].batch_proof().R().compressed_repr().nbits();
  }

  /* Simulate P2P communication: each Pi receives yji from each Pj */
  size_t y_comm_size_bits = 0UL;
  for (unsigned int i = 0; i < n; i++)
  {
    for (unsigned int j = 0; j < n; j++)
    {
      if (j == i) continue;
      P[i].keygen_add_share(j, P[j].y_k(i));
      y_comm_size_bits += P[j].y_k(i).nbits();
    }
  }

  /***************************** KEYGEN CHECK *******************************/
  auto keygen_check = [&P, &CL] {
    // P0 checks shares for all other players
    P[0].keygen_check_verify_all_players(CL);
  };
  Bench::one_function<ms, ms>(keygen_check, niter, "Keygen Check", desc.str());

  /**************************** KEYGEN EXTRACT ******************************/
  auto keygen_extract = [&P, &CL] {
    // P0 computes its share of sk, and pk
    P[0].keygen_extract(CL);
  };
  Bench::one_function<ms, ms>(
      keygen_extract, niter, "Keygen Extract", desc.str());

  // Do this for the t+1 first players, skip the rest to save time
  for (unsigned int i = 1; i < t + 1; i++)
  {
    P[i].keygen_extract_for_benchs(CL, P[0].Gammas());
  }

  /**************************** DECRYPT PARTIAL *****************************/
  /* Encrypt a random message */
  // Not measured in bench as it is NOT part of the protocol (the protocol only
  // regards decryption)
  CL_Threshold_Static::ClearText message{CL, randgen};
  CL_Threshold_Static::CipherText ct{
      CL,
      P.begin()->pk(),
      message,
      randgen.random_mpz(CL.encrypt_randomness_bound())};

  /* Decrypt partial: the first t honest parties perform decryption */
  auto decrypt_partial = [&P, &CL, &ct, &randgen] {
    // P0 performs partial decryption
    P[0].decrypt_partial(CL, randgen, ct);
  };
  Bench::one_function<ms, ms>(
      decrypt_partial, niter, "Decrypt Partial", desc.str());

  // P1 to Pt perform partial decryption
  for (unsigned int i = 1u; i < (t + 1); ++i)
  {
    P[i].decrypt_partial(CL, randgen, ct);
  }

  /************************ DECRYPT COMMUNICATION ***************************/
  /*
   * Simulate broadcast communication: P0 to Pt+1 broadcast their w and proof
   * In real execution, all players taking part in the decyryption should get
   * w_i and proof_i from the broadcast.
   * Here to speed up the bench, only P0 gets w_i and proof_i, needed to measure
   * decrypt_verify and decrypt_combine afterwards
   */
  size_t w_comm_size_bits = 0UL, dec_proof_comm_size_bits = 0UL;
  for (unsigned int j = 1; j < (t + 1); j++)
  {
    P[0].decrypt_add_partial_dec(j, P[j].part_dec()); // get w_j (broadcast)
    /* Compute broadcast size */
    w_comm_size_bits += P[j].part_dec().first.compressed_repr().nbits();
    dec_proof_comm_size_bits += P[j].part_dec().second.u().nbits();
    dec_proof_comm_size_bits
        += P[j].part_dec().second.R1().compressed_repr().nbits();
    dec_proof_comm_size_bits
        += P[j].part_dec().second.R2().compressed_repr().nbits();
  }

  /**************************** DECRYPT VERIFY ******************************/
  // "Check each player" variant
  auto decrypt_verify = [&P, &CL, &t] {
    for (unsigned int j = 1; j < (t + 1); j++)
      P[0].decrypt_verify_player_decryption(CL, j);
  };
  Bench::one_function<ms, ms>(
      decrypt_verify, niter, "Decrypt Verify", desc.str());

  // Batch variant
  auto decrypt_verify_batch = [&P, &CL, &randgen] {
    P[0].decrypt_verify_batch(CL, randgen);
  };
  Bench::one_function<ms, ms>(
      decrypt_verify_batch, niter, "  batch variant", desc.str());

  /**************************** DECRYPT COMBINE *****************************/
  CL_Threshold_Static::ClearText recovered_msg;
  auto decrypt_combine = [&P, &CL, &ct, &recovered_msg] {
    // P0 performs combined decryption
    P[0].decrypt_combine(recovered_msg, CL, ct);
  };
  Bench::one_function<ms, ms>(
      decrypt_combine, niter, "Decrypt Combine", desc.str());


  /************************** COMMUNICATION COSTS ***************************/

  float y_comm_size_KiB = (y_comm_size_bits + 7u) / 8192.0;
  float C_comm_size_KiB = (C_comm_size_bits + 7u) / 8192.0;
  float batch_proof_comm_size_KiB = (batch_proof_comm_size_bits + 7u) / 8192.0;
  float keygen_broadcast_comm_size_KiB
      = C_comm_size_KiB + batch_proof_comm_size_KiB;
  float w_comm_size_KiB = (w_comm_size_bits + 7u) / 8192.0;
  float dec_proof_comm_size_KiB = (dec_proof_comm_size_bits + 7u) / 8192.0;
  float decrypt_comm_size_KiB = w_comm_size_KiB + dec_proof_comm_size_KiB;

  std::cout << std::fixed;
  std::cout << "\n     Phase  |" << "   Comm. type    |" << "  Size/Player  |"
            << "  Size total\n";

  std::cout << "    Keygen  |" << " P2P             |"
            << std::setprecision(2) << std::setw(10)
            << y_comm_size_KiB / n << " KiB |"
            << std::setprecision(1) << std::setw(10)
            << y_comm_size_KiB << " KiB\n";
  std::cout << "            |" << " Broadcast       |"
            << std::setprecision(2) << std::setw(10)
            << keygen_broadcast_comm_size_KiB / n << " KiB |"
            << std::setprecision(1) << std::setw(10)
            << keygen_broadcast_comm_size_KiB << " KiB\n";
  std::cout << "            |" << "   Commitments   |"
            << std::setprecision(2) << std::setw(10)
            << C_comm_size_KiB / n << " KiB |"
            << std::setprecision(1) << std::setw(10)
            << C_comm_size_KiB << " KiB\n";
  std::cout << "            |" << "   Batch proofs  |"
            << std::setprecision(2) << std::setw(10)
            << batch_proof_comm_size_KiB / n << " KiB |"
            << std::setprecision(1) << std::setw(10)
            << batch_proof_comm_size_KiB
            << " KiB\n";

  std::cout << "   Decrypt  |" << " Broadcast       |"
            << std::setprecision(2) << std::setw(10)
            << decrypt_comm_size_KiB / (t+1u) << " KiB |"
            << std::setprecision(1) << std::setw(10)
            << (decrypt_comm_size_KiB) << " KiB\n";
  std::cout << "            |" << "   Part. decrypt |"
            << std::setprecision(2) << std::setw(10)
            << w_comm_size_KiB / (t+1u) << " KiB |"
            << std::setprecision(1) << std::setw(10)
            << w_comm_size_KiB  << " KiB\n";
  std::cout << "            |" << "   DlogEq proofs |"
            << std::setprecision(2) << std::setw(10)
            << dec_proof_comm_size_KiB / (t+1u) << " KiB |"
            << std::setprecision(1) << std::setw(10)
            << dec_proof_comm_size_KiB << " KiB\n";

  std::cout << std::flush;
}

////////////////////////////////////////////////////////////////////////////////
//****************************************************************************//
////////////////////////////////////////////////////////////////////////////////

int main (int argc, char * argv[])
{
  //                                 t = floor((n+1)/2) - 1
  //                                {comp. sec. , stat. dist, soundness, n, niter}
  const BenchParam bench_params[] = {{SecLevel::_112, 112u, 112u,  10u, 10u},
                                     {SecLevel::_112, 112u, 112u, 100u, 10u},
                                     {SecLevel::_128,  40u, 128u,  10u, 10u},
                                     {SecLevel::_128,  64u, 128u,  10u, 10u},
                                     {SecLevel::_128,  64u, 128u, 100u,  5u},
                                     {SecLevel::_128, 112u, 128u,  10u, 10u},
                                     {SecLevel::_192,  40u, 192u,  10u,  5u},
                                     {SecLevel::_192,  64u, 192u,  10u,  5u},
                                     {SecLevel::_192, 112u, 192u,  10u,  5u},
                                     {SecLevel::_256, 64u,  256u,  10u,  3u}};

  RandGen randgen;
  randseed_from_argv(randgen, argc, argv);

  Bench::print_thread_info();

  for (const BenchParam params : bench_params)
  {
    std::cout << " comp. sec. | stat. sec. | soundness |  n  |  t  |"
              << "    operation    |   time   |  time per op.  | std. dev."
              << std::endl;

    std::stringstream desc;
    desc << "  " << std::setw(3) << params.seclevel << " bits  |  "
         << std::setw(3) << params.stat_dist << " bits  | "
         << std::setw(3) << params.soundness_bits << " bits  | "
         << std::setw(3) << params.n << " | "
         << std::setw(3) << params.t;

    CL_Threshold_bench_protocol_per_part(params, randgen, desc.str());

    std::cout << "-------------------------------------------------------------"
                 "---------------"
              << std::endl;
  }

  return EXIT_SUCCESS;
}
