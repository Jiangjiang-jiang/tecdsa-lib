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
#ifndef BICYCL_CL_CL_THRESHOLD_INL
#define BICYCL_CL_CL_THRESHOLD_INL

#include "CL_threshold.hpp"

namespace BICYCL
{
  //////////////////////////////////////////////////////////////////////////////
  //    ___  _              ___ ___      _       _  __
  //   |   \| |   ___  __ _| __/ _ \    /_\  ___| |/ /
  //   | |) | |__/ _ \/ _` | _| (_) |  / _ \/ _ \ ' <
  //   |___/|____\___/\__, |___\__\_\ /_/ \_\___/_|\_\`
  //                  |___/
  //////////////////////////////////////////////////////////////////////////////
  inline
  CL_DlogEq_AoK::CL_DlogEq_AoK(const CL_HSMqk & cl_hsmq,
                               size_t soundness_bytes,
                               RandGen & randgen,
                               const Mpz & x,
                               const QFI & f1,
                               const QFI & f2,
                               const QFI & q1,
                               const QFI & q2)
  {
    // Sample r, random bound is :
    // 2^lambda_dist * 2^challenge_bits * 2^size_x
    Mpz r{randgen.random_mpz_2exp(x.nbits() + soundness_bytes*8u
                                  + cl_hsmq.lambda_distance())};

    // Compute commitment R2 = f2^r
    cl_hsmq.Cl_G().nupow(R2_, f2, r);

    // Compute commitment R1 = f1^r
    cl_hsmq.Cl_G().nupow(R1_, f1, r);

    // Compute hash-challenge
    Mpz ch{hash_for_challenge(soundness_bytes, f1, f2, q1, q2)};

    // Compute "response" u = r + ch*x
    Mpz::mul(u_, ch, x);
    Mpz::add(u_, u_, r);
  }

#ifdef BICYCL_WITH_PTHREADS
  /* Multi-threaded variant */
  inline
  CL_DlogEq_AoK::CL_DlogEq_AoK(const CL_HSMqk & cl_hsmq,
                               size_t soundness_bytes,
                               RandGen & randgen,
                               const Mpz & x,
                               const QFI & f1,
                               const QFI & f2,
                               const QFI & q1,
                               const QFI & q2,
                               std::thread & thread_q)
  {
    // Sample r, random bound is :
    // 2^lambda_dist * 2^challenge_bits * 2^size_x
    Mpz r{randgen.random_mpz_2exp(x.nbits() + soundness_bytes
                                  + cl_hsmq.lambda_distance())};

    // Compute R2 = f2^r on a another thread
    void (ClassGroup::*nupow_ptr)(QFI &, const QFI &, const Mpz &) const
        = &ClassGroup::nupow;
    std::thread thread_R2{
        nupow_ptr, cl_hsmq.Cl_G(), std::ref(R2_), std::cref(f2), std::cref(r)};

    // Compute commitment R1 = f1^r
    cl_hsmq.Cl_G().nupow(R1_, f1, r);

    // Compute hash-challenge
    thread_q.join();   // q1 and q2 required
    thread_R2.join();  // R2 required
    Mpz ch{hash_for_challenge(soundness_bytes, f1, f2, q1, q2)};

    // Compute "response" u = r + ch*x
    Mpz::mul(u_, ch, x);
    Mpz::add(u_, u_, r);
  }
#endif

  /* */
  inline const Mpz & CL_DlogEq_AoK::u() const
  {
    return u_;
  }

  /* */
  inline const QFI & CL_DlogEq_AoK::R1() const
  {
    return R1_;
  }

  /* */
  inline const QFI & CL_DlogEq_AoK::R2() const
  {
    return R2_;
  }

  /* */
  inline
  bool CL_DlogEq_AoK::verify(const CL_HSMqk & cl_hsmq,
                             size_t soundness_bytes,
                             const QFI & f1,
                             const QFI & f2,
                             const QFI & q1,
                             const QFI & q2) const
  {
    // Compute hash-challenge
    Mpz ch{hash_for_challenge(soundness_bytes, f1, f2, q1, q2)};

    // check: perform generic check f^u = R*Q^ch
    auto check
        = [this, &cl_hsmq, &ch] (
              bool & success, const QFI & f, const QFI & Q, const QFI & R) {
            QFI check_right, check_left;

            // f^u
            if (f == cl_hsmq.h()) // Optimize the case where f = h
              cl_hsmq.power_of_h(check_left, u_);
            else
              cl_hsmq.Cl_G().nupow(check_left, f, u_);

            // R*Q^ch
            cl_hsmq.Cl_G().nupow(check_right, Q, ch);
            cl_hsmq.Cl_G().nucomp(check_right, check_right, R);

            // Compare
            success = (check_left == check_right);
          };

#ifdef BICYCL_WITH_PTHREADS
    // Check f1^u = R1*q1^ch on a second thread
    bool check1;
    std::thread thread_check1{
        check, std::ref(check1), std::cref(f1), std::cref(q1), std::cref(R1_)};

    // Check f2^u = R2*q2^ch
    bool check2;
    check(check2, f2, q2, R2_);

    thread_check1.join();
    return (check1 && check2);

#else
    bool success;
    check(success, f1, q1, R1_);   // Check f1^u = R1*q1^ch
    if (success == true)           // If first check passed
      check(success, f2, q2, R2_); // Check f2^u = R2*q2^ch

    return success;

#endif
  }

  /* */
  inline
  Mpz CL_DlogEq_AoK::hash_for_challenge(size_t soundness_bytes,
                                        const QFI & f1,
                                        const QFI & f2,
                                        const QFI & q1,
                                        const QFI & q2) const
  {
    HashAlgo H((soundness_bytes <= 128) ? HashAlgo::SHAKE128
                                        : HashAlgo::SHAKE256,
               soundness_bytes);
    return Mpz(H(R1_, R2_, f1, f2, q1, q2));
  }

  //////////////////////////////////////////////////////////////////////////////
  //    ___       _      _      ___  _                  _       _  __
  //   | _ ) __ _| |_ __| |_   |   \| |   ___  __ _    /_\  ___| |/ /
  //   | _ \/ _` |  _/ _| ' \  | |) | |__/ _ \/ _` |  / _ \/ _ \ ' <
  //   |___/\__,_|\__\__|_||_| |___/|____\___/\__, | /_/ \_\___/_|\_\`
  //                                          |___/
  //////////////////////////////////////////////////////////////////////////////
  inline
  CL_Batch_Dlog_AoK::CL_Batch_Dlog_AoK(const Mpz & u, const QFI & R)
  : u_{u}, R_{R}
  {}

  inline
  CL_Batch_Dlog_AoK::CL_Batch_Dlog_AoK(const CL_HSMqk & cl_hsmq,
                                       size_t soundness_bytes,
                                       RandGen & randgen,
                                       const size_t a_rand_bound,
                                       const size_t x_rand_bound,
                                       const unsigned int t,
                                       const Mpz & delta,
                                       const Mpz & a,
                                       const std::vector<Mpz> & xi,
                                       const std::vector<QFI> & Ci)
  {
    if (xi.size() != t)
      throw std::invalid_argument("xi shall have exactly t elements");
    if (Ci.size() != t + 1)
      throw std::invalid_argument("Ci shall have exactly t+1 elements");

    // Sample r, random bound is :
    // 2^lambda_dist * 2^soundness * (2^size_a + t * delta * 2^size_x)
    Mpz rand_bound{static_cast<unsigned long>(t)};
    Mpz::mul(rand_bound, rand_bound, delta);
    Mpz::mulby2k(rand_bound, rand_bound, x_rand_bound); // t * delta * 2^size_x
    Mpz temp{1UL};
    Mpz::mulby2k(temp, temp, a_rand_bound);
    Mpz::add(rand_bound, rand_bound, temp);             // + 2^size_a
    Mpz::mulby2k(
        rand_bound, rand_bound, cl_hsmq.lambda_distance()); // * 2^lambda_dist
    Mpz::mulby2k(rand_bound, rand_bound, soundness_bytes*8u); // * 2^soundness
    Mpz r(randgen.random_mpz(rand_bound));

    // Compute R = h^r
    cl_hsmq.power_of_h(R_, r);

    // Compute t+1 hash-challenges
    std::vector<Mpz> challenges;
    hash_for_challenge(soundness_bytes,challenges, cl_hsmq, Ci);

    // a = ai
    // x[i] = r[i]
    // Compute u = r + a*ch[0] + delta*(x[0]*ch[1] + ... + x[t-1]*ch[t])
    for (unsigned int k = 0u; k < t; k++)
    {
      Mpz::mul(temp, xi[k], challenges[k + 1]);
      Mpz::add(u_, u_, temp); // + x[k]*ch[k+1]
    }
    Mpz::mul(u_, u_, delta); // * delta
    Mpz::mul(temp, a, challenges[0]);
    Mpz::add(u_, u_, temp); // + a*ch[0]
    Mpz::add(u_, u_, r);    // + r
  }

  /* */
  inline const Mpz & CL_Batch_Dlog_AoK::u () const
  {
    return u_;
  }

  /* */
  inline const QFI & CL_Batch_Dlog_AoK::R () const
  {
    return R_;
  }

  /* */
  inline
  bool CL_Batch_Dlog_AoK::verify(size_t soundness_bytes,
                                 const CL_HSMqk & cl_hsmq,
                                 size_t m,
                                 const std::vector<QFI> & Ci) const
  {
    if (Ci.size() != m)
      throw std::invalid_argument("Ci shall have exactly m elements");

    // Compute h^u
    QFI hu;
    cl_hsmq.power_of_h(hu, u_);

    // Compute t+1 hash-challenges
    std::vector<Mpz> challenges;
    hash_for_challenge(soundness_bytes, challenges, cl_hsmq, Ci);

    // Compute R * C[0]^ch[0] * C[1]^ch[1] * ... * C[t]^ch[t]
    QFI product;
    // WNAF multi-expo with w = 5
    cl_hsmq.Cl_G().nupow(product, Ci, challenges, 5);
    cl_hsmq.Cl_G().nucomp(product, product, R_);

    // Finally verify the product
    return (hu == product);
  }

  inline
  void CL_Batch_Dlog_AoK::hash_for_challenge(size_t soundness_bytes,
                                             std::vector<Mpz> & challenges,
                                             const CL_HSMqk & cl_hsmq,
                                             const std::vector<QFI> & Ci) const
  {
    // Extended hash of the statement, get t+1 challenges of [soundness] bytes
    HashAlgo H((soundness_bytes <= 128) ? HashAlgo::SHAKE128
                                        : HashAlgo::SHAKE256,
               soundness_bytes * Ci.size());
    HashAlgo::Digest hashed(H(R_, cl_hsmq.h(), Ci));

    // Split extended hash into t+1 challenges of [soundness] bytes
    challenges.reserve(Ci.size());
    for (unsigned int k = 0u; k < Ci.size(); ++k)
    {
      unsigned char * start = hashed.data() + k*soundness_bytes;
      std::vector<unsigned char> ch(start, start+soundness_bytes);
      challenges.emplace_back(ch);
    }
  }

  //////////////////////////////////////////////////////////////////////////////
  //    ___          _   _      _   ___                       _   _
  //   | _ \__ _ _ _| |_(_)__ _| | |   \ ___ __ _ _ _  _ _ __| |_(_)___ _ _
  //   |  _/ _` | '_|  _| / _` | | | |) / -_) _| '_| || | '_ \  _| / _ \ ' \`
  //   |_| \__,_|_|  \__|_\__,_|_| |___/\___\__|_|  \_, | .__/\__|_\___/_||_|
  //                                                |__/|_|
  //////////////////////////////////////////////////////////////////////////////

  inline
  CL_Threshold_Static::PartialDecryption::PartialDecryption()
    : std::pair<QFI, CL_DlogEq_AoK>(QFI(), CL_DlogEq_AoK())
  {
    // Nothing to do
  }

  inline
  QFI & CL_Threshold_Static::PartialDecryption::w()
  {
    return first;
  }

  inline const QFI & CL_Threshold_Static::PartialDecryption::w() const
  {
    return first;
  }

  inline
  CL_DlogEq_AoK & CL_Threshold_Static::PartialDecryption::proof()
  {
    return second;
  }

  inline const CL_DlogEq_AoK & CL_Threshold_Static::PartialDecryption::proof() const
  {
    return second;
  }

  inline
  bool CL_Threshold_Static::PartialDecryption::verify(const CL_HSMqk & cl_hsmq,
                                                      size_t soundness_bytes,
                                                      const QFI & h_delta2,
                                                      const QFI & ct1_delta2,
                                                      const QFI & gamma) const
  {
    // this.first : Partial decryption w (QFI)
    // this.second : Proof that goes with partial decryption (CL_DlogEq_AoK)
    return second.verify(cl_hsmq, soundness_bytes, h_delta2, ct1_delta2, gamma, first);
  }

  //////////////////////////////////////////////////////////////////////////////
  //     ___ _      _____ _               _        _    _
  //    / __| |    |_   _| |_  _ _ ___ __| |_  ___| |__| |
  //   | (__| |__    | | | ' \| '_/ -_|_-< ' \/ _ \ / _` |
  //    \___|____|   |_| |_||_|_| \___/__/_||_\___/_\__,_|
  //
  //////////////////////////////////////////////////////////////////////////////

  inline
  CL_Threshold_Static::CL_Threshold_Static(const CL_HSMqk & CL_Hsmq,
                                           unsigned int n,
                                           unsigned int t,
                                           unsigned int i,
                                           size_t soundness_bytes)
    :
      soundness_bytes_{soundness_bytes},
      n_{n},
      t_{t},
      i_{i}
  {
    // Ensure t < n, n > 1, t > 0, and i < n
    if (n < 2u)
      throw std::invalid_argument("CL_Threshold_Static: n must be > 1");
    if (t < 1u)
      throw std::invalid_argument("CL_Threshold_Static: t must be > 0");
    if (t >= n)
      throw std::invalid_argument("CL_Threshold_Static: t must be < n");
    if (i >= n)
      throw std::invalid_argument("CL_Threshold_Static: i must be < n");

    // Ensure 0 < soundness_bytes < 32 (max 256 bits with SHAKE-256)
    if (soundness_bytes == 0u)
      throw std::invalid_argument("CL_Threshold_Static: soundness must be > 0");

    // Precompute Delta, Delta^2, and Delta^(-2)
    Mpz::factorial(delta_, n);
    Mpz::mul(delta2_, delta_, delta_);
    Mpz::mod_inverse(delta2_inv_, delta2_, CL_Hsmq.q());

    // For each participant
    for (unsigned int k = 0u; k < n; ++k)
    {
      // Add to the set of qualified players
      QualifiedPlayersSet_.insert(k);
      // Prepare commitments container, fill with t+1 default QFIs
      C_[k].resize(t_ + 1);
    }

    // Reserve space for some containers
    r_.reserve(t_);
    y_self_.reserve(n_);
    y_others_.reserve(n_);
    keygen_batch_proofs_.reserve(n_);
    Gamma_.reserve(n_);

    // Precompute h^delta
    CL_Hsmq.power_of_h(h_delta_, delta_);

    // Precompute h_delta values to speed up (h^delta)^r exponentiations
    h_delta_precomp_ = QFIPrecomp(h_delta_, poly_coeff_bitsize_bound(CL_Hsmq));

    // Precompute h^(delta^2)
    // OPTIMIZE when to use precomp ? When to use wnaf* ?
    CL_Hsmq.Cl_G().nupow(h_delta2_, h_delta_, delta_, h_delta_precomp_);
  }

  inline
  unsigned int CL_Threshold_Static::i() const
  {
    return i_;
  }

  inline const Mpz & CL_Threshold_Static::y_k(unsigned int k) const
  {
    auto v = y_self_.find(k);
    if (v != y_self_.end())
    {
      return v->second;
    }
    else
    {
      if (y_self_.empty())
        throw ProtocolLogicError("y_k: Shamir shares not computed yet");
      else
        throw std::invalid_argument("y_k: No share exists for this player");
    }
  }

  inline const std::vector<QFI> & CL_Threshold_Static::C() const
  {
    auto v = C_.find(i_);
    if (v != C_.end())
    {
      return v->second;
    }
    else
    {
      throw ProtocolLogicError("C: Commitments not computed yet");
    }
  }

  inline const CL_Batch_Dlog_AoK & CL_Threshold_Static::batch_proof() const
  {
    auto v = keygen_batch_proofs_.find(i_);
    if (v != keygen_batch_proofs_.end())
    {
      return v->second;
    }
    else
    {
      throw ProtocolLogicError(
          "batch_proof: Batch proof not computed yet");
    }
  }

  inline const CL_Threshold_Static::PublicKey & CL_Threshold_Static::pk() const
  {
    return pk_;
  }

  inline const CL_Threshold_Static::ParticipantsValueMap<QFI> &
  CL_Threshold_Static::Gammas() const
  {
    return Gamma_;
  }

  inline const CL_Threshold_Static::PartialDecryption &
  CL_Threshold_Static::part_dec() const
  {
    auto v = part_dec_.find(i_);
    if (v != part_dec_.end())
    {
      return v->second;
    }
    else
    {
      throw ProtocolLogicError(
          "part_dec: Partial decryption not performed yet");
    }
  }

  inline const CL_Threshold_Static::ParticipantsSet &
  CL_Threshold_Static::QualifiedPlayerSet() const
  {
    return QualifiedPlayersSet_;
  }

  inline const CL_Threshold_Static::ParticipantsSet &
  CL_Threshold_Static::ComplaintsSet() const
  {
    return ComplaintsSet_;
  }

  inline const CL_Threshold_Static::ParticipantsSet &
  CL_Threshold_Static::DecryptionPlayerSet() const
  {
    return DecryptionPlayersSet_;
  }

  /* */
  inline
  void CL_Threshold_Static::keygen_dealing(const CL_HSMqk & CL_Hsmq,
                                           RandGen randgen)
  {
    //----------------------------------------------------------//
    // Sample secret ai from [0, 2^sigma * s]
    //----------------------------------------------------------//
    ai_ = randgen.random_mpz(CL_Hsmq.secretkey_bound());

    //----------------------------------------------------------//
    // Share ai as (yi1, ..., yin):
    //  Generate t random polynom coefficients (ri1, ..., rit)
    //----------------------------------------------------------//
    size_t r_rand_bound = poly_coeff_bitsize_bound(CL_Hsmq);

    r_.clear();
    for (unsigned int k = 0; k < t_; ++k)
    {
      r_.emplace_back(randgen.random_mpz_2exp(r_rand_bound));
    }

    //----------------------------------------------------------//
    // Compute (yi1, ... , yin)
    // For every player, evaluate F at the player's id
    // With F(X) = delta*ai + ri1*X + ri2*X^2 + ... + rit*X^t
    //----------------------------------------------------------//
    Mpz delta_ai;
    Mpz::mul(delta_ai, delta_, ai_);

    std::mutex mutex; // Used to regulate access to y_self

    // evaluate_poly: compute F(j) for a subset of QualifiedPlayersSet_
    auto evaluate_poly
        = [this, &mutex, &delta_ai] (ParticipantsSet::const_iterator start,
                                     ParticipantsSet::const_iterator end,
                                     unsigned int thread_id = 0u) {
            for (auto it = start; it != end; ++it)
            {
              // Evaluate F(j) using Horner's method
              Mpz eval{0UL};
              for (int k = t_ - 1; k >= 0; --k)
              {
                Mpz::add(eval, eval, r_[k]);
                // Player id's are 0-based, but protocol id's are 1-based.
                // Offset j by one
                Mpz::mul(eval, eval, *it + 1);
              }
              // Add constant term, which is delta * ai
              Mpz::add(eval, eval, delta_ai);
#ifdef BICYCL_WITH_PTHREADS
              std::unique_lock<std::mutex> lock{mutex};
#endif // BICYCL_WITH_PTHREADS
              y_self_[*it] = eval;
            }

            // thread_id needed by divide_workload, but not used here. Suppress warning.
            (void)thread_id;
          };

#ifdef BICYCL_WITH_PTHREADS
    // Multi-threaded version
    run_over_threads(evaluate_poly, NB_THREADS_, QualifiedPlayersSet_.cbegin(), QualifiedPlayersSet_.cend());

#else
    evaluate_poly(QualifiedPlayersSet_.cbegin(), QualifiedPlayersSet_.cend());

#endif

    //----------------------------------------------------------------------//
    // Compute commitments Ci0 of ai and (Ci1, .., Cit) of (ri1, ... ,rit)
    //----------------------------------------------------------------------//
    CL_Hsmq.power_of_h(C_[i_][0], ai_);       // Ci0 = h^ai

    // compute_commitments: compute Cik for a subset of [1, t+1[
    auto compute_commitments = [this, &CL_Hsmq] (unsigned int start,
                                                 unsigned int end,
                                                 unsigned int thread_id = 0u) {
      for (unsigned int k = start; k < end; ++k) // (Ci1, .., Cit)
      {
        // Ci[k] = (h^delta)^rik
        CL_Hsmq.Cl_G().nupow(C_[i_][k], h_delta_, r_[k - 1], h_delta_precomp_);
      }
      // thread_id needed by divide_workload, but not used here. Suppress warning.
      (void)thread_id;
    };

#ifdef BICYCL_WITH_PTHREADS
    // Multi-threaded version
    const unsigned int NB_THREADS_ = 6u;
    run_over_threads(compute_commitments, NB_THREADS_, 1, t_+1);

#else
    compute_commitments(1, t_ + 1);

#endif

    //----------------------------------------------------------//
    // Compute batch DL proof (Ci, (ai, ri1, ... , rit))
    //----------------------------------------------------------//
    keygen_batch_proofs_.emplace(
        std::piecewise_construct,
        std::forward_as_tuple(i_), // Key
        std::forward_as_tuple(     // Args for proof constructor
            CL_Hsmq,
            soundness_bytes_,
            randgen,
            CL_Hsmq.secretkey_bound().nbits(),
            r_rand_bound,
            t_,
            delta_,
            ai_,
            r_,
            C_[i_]));
  }

  /* */
  inline
  void CL_Threshold_Static::keygen_add_share(unsigned int j, const Mpz & yj)
  {
    if ((j == i_) || (j >= n_)) // Ensure j != i and j < n
    {
      std::string playerStr{std::to_string(j)};
      throw std::invalid_argument("keygen_add_share:" + playerStr
                                  + " is not a valid player id");
    }

    // Store share from j
    y_others_.emplace(j, yj);
  }

  /* */
  inline
  void CL_Threshold_Static::keygen_add_commitments(unsigned int j,
                                                   const std::vector<QFI> & Cj)
  {
    if ((j == i_) || (j >= n_)) // Ensure j != i and j < n
    {
      std::string playerStr{std::to_string(j)};
      throw std::invalid_argument("keygen_add_commitments: " + playerStr
                                  + " is not a valid player id");
    }
    if (Cj.size() != t_ + 1) // Ensure Cj contains t+1 commitments
      throw std::invalid_argument(
          "keygen_add_commitments: Cj must contain exactly t+1 entries");

    // Store commitments from j
    C_[j] = Cj;
  }

  inline
  void CL_Threshold_Static::keygen_add_proof(unsigned int j,
                                             const CL_Batch_Dlog_AoK & proof)
  {
    if ((j == i_) || (j >= n_)) // Ensure j != i and j < n
    {
      std::string playerStr{std::to_string(j)};
      throw std::invalid_argument("keygen_add_proof:" + playerStr
                                  + " is not a valid player id");
    }

    keygen_batch_proofs_.emplace(j, proof);
  }

  /* */
  inline
  bool CL_Threshold_Static::keygen_check_player_shares(const CL_HSMqk & CL_Hsmq,
                                                       unsigned int j,
                                                       bool resolve_complaints)
  {
    // Check that j is a qualified player
    if (QualifiedPlayersSet_.find(j) == QualifiedPlayersSet_.end())
    {
      std::string playerStr{std::to_string(j)};
      throw std::invalid_argument("keygen_check_player_shares:" + playerStr
                                  + " is not a qualified player id");
    }
    // Check j is another player
    if (j == i_)
      throw std::invalid_argument(
          "keygen_check_player_shares: Do not check own shares");

    // If no share yij received from j, cannot verify
    if (y_others_.find(j) == y_others_.end())
      throw ProtocolLogicError(
          "keygen_check_player_shares: no share received from this player");
    // If # of commitments received (from j) != t+1, cannot verify
    if (C_[j].size() != t_ + 1)
      throw ProtocolLogicError(
          "keygen_check_player_shares: no commitments received from this player");

    // Left operand
    QFI check_leftside;
    CL_Hsmq.Cl_G().nupow(
        check_leftside, h_delta_, y_others_[j], h_delta_precomp_);

    // Right operand
    // First compute product for k in {1, .. ,t} of Cjk^(i^k)
    // with Horner's method:
    // Cj1^(i) * Cj2^(i^2) * ... * Cjt-1^(i^(t-1)) * Cjt^(i^t)
    // -> (Cj1 * (Cj2 * ( ... * (Cjt-1 * Cjt^i )^i ... )^i )^i
    //
    // Player id's are 0-based, but protocol id's are 1-based. Offset i by one
    Mpz exponent = Mpz(static_cast<unsigned long>(i_ + 1));
    QFI check_rightside;
    for (unsigned int k = t_; k > 0u; --k)
    {
      CL_Hsmq.Cl_G().nucomp(check_rightside, check_rightside, C_[j][k]);
      // Very small exponent, use a window width of 2 (like a regular NAF)
      CL_Hsmq.Cl_G().nupow(check_rightside, check_rightside, exponent, 2);
    }
    // Then compose with Cj0^(delta^2)
    QFI temp;
    // OPTIMIZE possible ?
    // delta2 is very large, can we compute differently to reduce the exponent ?
    CL_Hsmq.Cl_G().nupow(temp, C_[j][0], delta2_);
    CL_Hsmq.Cl_G().nucomp(check_rightside, check_rightside, temp);

    // Compare values to determine if share is valid.
    bool check_pass = (check_leftside == check_rightside);

    if (resolve_complaints)
    {
      // If it is valid, resolve the complaint (if there was one).
      // Otherwise, store the complaint to be made to Pj
      if (check_pass)
        ComplaintsSet_.erase(j);
      else
        ComplaintsSet_.insert(j);
    }

    return check_pass;
  }

  /* */
  inline
  bool CL_Threshold_Static::keygen_verify_player_proof(const CL_HSMqk & CL_Hsmq,
                                                       unsigned int j,
                                                       bool disqualify_on_fail)
  {
    // Check that j is a qualified player
    if (QualifiedPlayersSet_.find(j) == QualifiedPlayersSet_.end())
    {
      std::string playerStr{std::to_string(j)};
      throw std::invalid_argument("keygen_verify_player_proof:" + playerStr
                                  + " is not a qualified player id");
    }
    // Check j is another player
    if (j == i_)
      throw std::invalid_argument(
          "keygen_verify_player_proof: Do not check own shares");

    // If proof not received, cannot verify
    if (keygen_batch_proofs_.find(j) == keygen_batch_proofs_.end())
      throw ProtocolLogicError("keygen_verify_player_proof: no batch proof "
                               "received from this player");
    // If # of commitments received (from j) != t+1, cannot verify
    if (C_[j].size() != (t_ + 1))
      throw ProtocolLogicError("keygen_verify_player_proof: no commitments "
                               "received from this player");

    // Verify proof.
    HashAlgo H{hash_algo()};
    bool verify_pass = keygen_batch_proofs_.at(j).verify(
        soundness_bytes_, CL_Hsmq, t_ + 1, C_[j]);

    // If the verification fails, we can disqualify j
    if(disqualify_on_fail && !verify_pass)
      keygen_disqualify_player(j);

    return verify_pass;
  }

  /* */
  inline bool
  CL_Threshold_Static::keygen_check_verify_all_players(const CL_HSMqk & CL_Hsmq)
  {
    std::vector<std::vector<unsigned int>> to_disqualify;
    std::vector<std::vector<unsigned int>> to_complain;

    // check_verify:
    // Perform share check and proof verification for a subset of players
    // Register players that fail to verify proof in to_disqualify
    // Register players that verify proof, but fail to check share in to_complain
    auto check_verify = [this, &CL_Hsmq, &to_disqualify, &to_complain] (
                            ParticipantsSet::const_iterator start,
                            ParticipantsSet::const_iterator end,
                            unsigned int thread_id = 0u) {
      std::vector<unsigned int> & disqualify = to_disqualify.at(thread_id);
      std::vector<unsigned int> & complain = to_complain.at(thread_id);
      for (auto it = start; it != end; ++it)
      {
        if (*it == i_) // For every other P
          continue;

        if (false == keygen_verify_player_proof(CL_Hsmq, *it, false))
        {
          // Remove Pj from Q immediately
          disqualify.push_back(*it);
        }
        else if (false == keygen_check_player_shares(CL_Hsmq, *it, false))
        {
          // Complain to Pj before deciding its removal from Q
          complain.push_back(*it);
        }
      }
    };

    bool success_for_all = true;

#ifdef BICYCL_WITH_PTHREADS
    // Multi-threaded version

    to_complain.resize(NB_THREADS_);
    to_disqualify.resize(NB_THREADS_);
    run_over_threads(check_verify,
                    NB_THREADS_,
                    QualifiedPlayersSet_.cbegin(),
                    QualifiedPlayersSet_.cend());

    // Handle complaints and disqualification
    ComplaintsSet_.clear();
    for (unsigned int u = 0; u < NB_THREADS_; ++u)
    {
      // Store complaints
      for (unsigned int j: to_complain[u])
      {
        ComplaintsSet_.insert(j);
        success_for_all = false;
      }
      // Disqualify dishonest players found in this thread
      for (unsigned int j : to_disqualify[u])
      {
        keygen_disqualify_player(j);
        success_for_all = false;
      }
    }

#else
    // Single-threaded version
    to_disqualify.resize(1);
    to_complain.resize(1);
    check_verify(QualifiedPlayersSet_.cbegin(), QualifiedPlayersSet_.cend());

    // Store complaints
    ComplaintsSet_.clear();
    for (unsigned int j: to_complain[0])
    {
      ComplaintsSet_.insert(j);
      success_for_all = false;
    }
    // Disqualify dishonest players
    for (unsigned int j : to_disqualify[0])
    {
      keygen_disqualify_player(j);
      success_for_all = false;
    }

#endif

    return success_for_all;
  }

  /* */
  void CL_Threshold_Static::keygen_disqualify_player(unsigned int j)
  {
    // Check that j is a qualified player
    if (QualifiedPlayersSet_.find(j) == QualifiedPlayersSet_.end())
    {
      std::string playerStr{std::to_string(j)};
      throw std::invalid_argument("keygen_disqualify_player:" + playerStr
                                  + " is not a qualified player id");
    }
    // Check j is another player
    if (j == i_)
      throw std::invalid_argument(
          "keygen_disqualify_player: A player cannot disuqalify themselves");

    // Remove j's values from all maps used during keygen
    y_self_.erase(j);
    y_others_.erase(j);
    C_.erase(j);
    keygen_batch_proofs_.erase(j);

    // Remove j from Q and Complaints sets
    QualifiedPlayersSet_.erase(j);
    ComplaintsSet_.erase(j);
  }

  /* */
  inline
  void CL_Threshold_Static::keygen_extract(const CL_HSMqk & CL_Hsmq)
  {
    // Check shares were received from every other valid player
    if (y_others_.size() < (QualifiedPlayersSet_.size() - 1u))
      throw ProtocolLogicError(
          "keygen_extract: missing shares from other players");

    // Check commitments were received from every other valid player
    if (C_.size() < QualifiedPlayersSet_.size())
      throw ProtocolLogicError(
          "keygen_extract: missing commitments from other players");
    // Check all complaints have been resolved
    if (ComplaintsSet_.size() != 0)
      throw ProtocolLogicError(
          "keygen_extract: some complaints have not been resolved");

    //----------------------------------------------------------//
    // Compute public key
    // pkcl = (C10 * C20 * ... * Ci0 * ... * Cn0) ^ delta2
    //----------------------------------------------------------//
    QFI pk_temp;
    for (unsigned int j : QualifiedPlayersSet_)
    {
      CL_Hsmq.Cl_G().nucomp(pk_temp, pk_temp, C_[j][0]);
    }
    CL_Hsmq.Cl_G().nupow(pk_temp, pk_temp, delta2_);
    pk_ = CL_Threshold_Static::PublicKey(CL_Hsmq, pk_temp);

    //----------------------------------------------------------//
    // Compute Shamir-share of private key
    // sk_share = y1i + y2i + ... + yii + ... + yni
    //----------------------------------------------------------//
    sk_share_ = y_self_[i_];
    for (unsigned int player_j : QualifiedPlayersSet_)
    {
      if (i_ == player_j) continue;
      Mpz::add(sk_share_, sk_share_, y_others_[player_j]);
    }

    //----------------------------------------------------------//
    // Compute public verification keys Gamma[i], used in decryption proofs
    //----------------------------------------------------------//
    // Used to regulate Gamma_ access
    std::mutex mutex_gamma;

    // Precomputations CC[k] = \prod{l in Q} C[l][k+1], with k in [0, t-1]
    std::vector<QFI> CC(t_);

    // compute_CCs: compute CC[k] for a range of values of k
    auto compute_CCs = [this, &CL_Hsmq, &CC] (unsigned int start,
                                              unsigned int end,
                                              unsigned int thread_id = 0u) {
      for (auto k = start; k < end; ++k)
      {
        for (unsigned int l : QualifiedPlayersSet_)
          CL_Hsmq.Cl_G().nucomp(CC[k], CC[k], C_[l][k + 1]);
      }
      // thread_id needed by divide_workload, but not used here. Suppress warning.
      (void)thread_id;
    };

    // compute_gammas: compute the Gamma_ value for a subset of players
    auto compute_Gammas = [this, &CL_Hsmq, &CC, &mutex_gamma] (
                              ParticipantsSet::const_iterator start,
                              ParticipantsSet::const_iterator end,
                              unsigned int thread_id = 0u) {
      QFI Gamma_temp;
      Mpz exponent;
      for (auto it = start; it != end; ++it)
      {
        exponent = static_cast<unsigned long>(*it + 1u);
        // Gamma[j] = ( pk * \prod{k} {(\prod{l} Clk)^(j^k)} )^delta
        //          = ( pk * \prod{k} {CC[k]^(j^k)} )^delta
        //
        // First compute \prod{k}{ CC[k]^(j^k) } with Horner's method:
        // CC[1]^(j) * CC[2]^(j^2) * ... * CC[t]^(j^t)
        // -> (CC[1] * (CC[2] * ( ... * CC[t]^j) ... )^j )^j
        //
        Gamma_temp = CL_Hsmq.Cl_G().one();
        for (unsigned int k = t_; k > 0u; k--)
        {
          // Horner's method: multiply then bring to power j
          CL_Hsmq.Cl_G().nucomp(Gamma_temp, Gamma_temp, CC[k - 1]);
          // Very small exponent, use a window width of 2 (like a regular NAF)
          CL_Hsmq.Cl_G().nupow(Gamma_temp, Gamma_temp, exponent, 2);
        }
        // Compose with pkCL
        CL_Hsmq.Cl_G().nucomp(Gamma_temp, Gamma_temp, pk_.elt());
        // Finally bring to power of delta
        CL_Hsmq.Cl_G().nupow(Gamma_temp, Gamma_temp, delta_);

#ifdef BICYCL_WITH_PTHREADS
        // Lock mutex to write Gamma_
        std::unique_lock<std::mutex> lock{mutex_gamma};
#endif
        Gamma_[*it] = Gamma_temp;
      }
      // thread_id needed by divide_workload, but not used here. Suppress warning.
      (void)thread_id;
    };

#ifdef BICYCL_WITH_PTHREADS
    // Multi-threaded version
    run_over_threads(compute_CCs, NB_THREADS_, 0, t_);
    run_over_threads(compute_Gammas,
                    NB_THREADS_,
                    QualifiedPlayersSet_.cbegin(),
                    QualifiedPlayersSet_.cend());

#else
    // Single-threaded version
    compute_CCs(0, t_);
    compute_Gammas(QualifiedPlayersSet_.cbegin(), QualifiedPlayersSet_.cend());
#endif
  }

  /* */
  inline
  void CL_Threshold_Static::decrypt_partial(const CL_HSMqk & CL_Hsmq,
                                            RandGen randgen,
                                            const CipherText & ct)
  {
    // Clear values from previous decryptions
    part_dec_.clear();
    part_dec_.insert({i_, PartialDecryption()});
    DecryptionPlayersSet_.clear();
    DecryptionPlayersSet_.insert(i_);

    // Compute ct1^(delta^2), for proof and verification
    CL_Hsmq.Cl_G().nupow(ct1_delta2_, ct.c1(), delta2_);

    HashAlgo H{hash_algo()};
#ifdef BICYCL_WITH_PTHREADS
    // Compute w = ct1^((delta^2)*sk_share) on a diferent thread
    void (ClassGroup::*nupow_ptr)(QFI &, const QFI &, const Mpz &) const
        = &ClassGroup::nupow;
    std::thread th{nupow_ptr,
                   std::cref(CL_Hsmq.Cl_G()),
                   std::ref(part_dec_[i_].w()),
                   std::cref(ct1_delta2_),
                   std::cref(sk_share_)};

    // Compute proof: DL-Eq ((h^delta2, ct1^delta2), (Gamma[i], w[i]), sk_share)
    // Provide thread reference to proof constructor, so that the thread can be
    // joined when the value of w is needed
    part_dec_[i_].proof() = CL_DlogEq_AoK(CL_Hsmq,
                                          soundness_bytes_,
                                          randgen,
                                          sk_share_,
                                          h_delta2_,
                                          ct1_delta2_,
                                          Gamma_[i_],
                                          part_dec_[i_].w(),
                                          th);

#else
    // Compute w = ct1^((delta^2)*sk_share)
    CL_Hsmq.Cl_G().nupow(part_dec_[i_].w(), ct1_delta2_, sk_share_);

    // Compute proof
    // Proof: DL-Eq ((h^delta2, ct1^delta2), (Gamma[i], w[i]), sk_share)
    //   u = r + sk_share*h
    //  R1 = (h^delta2)^r
    //  R2 = (ct1^delta2)^r
    part_dec_[i_].proof() = CL_DlogEq_AoK(CL_Hsmq,
                                          soundness_bytes_,
                                          randgen,
                                          sk_share_,
                                          h_delta2_,
                                          ct1_delta2_,
                                          Gamma_[i_],
                                          part_dec_[i_].w());

#endif
  }

  /* */
  inline
  void CL_Threshold_Static::decrypt_add_partial_dec(
      unsigned int j, const PartialDecryption & part_dec)
  {
    // Ensure j != i
    if (j == i_)
      throw std::invalid_argument(
          "decrypt_add_partial_dec: Cannot add self partial decryption");

    // Ensure j is a qualified player
    if (QualifiedPlayersSet_.find(j) == QualifiedPlayersSet_.end())
    {
      std::string playerStr{std::to_string(j)};
      throw std::invalid_argument("decrypt_add_partial_dec: " + playerStr
                                  + " is not a qualified player id");
    }
    // Check that j is NOT in S yet
    if (DecryptionPlayersSet_.find(j) != DecryptionPlayersSet_.end())
    {
      std::string playerStr{std::to_string(j)};
      throw ProtocolLogicError("decrypt_add_partial_dec: P" + playerStr
                               + " decryption was already added and verified");
    }

    // Store partial decrypt from j
    part_dec_.emplace(j, part_dec);
  }

  inline
  bool CL_Threshold_Static::decrypt_verify_player_decryption(
      const CL_HSMqk & CL_Hsmq,
      unsigned int j)
  {
    // Check that j is a qualified player
    if (QualifiedPlayersSet_.find(j) == QualifiedPlayersSet_.end())
    {
      std::string playerStr{std::to_string(j)};
      throw std::invalid_argument("decrypt_verify_player_decryption:"
                                  + playerStr
                                  + " is not a qualified player id");
    }

    // Check j is another player
    if (j == i_)
      throw std::invalid_argument(
          "decrypt_verify_player_decryption: Do not check own decryption");

    // If partial decryption not received, cannot verify
    if (part_dec_.find(j) == part_dec_.end())
      throw ProtocolLogicError("decrypt_verify_player_decryption: no partial "
                               "decryption received from this player");

    // Verify Pj's partial decryption. If successful, add j to S
    HashAlgo H{hash_algo()};
    bool is_pass = part_dec_.at(j).verify(
        CL_Hsmq, soundness_bytes_, h_delta2_, ct1_delta2_, Gamma_.at(j));

    if (is_pass)
      DecryptionPlayersSet_.insert(j);

    return is_pass;
  }

  /* */
  inline
  bool CL_Threshold_Static::decrypt_verify_batch(const CL_HSMqk & cl_hsmq,
                                                 RandGen & randgen)
  {
    // Check there are at least t+1 partial decryptions
    if (part_dec_.size() < t_ + 1u)
      throw ProtocolLogicError(
          "decrypt_verify_batch: t+1 partial decryptions are needed");

    // Check Gamma has at least t+1 elements
    // If not, this means the keygen phase was not properly executed
    if (Gamma_.size() < t_ + 1u)
      throw ProtocolLogicError(
          "decrypt_verify_batch: Cannot verify, Gamma values are missing");

    unsigned int k = 0u;
    // Iterator for part_dec_ map
    //   it->first  : player id
    //   it->second : PartialDecryption for player
    auto it = part_dec_.cbegin();

    //------------------------------------------------------------------------//
    // Valid proofs (u, R1, R2) are constructed such that:
    //  hd2^u    = R1*Gamma^ch
    //  ct1d2^u  = R2*w^ch
    // For each proof (u, R1, R2), verify that:
    //  hd2^(sum u[i]*e[i])   = \prod Gamma[i]^(ch[i]*e[i]) \prod R1[i]^(e[i])
    //  ct1d2^(sum u[i]*e[i]) = \prod     w[i]^(ch[i]*e[i]) \prod R2[i]^(e[i])
    //
    // With :
    //  - hd2   = h^(delta^2)
    //  - ct1d2 = ct1^(delta^2)
    //  - ch[i]: Hash-challenge for proof i
    //  - ei[i]: Random exponent for small exponent test
    //------------------------------------------------------------------------//

    // Compute hash-challenges
    HashAlgo H{hash_algo()};
    std::vector<Mpz> ch;
    ch.reserve(t_ + 1u);
    for (it = part_dec_.cbegin(), k=0u; k < t_ +1u; ++k, ++it)
    {
      ch.emplace_back(it->second.proof().hash_for_challenge(
          soundness_bytes_, h_delta2_, ct1_delta2_, Gamma_.at(it->first), it->second.w()));
    }


    // Sample t+1 ei with (soundness) bits
    std::vector<Mpz> ei;
    ei.reserve(t_ + 1u);
    for (k = 0u; k < t_ + 1u; ++k)
      ei.emplace_back(randgen.random_mpz_2exp(soundness_bytes_*8u));

    //----------------------------------------------------------//
    // Compute left-hand side
    //----------------------------------------------------------//
    // Compute exponent: sum u[i]*e[i]
    Mpz exponent{0UL};
    for (it = part_dec_.cbegin(), k = 0u; k < t_ + 1u; ++k, ++it)
      Mpz::addmul(exponent, it->second.proof().u_, ei[k]);

    // Compute h^(sum u[i]*e[i])
    //     and ct1^(sum u[i]*e[i])
    QFI hu, ct1u;
#ifdef BICYCL_WITH_PTHREADS
    // Multi-threaded version, use 6 threads
    std::thread threads[5u];

    // Make a pointer to nupow with wNAF*
    void (ClassGroup::*nupow_ptr)(QFI &, const QFI &, const Mpz &) const
        = &ClassGroup::nupow;

    // Compute both expos on other threads
    threads[3] = std::thread{nupow_ptr,
                             std::cref(cl_hsmq.Cl_G()),
                             std::ref(ct1u),
                             std::cref(ct1_delta2_),
                             std::cref(exponent)
                             };
    threads[4] = std::thread{nupow_ptr,
                             std::cref(cl_hsmq.Cl_G()),
                             std::ref(hu),
                             std::cref(h_delta2_),
                             std::cref(exponent)};

#else
    cl_hsmq.Cl_G().nupow(ct1u, ct1_delta2_, exponent);
    cl_hsmq.Cl_G().nupow(hu, h_delta2_, exponent);

#endif

    //----------------------------------------------------------//
    // Compute right-hand side
    //----------------------------------------------------------//
    // Compute exponents ch[i]*e[i]
    std::vector<Mpz> ei_chi;
    ei_chi.resize(t_ + 1u);
    for (k = 0u; k < t_ + 1u; ++k)
      Mpz::mul(ei_chi[k], ei[k], ch[k]);

    // Compute \prod (Gamma[i]^(ch[i]*e[i])) * \prod (R1[i]^(e[i]))
    //     and \prod (    w[i]^(ch[i]*e[i])) * \prod (R2[i]^(e[i]))
    const unsigned int wnaf_w = 6u; // w used in multi-expo wNAF
    auto it_end = it; // Store iterator to the t+1 th element of part_dec_
    QFI product_R1, product_Gamma, product_R2, product_w;

#ifdef BICYCL_WITH_PTHREADS
    // Divide the workload, one multi-expo per thread
    std::vector<QFI> fi[4u];
    for (unsigned int u = 0; u < 4u; ++u)
      fi[u].reserve(t_ + 1u);

    // Make a pointer to multi-exponentiaion nupow
    void (ClassGroup::*multi_exp_nupow)(
        QFI &, const std::vector<QFI> &, const std::vector<Mpz> &, unsigned int)
        const
        = &ClassGroup::nupow;

    // Multi-expo \prod R1[i]^(e[i]) on another thread
    for (it = part_dec_.cbegin(); it != it_end; ++it)
      fi[0].push_back(it->second.proof().R1_);
    threads[0] = std::thread{multi_exp_nupow,
                             std::cref(cl_hsmq.Cl_G()),
                             std::ref(product_R1),
                             std::cref(fi[0]),
                             std::cref(ei),
                             wnaf_w};

    // Multi-expo \prod Gamma[i]^(ch[i]*e[i]) on another thread
    for (it = part_dec_.cbegin(); it != it_end; ++it)
      fi[1].push_back(Gamma_[it->first]);
    threads[1] = std::thread{multi_exp_nupow,
                             std::cref(cl_hsmq.Cl_G()),
                             std::ref(product_Gamma),
                             std::cref(fi[1]),
                             std::cref(ei_chi),
                             wnaf_w};

    // Multi-expo \prod R2[i]^(e[i]) on another thread
    for (it = part_dec_.cbegin(); it != it_end; ++it)
      fi[2].push_back(it->second.proof().R2_);
    threads[2] = std::thread{multi_exp_nupow,
                             std::cref(cl_hsmq.Cl_G()),
                             std::ref(product_R2),
                             std::cref(fi[2]),
                             std::cref(ei),
                             wnaf_w};

    // Multi-expo \prod w[i]^(ch[i]*e[i]) on current thread
    for (it = part_dec_.cbegin(); it != it_end; ++it)
      fi[3].push_back(it->second.w());
    cl_hsmq.Cl_G().nupow(product_w, fi[3], ei_chi, wnaf_w);

    // Wait for the other threads to finish
    for (unsigned int u = 0u; u < 5u; ++u)
      threads[u].join();

#else
    // Single-threaded version

    // Copying exponent bases into fi results in... well, many copies.
    // But I don't see a better way of doing this, and the performance is good
    std::vector<QFI> fi; // Vector of the bases for multi-expo
    fi.reserve(t_ + 1u);

    // Multi-expo \prod R1[i]^(e[i])
    for (it = part_dec_.cbegin(); it != it_end; ++it)
      fi.push_back(it->second.proof().R1_);
    cl_hsmq.Cl_G().nupow(product_R1, fi, ei, wnaf_w);

    // Multi-expo \prod Gamma[i]^(ch[i]*e[i])
    for (it = part_dec_.cbegin(), k=0u; it != it_end; ++k, ++it)
      fi[k] = Gamma_[it->first];
    cl_hsmq.Cl_G().nupow(product_Gamma, fi, ei_chi, wnaf_w);

    // Multi-expo \prod R2[i]^(e[i])
    for (it = part_dec_.cbegin(), k=0u; it != it_end; ++k, ++it)
      fi[k] = it->second.proof().R2_;
    cl_hsmq.Cl_G().nupow(product_R2, fi, ei, wnaf_w);

    // Multi-expo \prod w[i]^(ch[i]*e[i])
    for (it = part_dec_.cbegin(), k=0u; it != it_end; ++k, ++it)
      fi[k] = it->second.w();
    cl_hsmq.Cl_G().nupow(product_w, fi, ei_chi, wnaf_w);

#endif
    cl_hsmq.Cl_G().nucomp(product_Gamma, product_Gamma, product_R1);
    cl_hsmq.Cl_G().nucomp(product_w, product_w, product_R2);

    //----------------------------------------------------------//
    // Verify the values match
    //----------------------------------------------------------//
    bool verify_pass = (hu == product_Gamma) && (ct1u == product_w);

    // If proof is verified, add all verified players to S
    if (verify_pass)
    {
      for (it = part_dec_.cbegin(); it != it_end; ++it)
        DecryptionPlayersSet_.insert(it->first);
    }

    return verify_pass;
  }

  /* */
  inline
  void CL_Threshold_Static::decrypt_combine(ClearText & m,
                                            const CL_HSMqk & CL_Hsmq,
                                            const CipherText & ct)
  {
    // t+1 partial decryptions are needed to reconstruct the secret
    if (DecryptionPlayersSet_.size() < t_ + 1u)
      throw ProtocolLogicError("decrypt_combine: t+1 verified decryptions are "
                               "needed before trying to jointly decrypt");

    // Keep the first t+1 values of S
    if (DecryptionPlayersSet_.size() > t_+1u)
    {
      auto it = DecryptionPlayersSet_.cbegin();
      std::advance(it, DecryptionPlayersSet_.size() - t_ - 1u);
      DecryptionPlayersSet_.erase(DecryptionPlayersSet_.cbegin(), it);
    }

    //----------------------------------------------------------//
    // Compute W from partial decryptions
    //----------------------------------------------------------//
    std::vector<QFI> W_parts;

    // compute_W : compute W = \prod{j} wj^Lj0 for a subset of players
    auto compute_W
        = [this, &CL_Hsmq, &W_parts] (ParticipantsSet::const_iterator start,
                                      ParticipantsSet::const_iterator end,
                                      unsigned int thread_id = 0u) {
            QFI & W_part = W_parts.at(thread_id);

            // Prepare data for multi-expo
            size_t nb_players = std::distance(start, end);
            std::vector<Mpz> Lj0s;
            std::vector<QFI> wjs;
            Lj0s.reserve(nb_players);
            wjs.reserve(nb_players);
            Mpz Lj0;
            for (auto it = start; it != end; ++it)
            {
              lagrange_at_zero(Lj0, *it);
              Lj0s.emplace_back(Lj0);
              wjs.emplace_back(part_dec_.at(*it).w());
            }
            // Multi-expo W-part = \prod{j} wj^Lj0
            // OPTIMIZE could coarse-tune w
            CL_Hsmq.Cl_G().nupow(W_part, wjs, Lj0s, 5u);
          };

#ifdef BICYCL_WITH_PTHREADS
    // Multi-threaded version

    if (DecryptionPlayersSet_.size() < 2*NB_THREADS_)
    {
      // Less than 2 expos per thread, compute W on a single thread
      W_parts.push_back(CL_Hsmq.Cl_G().one());
      compute_W(DecryptionPlayersSet_.cbegin(), DecryptionPlayersSet_.cend());
    }
    else
    {
      // Compute W over multiple threads
      W_parts.resize(NB_THREADS_, CL_Hsmq.Cl_G().one());
      run_over_threads(compute_W,
                       NB_THREADS_,
                       DecryptionPlayersSet_.cbegin(),
                       DecryptionPlayersSet_.cend());

      // Compute W from parts
      for (unsigned int u = 1; u < NB_THREADS_; ++u)
      {
        CL_Hsmq.Cl_G().nucomp(W_parts[0], W_parts[0], W_parts[u]);
      }
    }

#else
    W_parts.push_back(CL_Hsmq.Cl_G().one());
    compute_W(DecryptionPlayersSet_.cbegin(), DecryptionPlayersSet_.cend());

#endif
    const QFI & W = W_parts[0];

    //----------------------------------------------------------//
    // Compute M = ct2^(delta^2)*W^(-1)
    //----------------------------------------------------------//

    QFI M;
    CL_Hsmq.Cl_G().nupow(M, ct.c2(), delta2_);
    CL_Hsmq.Cl_G().nucompinv(M, M, W);

    //----------------------------------------------------------//
    // Compute DLog(M) if it is possible
    //----------------------------------------------------------//
    try
    {
      m = ClearText(CL_Hsmq, CL_Hsmq.dlog_in_F(M));
    }
    catch (const std::invalid_argument & except)
    {
      throw ProtocolAbortError("decrypt_combine: DLog could not be solved");
    }

    //----------------------------------------------------------//
    // Compute m = DLog(M) * delta^(-2)  mod q
    //----------------------------------------------------------//
    Mpz::mul(m, m, delta2_inv_);
    Mpz::mod(m, m, CL_Hsmq.q());
  }

  /* */
  inline
  void CL_Threshold_Static::lagrange_at_zero(
      Mpz & Lj0, unsigned int j) const
  {
    Lj0 = delta_; // Delta = N! ensures the evaluation is an integer
    j++;          // Offset by one to get non-zero ids

    bool result_is_neg = false; // Keep track of result sign, handle at the end
    for (unsigned int k : DecryptionPlayersSet_)
    {
      k++;                      // Offset by one to get non-zero ids
      if (k == j) continue;     // for k != j

      if (k > j)                // Div by abs(k-j)
      {                         // Div is exact thanks to delta)
        Mpz::divexact(Lj0, Lj0, k - j);
      }
      else
      {
        result_is_neg = !result_is_neg; // Flip the sign
        Mpz::divexact(Lj0, Lj0, j - k);
      }
      Mpz::mul(Lj0, Lj0, k);            // Mult by k
    }

    if (result_is_neg) Lj0.neg();
  }

  /* */
  inline
  size_t CL_Threshold_Static::poly_coeff_bitsize_bound(const CL_HSMqk & CL_Hsmq) const
  {
    return (CL_Hsmq.lambda_distance() + CL_Hsmq.secretkey_bound().nbits()
            + delta_.nbits() + 2u * nbits(t_ + 1u) + 3u);
  }

  /* */
  inline
  HashAlgo CL_Threshold_Static::hash_algo() const {
    if (soundness_bytes_ <= 128u)
      return HashAlgo{HashAlgo::SHAKE128, soundness_bytes_};
    else
      return HashAlgo{HashAlgo::SHAKE256, soundness_bytes_};
  }

  /* */
  /*
   * Faster keygen_extract with Gamma already computed.
   */
  inline
  void CL_Threshold_Static::keygen_extract_for_benchs(
      const CL_HSMqk & CL_Hsmq, const ParticipantsValueMap<QFI> & Gamma)
  {
    // Check shares were received from every other valid player
    if (y_others_.size() < (QualifiedPlayersSet_.size() - 1u))
      throw ProtocolLogicError(
          "keygen_extract: missing shares from other players");

    // Check commitments were received from every other valid player
    if (C_.size() < QualifiedPlayersSet_.size())
      throw ProtocolLogicError(
          "keygen_extract: missing commitments from other players");
    // Check all complaints have been resolved
    if (ComplaintsSet_.size() != 0)
      throw ProtocolLogicError(
          "keygen_extract: some complaints have not been resolved");

    //----------------------------------------------------------//
    // Compute public key
    // pkcl = (C10 * C20 * ... * Ci0 * ... * Cn0) ^ delta2
    //----------------------------------------------------------//
    QFI pk_temp;
    for (unsigned int j : QualifiedPlayersSet_)
    {
      CL_Hsmq.Cl_G().nucomp(pk_temp, pk_temp, C_[j][0]);
    }
    CL_Hsmq.Cl_G().nupow(pk_temp, pk_temp, delta2_);
    pk_ = CL_Threshold_Static::PublicKey(CL_Hsmq, pk_temp);

    //----------------------------------------------------------//
    // Compute Shamir-share of private key
    // sk_share = y1i + y2i + ... + yii + ... + yni
    //----------------------------------------------------------//
    sk_share_ = y_self_[i_];
    for (unsigned int player_j : QualifiedPlayersSet_)
    {
      if (i_ == player_j) continue;
      Mpz::add(sk_share_, sk_share_, y_others_[player_j]);
    }

    //----------------------------------------------------------//
    // Copy Gamma values
    //----------------------------------------------------------//
    Gamma_ = Gamma;
  }
}

#endif /* BICYCL_CL_CL_THRESHOLD_INL */