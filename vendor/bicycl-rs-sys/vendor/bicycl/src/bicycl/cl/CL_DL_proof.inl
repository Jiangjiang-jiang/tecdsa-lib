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
#ifndef BICYCL_CL_CL_DL_PROOF_INL
#define BICYCL_CL_CL_DL_PROOF_INL

#include "CL_DL_proof.hpp"

namespace BICYCL
{
  /**
   * CLDLZKProof default contructor
   *
   **/
  inline
  CLDLZKProof::CLDLZKProof(const ECGroup & ec_group)
    : R_{ec_group}
  {
    // Nothing to do
  }

  /**
   * CLDLZKProof contructor
   *
   **/
  inline
  CLDLZKProof::CLDLZKProof(const ECGroup & ec_group,
                           const ECPoint & R,
                           const Mpz & u1,
                           const Mpz & u2,
                           const Mpz & chl)
    : R_{ec_group, R},
      u1_{u1},
      u2_{u2},
      chl_{chl}
  {
    // Nothing to do
  }

  /**
   * CLDLZKProof contructor
   *
   **/
  inline
  CLDLZKProof::CLDLZKProof(HashAlgo & H,
                           const ECGroup & ec_group,
                           const SecretValue & x,
                           const PublicValue & Q,
                           const CL_HSMqk & C,
                           const CL_HSMqk::PublicKey & pk,
                           const CL_HSMqk::CipherText & cyphtext,
                           const Mpz & r,
                           RandGen & randgen)
    : R_{ec_group}
  {
    int soundness = H.digest_nbits();

    // Compute r1 randomness bound
    Mpz B(C.encrypt_randomness_bound());     // B = S
    Mpz::mulby2k(B, B, soundness);           // B = S * 2^soundness
    Mpz::mulby2k(B, B, C.lambda_distance()); // B = S * 2^soundness * 2^dist

    // Sample r1, r2
    Mpz r1(randgen.random_mpz(B));
    Mpz r2(randgen.random_mpz(C.M()));
    // Compute t1, t2
    CL_HSMqk::CipherText t(C, pk, CL_HSMqk::ClearText(C, r2), r1);

    // Compute R
    ec_group.scal_mul_gen(R_, BN(r2));

    // Compute hash-challenge
    chl_ = hash_for_challenge(H, ec_group, Q, pk, cyphtext, t.c1(), t.c2());

    Mpz::mul(u1_, chl_, r);
    Mpz::add(u1_, u1_, r1);

    Mpz::mul(u2_, chl_, static_cast<Mpz>(x));
    Mpz::add(u2_, u2_, r2);
    Mpz::mod(u2_, u2_, C.M());
  }

#ifdef BICYCL_WITH_PTHREADS
  /**
   * CLDLZKProof contructor
   *
   **/
  inline
  CLDLZKProof::CLDLZKProof(HashAlgo & H,
                           const ECGroup & ec_group,
                           const SecretValue & x,
                           const PublicValue & Q,
                           const CL_HSMqk & C,
                           const CL_HSMqk::PublicKey & pk,
                           const CL_HSMqk::CipherText & cyphtext,
                           const Mpz & r,
                           RandGen & randgen,
                           std::thread & thread_ckey)
    : R_{ec_group}
  {
    int soundness = H.digest_nbits();

    // Compute r1 randomness bound
    Mpz B(C.encrypt_randomness_bound());     // B = S
    Mpz::mulby2k(B, B, soundness);           // B = S * 2^soundness
    Mpz::mulby2k(B, B, C.lambda_distance()); // B = S * 2^soundness * 2^dist

    // Sample r1, r2
    Mpz r1(randgen.random_mpz(B));
    Mpz r2(randgen.random_mpz(C.M()));
    // Compute t1, t2
    CL_HSMqk::CipherText t(C, pk, CL_HSMqk::ClearText(C, r2), r1);

    // Compute R
    ec_group.scal_mul_gen(R_, BN(r2));

    // Ensure Ckey computation is done
    thread_ckey.join();

    // Compute hash-challenge
    chl_ = hash_for_challenge(H, ec_group, Q, pk, cyphtext, t.c1(), t.c2());

    Mpz::mul(u1_, chl_, r);
    Mpz::add(u1_, u1_, r1);

    Mpz::mul(u2_, chl_, static_cast<Mpz>(x));
    Mpz::add(u2_, u2_, r2);
    Mpz::mod(u2_, u2_, C.M());
  }
#endif

  /**
   * Getters
   */
  inline const ECPoint & CLDLZKProof::R() const
  {
    return R_;
  }
  inline const Mpz & CLDLZKProof::u1() const
  {
    return u1_;
  }
  inline const Mpz & CLDLZKProof::u2() const
  {
    return u2_;
  }
  inline const Mpz & CLDLZKProof::chl() const
  {
    return chl_;
  }


  /**
   * Verify
   *
   **/
  inline
  bool CLDLZKProof::verify(HashAlgo & H,
                           const ECGroup & E,
                           const PublicValue & Q,
                           const CL_HSMqk & C,
                           const CL_HSMqk::PublicKey & pk,
                           const CL_HSMqk::CipherText & cyphtext) const
  {
    bool ret = true;

    /* Check that Q belongs to E*/
    if (!E.is_in_group(Q))
      return false;

    int soundness = H.digest_nbits();

    // TODO early return if checks fail
    /* Check that pk is a form in G */
    ret &= pk.elt().discriminant() == C.Cl_G().discriminant();
    ret &= C.genus(pk.elt()) == CL_HSMqk::Genus({1, 1});

    /* Check that c1 is a form in G */
    ret &= cyphtext.c1().discriminant() == C.Cl_G().discriminant();
    ret &= C.genus(cyphtext.c1()) == CL_HSMqk::Genus({1, 1});

    /* Check that c2 is a form in G */
    ret &= cyphtext.c2().discriminant() == C.Cl_Delta().discriminant();
    ret &= C.genus(cyphtext.c2()) == CL_HSMqk::Genus({1, 1});

    /* Check u1 bound */
    Mpz B(1UL);
    Mpz::mulby2k(B, B, C.lambda_distance());
    Mpz::add(B, B, 1UL);
    Mpz::mulby2k(B, B, soundness);
    Mpz::mul(B, B, C.encrypt_randomness_bound());
    ret &= (u1_.sgn() >= 0 && u1_ <= B);

    /* Check u2 bound */
    ret &= (u2_.sgn() >= 0 && u2_ < C.M());

    /* cu = (gq^u1, pk^u1 f^u2) */

#ifdef BICYCL_WITH_PTHREADS
    // Compute cu in a separate tread

    auto compute_cu = [this, &C, &pk] (CL_HSMqk::CipherText & cu) {
      cu = CL_HSMqk::CipherText(C, pk, CL_HSMqk::ClearText(C, u2_), u1_);
    };

    CL_HSMqk::CipherText cu;
    std::thread th(compute_cu, std::ref(cu));
#else
    CL_HSMqk::CipherText cu(C, pk, CL_HSMqk::ClearText(C, u2_), u1_);
#endif

    /* ck = (c1^k, c2^k) */
    CL_HSMqk::CipherText ck(C.scal_ciphertexts(pk, cyphtext, chl_, Mpz(0UL)));

#ifdef BICYCL_WITH_PTHREADS
    // Wait until cu computation is done
    th.join();
#endif

    QFI t1, t2;

    /* Using the equality gq^u1 == t1*c1^k to compute t1 */
    C.Cl_G().nucompinv(t1, cu.c1(), ck.c1());

    /* Using the equality pk^u1 f^u2 == t2*c2^k to compute t2 */
    C.Cl_Delta().nucompinv(t2, cu.c2(), ck.c2());

    /* Generate chl using hash function and check that it matches */
    Mpz chl{hash_for_challenge(H, E, Q, pk, cyphtext, t1, t2)};

    ret &= (chl == chl_);

    /* Verify dicrete log knowledge */
    ECPoint R_retreived(E);
    BN chl_neg = BN(chl);
    chl_neg.neg();
    E.scal_mul(R_retreived, BN(u2_), chl_neg, Q); /* u2*P - chl*Q */
    ret &= E.ec_point_eq(R_, R_retreived);

    return ret;
  }

  /**
   * Hash for challenge util
   *
   **/
  inline
  Mpz CLDLZKProof::hash_for_challenge(HashAlgo & H,
                                      const ECGroup & E,
                                      const PublicValue & Q,
                                      const CL_HSMqk::PublicKey & pk,
                                      const CL_HSMqk::CipherText & c,
                                      const QFI & t1,
                                      const QFI & t2) const
  {
    return Mpz(H(E,
                 ECPointGroupCRefPair(Q, E),
                 ECPointGroupCRefPair(R_, E),
                 pk,
                 c,
                 t1,
                 t2));
  }

} /* namespace BICYCL */

#endif /* BICYCL_CL_CL_DL_PROOF_INL */