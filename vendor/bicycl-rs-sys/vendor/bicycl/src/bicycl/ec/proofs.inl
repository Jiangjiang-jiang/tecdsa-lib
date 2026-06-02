/*
 * BICYCL Implements CryptographY in CLass groups
 * Copyright (C) 2022  Cyril Bouvier <cyril.bouvier@lirmm.fr>
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
#ifndef BICYCL_ECNIZK_PROOFS_INL
#define BICYCL_ECNIZK_PROOFS_INL

#include "proofs.hpp"

namespace BICYCL
{
  /* */
  inline
  ECNIZKProof::ECNIZKProof (const ECGroup &E, HashAlgo &H, RandGen & randgen,
                            const SecretValue &s, const PublicValue &Q,
                            const Mpz & sid)
    : R_(E)
  {
    BN r (E.random_mod_order(randgen));
    E.scal_mul_gen (R_, r);

    BN c (hash_for_challenge (H, E, R_, Q, sid)); /* c = Hash (E, R_, Q) */

    E.mul_mod_order (z_, c, s);
    E.sub_mod_order (z_, r, z_); /* z = r - c*s */
  }

  /* */
  inline
  ECNIZKProof::ECNIZKProof (const ECGroup &E, HashAlgo &H, RandGen & randgen,
                            const SecretValue &s)
    : ECNIZKProof (E, H, randgen, s, compute_Q_from_secret (E, s))
  {
  }

  /* */
  inline ECNIZKProof::ECNIZKProof(const ECGroup & E,
                                  const ECPoint & R,
                                  const BN & z)
    : R_(E, R),
      z_(z)
  {
  }

  /* */
  inline ECNIZKProof::ECNIZKProof(const ECGroup & E,
                                  const BN & Rx,
                                  const BN & Ry,
                                  const BN & z)
    : R_(E, Rx, Ry),
      z_(z)
  {
  }

  /* */
  inline
  ECNIZKProof::ECNIZKProof (const ECGroup &E, const ECNIZKProof &p)
    : ECNIZKProof(E, p.R_, p.z_)
  {
  }

  /* */
  inline
  ECNIZKProof::ECNIZKProof (const ECGroup &E)
    : R_ (E)
  {
  }

  inline
  const ECPoint & ECNIZKProof::R() const
  {
    return R_;
  }

  inline
  const BN & ECNIZKProof::z() const
  {
    return z_;
  }

  /* */
  inline
  bool ECNIZKProof::verify (const ECGroup &E, HashAlgo &H,
                            const PublicValue &Q, const Mpz & sid) const
  {
    if (!E.is_in_group (Q))
      return false;

    BN c (hash_for_challenge (H, E, R_, Q, sid)); /* c = Hash (E, R_, Q) */

    ECPoint rhs (E);
    E.scal_mul (rhs, z_, c, Q); /* z*P + cQ */

    return E.ec_point_eq (R_, rhs);
  }

  /* */
  inline
  BN ECNIZKProof::hash_for_challenge (HashAlgo & H,
                                      const ECGroup &E,
                                      const ECPoint &R,
                                      const ECPoint &Q,
                                      const Mpz &sid)
  {
    return BN (H (E, ECPointGroupCRefPair (R, E),
                              ECPointGroupCRefPair (Q, E), sid));
  }

  /* */
  inline
  ECPoint ECNIZKProof::compute_Q_from_secret (const ECGroup &E,
                                                      const SecretValue &s)
  {
    ECPoint Q (E);
    E.scal_mul_gen (Q, s);
    return Q;
  }

  /******************************************************************************/
  /* */
  inline
  ECNIZKAoK::ECNIZKAoK (const ECGroup &E, HashAlgo &H, RandGen & randgen,
                        const ECPoint & R, const SecretValue &x,
                        const SecretValue &y, const SecretValue &rho,
                        const PublicValue &V, const PublicValue &A)
    : H_(E)
  {
    BN v (E.random_mod_order(randgen));
    BN u (E.random_mod_order(randgen));

    E.scal_mul (H_, v, u, R); /* H = u R + v P */

    /* c = Hash(E, R, V, A, H) */
    BN c (hash_for_challenge (H, E, R, V, A, H_));

    E.mul_mod_order (t1_, c, x);
    E.add_mod_order (t1_, t1_, u); /* t1 = u + c * x */

    E.mul_mod_order (t2_, c, y);
    E.mul_mod_order (u, c, c); /* use u as temp var */
    E.mul_mod_order (u, u, rho); /* use u as temp var */
    E.add_mod_order (t2_, t2_, u);
    E.add_mod_order (t2_, t2_, v); /* t2 = v + c*y + c^2 * rho */
  }

  /* */
  inline
  ECNIZKAoK::ECNIZKAoK (const ECGroup &E, const ECNIZKAoK &p)
    : H_ (E, p.H_), t1_(p.t1_), t2_(p.t2_)
  {
  }

  /* */
  inline
  bool ECNIZKAoK::verify (const ECGroup &E, HashAlgo &H,
                          const ECPoint & R, const PublicValue &V,
                          const PublicValue &A) const
  {
    /* c = Hash(E, R, V, A, H) */
    BN c (hash_for_challenge (H, E, R, V, A, H_));

    ECPoint lhs (E);
    ECPoint rhs (E);

    E.scal_mul (lhs, t2_, t1_, R); /* t1 R + t2 P */

    E.scal_mul (rhs, c, A);
    E.ec_add (rhs, V, rhs);
    E.scal_mul (rhs, c, rhs);
    E.ec_add (rhs, rhs, H_); /* c V + c^2 A + H */

    return E.ec_point_eq (lhs, rhs);
  }

  /* */
  inline
  BN ECNIZKAoK::hash_for_challenge (HashAlgo &Hash,
                                            const ECGroup &E,
                                            const ECPoint &R,
                                            const ECPoint &V,
                                            const ECPoint &A,
                                            const ECPoint &H)
  {
    return BN (Hash (E, ECPointGroupCRefPair (R, E),
                                ECPointGroupCRefPair (V, E),
                                ECPointGroupCRefPair (A, E),
                                ECPointGroupCRefPair (H, E)));
  }

}

#endif /* BICYCL_ECNIZK_PROOFS_INL */