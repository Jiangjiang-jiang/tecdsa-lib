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
#include <string>
#include <sstream>

#include "bicycl.hpp"
#include "internals.hpp"

using namespace BICYCL;
using BICYCL::Bench::ms;
using BICYCL::Bench::us;

/* Needed to make protected methods public */
class BenchQFI : public QFI
{
  public:
    using QFI::nupow;
};

/* */
template <class Cryptosystem>
void CL_HSMqk_benchs_nupow_wnaf (const Cryptosystem & C,
                                 RandGen & randgen,
                                 const std::string & pre,
                                 size_t exp_bits,
                                 unsigned int w_low,
                                 unsigned int w_high,
                                 unsigned int niter)
{
  std::stringstream desc;
  desc << pre << std::setw(4) << exp_bits << "  ";

  QFI::OpsAuxVars tmp;
  QFI r, r2, f;
  unsigned int w;

  /* Generate random form */
  f = C.Cl_G().random (randgen);
  const Mpz &bound = C.Cl_G().default_nucomp_bound();

  /* Generate niter random exponents */
  std::vector<Mpz> n;
  for (unsigned int k=0u; k < niter; ++k)
    n.emplace_back(randgen.random_mpz_2exp(exp_bits));

  unsigned int i;

  /* nupow */
  auto nupow = [&r, &f, &n, &bound, &w, &i ] ()
  {
    BenchQFI::nupow (r, f, n[i], bound, w);
    ++i;
  };

  for (w=w_low; w <= w_high; w++)
  {
    i = 0u;
    Bench::one_function<ms, ms> (nupow, niter, std::to_string(w), desc.str());
  }
}

/* */
int
main (int argc, char *argv[])
{
  RandGen randgen;
  randseed_from_argv (randgen, argc, argv);

  Bench::print_thread_info();

  std::cout << "operation |  n bits |   wnaf w size   |"
            << "   time   |  time per op.  | std. dev." << std::endl;

  const SecLevel seclevel{SecLevel::_128};

  /* With a random q twice as big as the security level */
  CL_HSMqk C (2*seclevel.nbits(), 1, seclevel, randgen);

  std::stringstream pre;
  pre << "  nupow   |  ";

  /* Test exponents with bit size 10 to 100 */
  for(unsigned int exp_bits = 10u; exp_bits <= 100u; exp_bits+=10u)
  {
    CL_HSMqk_benchs_nupow_wnaf (C, randgen, pre.str(), exp_bits, 2, 6, 1000);
    std::cout << std::endl;
  }

  /* Test exponents with bit size 200 to 2000 */
  for(unsigned int exp_bits = 200u; exp_bits <= 2000u; exp_bits+=100u)
  {
    CL_HSMqk_benchs_nupow_wnaf (C, randgen, pre.str(), exp_bits, 4, 8, 100);
    std::cout << std::endl;
  }

  /* Test exponents with bit size 2000 to 10000 */
  for(unsigned int exp_bits = 3000u; exp_bits <= 10000u; exp_bits+=1000u)
  {
    CL_HSMqk_benchs_nupow_wnaf (C, randgen, pre.str(), exp_bits, 6, 11, 10);
    std::cout << std::endl;
  }



  return EXIT_SUCCESS;
}
