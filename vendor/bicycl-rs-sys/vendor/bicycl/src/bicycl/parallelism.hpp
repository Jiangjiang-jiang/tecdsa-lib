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

/**
 * @file parallelism.hpp
 * Utily functions for data parallelism
 *
 */

#ifndef BICYCL_PARALLELISM_HPP
#define BICYCL_PARALLELISM_HPP

#ifdef BICYCL_WITH_PTHREADS

  #include <iterator>
  #include <thread>
  #include <vector>

namespace BICYCL
{

/**
 * @brief Run a task with data-parallelism, where data is an STL container.
 *
 * @see CL_threshold.inl for examples.
 *
 * @tparam F callable type
 * @tparam Iterator An STL container iterator type
 * @param[in] task
 *   Task to run in parallel.\n
 *   It must be a callable object (function, lambda. etc.)
 *   with exactly three arguments in the following order:\n
 *   - <tt><b>Iterator</b> start</tt> : start of the data range to operate on
 *   - <tt><b>Iterator</b> end</tt> : end of the data range to operate on
 *   - <tt>unsigned int id</tt> : thread id (between 1 and @p nb_threads )
 *   .
 *   For instance: a function pointer of type <tt>void (*)(Iterator, Iterator, unsigned int)</tt>
 * @param[in] nb_threads Number of threads to run the function on. Must be at least 2.
 * @param[in] it_start Iterator to the start of the data (ex. data.cbegin())
 * @param[in] it_end Iterator to the end of the data (ex. data.cend())
 * @exception std::invalid_argument if @p nb_threads \f$>2\f$,
 * or @p it_start @p it_end are the same iterator
 */
template <typename F, typename Iterator> void run_over_threads (
    F task, unsigned int nb_threads, Iterator it_start, Iterator it_end)
{
  if (nb_threads < 2)
    throw std::invalid_argument("divide_workload: nb_threads must be > 2");

  if (it_start == it_end)
    throw std::invalid_argument(
        "divide_workload: work_start and work_end must be different iterators");

  size_t worksize = std::distance(it_start, it_end);

  if (worksize == 1)
  {
    // No need for parallelism, run on one thread
    task(it_start, it_end, 0);
  }
  else
  {
    if (worksize < nb_threads)
    {
      // worksize is small, adapt nb_threads to process 1 data per thread
      nb_threads = worksize;
    }

    // Divide the workload
    std::vector<std::thread> threads(nb_threads - 1u);
    const size_t per_thread = (worksize + nb_threads - 1u) / nb_threads;
    const size_t remainder = nb_threads * per_thread - worksize;
    Iterator start = it_start;
    Iterator end = start;

    unsigned int u = 0u;
    for (; u < nb_threads - ((remainder == 0) ? 1 : remainder); ++u)
    {
      std::advance(end, per_thread);
      threads[u] = std::thread(task, start, end, u);
      std::advance(start, per_thread);
    }
    for (; u < nb_threads - 1; ++u)
    {
      std::advance(end, per_thread - 1);
      threads[u] = std::thread(task, start, end, u);
      std::advance(start, per_thread - 1);
    }
    // Handle remaining work in main thread
    end = it_end;
    task(start, end, u);

    // Wait until all threads finish
    for (u = 0; u < nb_threads - 1; ++u) threads[u].join();
  }
}

/**
 * @brief Run a task with data-parallelism, where data is an array or a sequence container.
 * @see CL_threshold.inl for examples.
 *
 * @tparam F callable type
 * @param[in] task
 *   Task to run in parallel.\n
 *   It must be a callable object (function, lambda. etc.)
 *   with exactly three arguments in the following order:\n
 *   - <tt>unsigned int start</tt> : start of the data range to operate on
 *   - <tt>unsigned int end</tt> : end of the data range to operate on
 *   - <tt>unsigned int id</tt> : thread id (between 1 and @p nb_threads )
 *   .
 *   For instance: a function pointer of type <tt>void (*)(unsigned int, unsigned int, unsigned int)</tt>
 * @param[in] nb_threads Number of threads to run the function on. Must be at least 2.
 * @param[in] idx_start Index to the start of the data
 * @param[in] idx_end Index to the end of the data
 * @exception std::invalid_argument if @p nb_threads \f$>2\f$, or @p idx_start \f$<\f$ @p idx_end
 */
template <typename F> void run_over_threads (F task,
                                             unsigned int nb_threads,
                                             size_t idx_start,
                                             size_t idx_end)
{
  if (nb_threads < 2)
    throw std::invalid_argument("divide_workload: nb_threads must be > 2");

  long worksize = idx_end - idx_start;
  if (worksize <= 0)
    throw std::invalid_argument(
        "divide_workload: start/end indexes are invalid");

  if (worksize == 1)
  {
    // No need for parallelism, run on one thread
    task(idx_start, idx_end, 0);
  }
  else
  {
    if (worksize < nb_threads)
    {
      // worksize is small, adapt nb_threads to process 1 data per thread
      nb_threads = worksize;
    }

    // Divide the workload
    std::vector<std::thread> threads(nb_threads - 1u);
    const size_t per_thread = (worksize + nb_threads - 1u) / nb_threads;
    const size_t remainder = nb_threads * per_thread - worksize;
    unsigned int start = idx_start;
    unsigned int end = start;

    unsigned int u = 0u;
    for (; u < nb_threads - ((remainder == 0) ? 1 : remainder); ++u)
    {
      end += per_thread;
      threads[u] = std::thread(task, start, end, u);
      start += per_thread;
    }
    for (; u < nb_threads - 1; ++u)
    {
      end += per_thread-1;
      threads[u] = std::thread(task, start, end, u);
      start += per_thread-1;
    }
    // Handle remaining work in main thread
    end = idx_end;
    task(start, end, u);

    // Wait until all threads finish
    for (u = 0; u < nb_threads - 1; ++u) threads[u].join();
  }
}

}

#endif // BICYCL_WITH_PTHREADS

#endif // BICYCL_PARALLELISM_HPP