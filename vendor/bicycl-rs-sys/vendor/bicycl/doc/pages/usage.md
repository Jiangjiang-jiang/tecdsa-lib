# Usage {#usage}
\tableofcontents

## Tests {#tests}


To test the code, run the following command in the `build` directory:

    make check

## Benchmarks {#benchmarks}
BICYCL provides benchmarks for the implemented protocols. The benchmarks measure the computational time of protocol operations, they do not consider network latency.

### Running the benchmarks
To run a specific benchmark, enter the following command in the `build` directory:

    make benchmark_<benchmark_name>

Change `<benchmark_name>` to select a protocol to measure. The main benchmarks names and descriptions can be found in the following table.

##### Main benchmarks with description and # of threads
Benchmark name  | Threads used  | Benchmark description                                                                                          |
--------------- | -----------   | -------------------------------------------------------------------------------------------------------------- |
CL_HSMqk        | 2             | BICYCL::CL_HSMqk cryptosystem setup, encryption, decryption, and operations on quadratic forms (nucomp, nupow) |
CL_HSM2k        | 2             | BICYCL::CL_HSM2k cryptosystem setup, encryption, decryption, and operations on quadratic forms (nucomp, nupow) |
CL_Threshold    | 8             | BICYCL::CL_Threshold_Static keygen and threshold decryption                                                    |
twoParty_ECDSA  | 4             | BICYCL::TwoPartyECDSA keygen and signature                                                                     |
threshold_ECDSA | 1             | BICYCL::thresholdECDSA keygen and threshold signature                                                          |
Paillier        | 2             | BICYCL::Paillier cryptosystem setup, encryption, decryption with Paillier                                      |
JoyeLibert      | 1             | BICYCL::JoyeLibert cryptosystem setup, encryption, decryption with JoyeLibert                                  |

To run all benchmarks, enter the following command in the `build` directory:

    make benchs

To build the benchmarks (but not run them), enter the following command in the `build` directory:

    make benchs_build

When built, the benchmarks can then be run using the following command in the `build` directory:

    ./benchs/benchmark_<benchmark_name>

Timings per operation are displayed on the standard output.

\note To get the best timings out of the benchmarks, make sure that your OS's "Power Saver" is not enabled, as it tends to slow down computations.

### Benchmarking with single or multiple threads
BICYCL makes use of the multi-threading environment on your machine to perform some computations faster. Benchmarks can be run in single-thread or multi-thread.

By default, BICYCL uses multi-threading. The benchmark computations are performed over multiple-threads.

To run the benchmarks on a single thread, first call `cmake` with the `-DWITH_THREADS=OFF` option, in the `build` directory:

    cmake -DWITH_THREADS=OFF ..

Then run the benchmarks as described \ref benchmarks "in the above section". They will now be run on a single thread.

To revert to using multiple threads, call `cmake` again without the option:

    cmake ..

\see \ref build_from_source "Building from source" for more cmake options.


## Using BICYCL in your implementation {#using_bicycl}

First follow the instructions to \ref install "install the library".

Once BICYCL is installed on your system, include it in your program with :

    #include "bicycl.hpp"

All classes and functions are in the BICYCL namespace. To access them, use the prefix `BICYCL::`.
For instance, to setup a CL_HSMqk cryptosystem :

    BICYCL::CL_HSMqk (q, k, seclevel, randgen);

Alternatively, use the `namespace` directive for the prefix to be implicit:

    using namespace BICYCL;

\htmlonly
To take a look at the classes and functions of BICYCL, start with the <a href="topics.html">Topics</a> page.
\endhtmlonly

The example files are a good starting point if you want to use BICYCL in your implementation. They are found in the `examples` directory.

\htmlonly
You can also find a list of examples on the <a href="examples.html">Examples</a> page.
\endhtmlonly

## Running examples {#run_examples}

Some examples can be found in the `examples` directory of the source tree.
The examples can be compiled and run, and show the output of the implemented protocols.

To compile all the examples, run the following command in the `build` directory:

    make examples

To compile only a specific example (`CL_HSMqk_example` in this case), run the
following command in the `build` directory:

    make CL_HSMqk_example

The examples can then be run using the following command in the `build` directory:

    ./examples/
