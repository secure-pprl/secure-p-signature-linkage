#pragma once

#include <cstdint>
#include <vector>
#include <streambuf>

#include <seal/seal.h>

#include "seclink.h"


typedef std::vector<std::int64_t> CLK;

extern unsigned NTHREADS;

using seal::Plaintext;
using seal::Ciphertext;
using seal::Evaluator;
using seal::GaloisKeys;
using seal::BatchEncoder;

struct seclink_ctx {
    std::shared_ptr<seal::SEALContext> context;
    seal::Evaluator evaluator;
    seal::BatchEncoder encoder;
    seal::GaloisKeys galkeys;
};

struct seclink_emat {
    std::vector<seal::Ciphertext> data;
};


// Found here: https://stackoverflow.com/a/7782037
// Usage:
//   char buffer[] = "I'm a buffer with embedded nulls\0and line\n feeds";
//
//   membuf sbuf(buffer, buffer + sizeof(buffer));
//   std::istream in(&sbuf);
//   std::string line;
//   while (std::getline(in, line)) {
//       std::cout << "line: " << line << "\n";
//   }
//   return 0;
//
struct membuf : std::streambuf {
    // NB: C++ requires these to be char*, not const char*.
    membuf(char* begin, char* end) {
        this->setg(begin, begin, end);
    }
};

std::vector<Plaintext>
clks_to_left_matrix(const std::vector<CLK> &clks, BatchEncoder &encoder);

std::vector<Plaintext>
clks_to_right_matrix(const std::vector<CLK> &clks, BatchEncoder &encoder);

std::vector<std::int64_t>
mat_vec_prod(const std::vector<CLK> &clks);

Ciphertext
emat_evec_prod(
        const std::vector<Ciphertext> &mat,
        const Ciphertext &vec,
        Evaluator &eval,
        const GaloisKeys &galois_keys);

Ciphertext
emat_evec_prod_omp(
        const std::vector<Ciphertext> &mat,
        const Ciphertext &vec,
        Evaluator &eval,
        const GaloisKeys &galois_keys);

Ciphertext
emat_evec_prod_thread(
        const std::vector<Ciphertext> &mat,
        const Ciphertext &vec,
        Evaluator &eval,
        const GaloisKeys &galois_keys);


Ciphertext
mat_evec_prod(
        const std::vector<Plaintext> &mat,
        const Ciphertext &vec,
        Evaluator &eval,
        const GaloisKeys &galois_keys);

Ciphertext
emat_vec_prod(
        const std::vector<Ciphertext> &mat,
        const Plaintext &vec,
        Evaluator &eval,
        BatchEncoder &encoder);
