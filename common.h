#pragma once

#include <cstdint>
#include <vector>

#include <seal/seal.h>

typedef std::vector<std::int64_t> CLK;

extern unsigned NTHREADS;

using seal::Plaintext;
using seal::Ciphertext;
using seal::Evaluator;
using seal::GaloisKeys;
using seal::BatchEncoder;



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
