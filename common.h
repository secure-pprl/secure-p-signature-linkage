#pragma once

#include <cstdint>
#include <vector>
#include <istream>
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
    seal::BatchEncoder encoder;

    seclink_ctx(std::shared_ptr<seal::SEALContext> ctx)
        : context(ctx), encoder(ctx) { }
};

struct seclink_emat {
    std::vector<seal::Ciphertext> data;
};


// Convenience for using buffers as streams
// Found here: https://stackoverflow.com/a/13059195
struct membuf: std::streambuf {
    membuf(char const* base, size_t size) {
        char* p(const_cast<char*>(base));
        this->setg(p, p, p + size);
    }
};
struct imemstream: virtual membuf, std::istream {
    imemstream(char const* base, size_t size)
        : membuf(base, size)
        , std::istream(static_cast<std::streambuf*>(this)) {
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
