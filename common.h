#pragma once

#include <vector>
#include <istream>
#include <streambuf>

#include <stdint.h>

#include <seal/seal.h>

#include "seclink.h"


typedef std::vector<int64_t> CLK;

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
// and here: https://stackoverflow.com/a/13542996
struct membuf: std::streambuf {
    membuf(char *base, size_t size) {
        this->setp(base, base + size);
        this->setg(base, base, base + size);
    }
    std::size_t written() const { return this->pptr() - this->pbase(); }
    std::size_t read() const    { return this->gptr() - this->eback(); }
};

struct imemstream: virtual membuf, std::istream {
    imemstream(const char *base, size_t size)
        : membuf(const_cast<char *>(base), size)
        , std::istream(static_cast<std::streambuf *>(this)) {
    }
};

struct omemstream: virtual membuf, std::ostream {
    omemstream(char *base, std::size_t size)
        : membuf(base, size)
        , std::ostream(static_cast<std::streambuf *>(this)) {
    }
};

std::vector<int64_t>
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
