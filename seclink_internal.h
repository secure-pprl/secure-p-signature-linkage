#pragma once

#include <stdint.h>
#include <vector>
#include <seal/seal.h>

#include "seclink.h"

struct seclink_ctx {
    std::shared_ptr<seal::SEALContext> context;
    seal::BatchEncoder encoder;

    seclink_ctx(std::shared_ptr<seal::SEALContext> ctx)
        : context(ctx), encoder(ctx) { }
};

struct seclink_emat {
    size_t nrows, ncols;
    std::vector<seal::Ciphertext> data;

    seclink_emat(size_t nrows_, size_t ncols_, const std::vector<seal::Ciphertext> &data_)
        : nrows(nrows_), ncols(ncols_), data(data_) { };
};
