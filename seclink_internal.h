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
    std::vector<seal::Ciphertext> data;
};
