#include "common.h"

static std::vector<seal::Plaintext>
decrypt_all(const seclink_ctx_t ctx,
        const seclink_emat_t inmat,
        const char *seckey, int seckeybytes) {
    imemstream in(seckey, seckeybytes);
    seal::SecretKey key;
    key.load(ctx->context, in);
    seal::Decryptor decryptor(ctx->context, key);

    std::vector<seal::Plaintext> ptxts;
    for (auto &c : inmat->data) {
        seal::Plaintext ptxt;
        decryptor.decrypt(c, ptxt);
        ptxts.push_back(ptxt);
    }
    return ptxts;
}

void seclink_decrypt_left(const seclink_ctx_t ctx,
        void *outmat, int nrows, int ncols, int eltbytes,
        const seclink_emat_t inmat,
        const char *seckey, int seckeybytes) {
    auto ptxts = decrypt_all(ctx, inmat, seckey, seckeybytes);
}

void seclink_decrypt_right(const seclink_ctx_t ctx,
        void *outmat, int nrows, int ncols, int eltbytes,
        const seclink_emat_t inmat,
        const char *seckey, int seckeybytes) {
    auto ptxts = decrypt_all(ctx, inmat, seckey, seckeybytes);
}
