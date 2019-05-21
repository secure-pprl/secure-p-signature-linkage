#include <cassert>

#include "common.h"

static std::vector< std::vector<std::int64_t> >
decrypt_all(
    const seclink_ctx_t ctx,
    const seclink_emat_t inmat,
    const char *seckey, int seckeybytes)
{
    imemstream in(seckey, seckeybytes);
    seal::SecretKey key;
    key.load(ctx->context, in);
    seal::Decryptor decryptor(ctx->context, key);

    std::vector< std::vector<std::int64_t> > ptxts;
    for (auto &c : inmat->data) {
        seal::Plaintext ptxt;
        decryptor.decrypt(c, ptxt);
        std::vector<std::int64_t> tmp;
        ctx->encoder.decode(ptxt, tmp);
        ptxts.push_back(tmp);
    }
    return ptxts;
}

void
seclink_decrypt(
    const seclink_ctx_t ctx,
    int64_t *outmat, int nrows, int ncols,
    const seclink_emat_t inmat,
    const char *seckey, int seckeybytes)
{
    auto ptxts = decrypt_all(ctx, inmat, seckey, seckeybytes);
    int ptxt_rows = ctx->encoder.slot_count() / 2;
    int ptxt_cols = ptxts.size() * 2;

    assert(nrows >= ptxt_rows);
    assert(ncols >= ptxt_cols);

    // ptxts are columns.
    int j = 0;
    for (auto &ptxt : ptxts) {
        for (int i = 0; i < 2 * ptxt_rows; ++i)
            outmat[j * ptxt_rows + i] = ptxt[i];
        ++j;
    }
}
