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
    void *outmat, int nrows, int ncols, int eltbytes,
    const seclink_emat_t inmat,
    const char *seckey, int seckeybytes)
{
    char *out = static_cast<char *>(outmat);
    auto ptxts = decrypt_all(ctx, inmat, seckey, seckeybytes);
    int ptxt_rows = ctx->encoder.slot_count() / 2;
    int ptxt_cols = ptxts.size() * 2;

    assert(nrows >= ptxt_rows);
    assert(ncols >= ptxt_cols);

    // ptxts are columns.
    std::memset(outmat, 0, nrows * ncols * eltbytes);
    int j = 0;
    // FIXME: This will truncate the output
    int nbytes = std::min(eltbytes, static_cast<int>(sizeof(std::int64_t)));
    for (auto &ptxt : ptxts) {
        int i = 0;
        for ( ; i < 2 * ptxt_rows; ++i) {
            std::int64_t v = ptxt[i];
            std::memcpy(out + eltbytes*(j * ptxt_rows + i), &v, nbytes);
        }
        ++j;
    }
}
