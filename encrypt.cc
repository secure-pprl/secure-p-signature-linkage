#include <cassert>
#include <vector>
#include <algorithm> // rotate, generate

#include "memstream.h"
#include "seclink_internal.h"

using namespace std;

/*
 * rowmat is an array of nrows*ncols int64_t values. It is interpreted
 * in ROW-MAJOR order, that is
 * row 0 is {rowmat[0], rowmat[1], ..., colmat[ncols - 1]}
 * column 0 is {rowmat[0], rowmat[nrows], ..., rowmat[nrows * (ncols - 1)]},
 */
static vector<seal::Plaintext>
encode_left_matrix(const int64_t *rowmat, size_t nrows, size_t ncols, seal::BatchEncoder &encoder)
{
    assert(nrows > 0 && ncols > 0);

    size_t half_slot_count = encoder.slot_count() / 2;
    // TODO: Relax this restriction with chunking
    assert(nrows <= half_slot_count);

    vector<seal::Plaintext> ptxts(ncols);
    vector<int64_t> ptxt(encoder.slot_count(), 0L);
    for (size_t j = 0; j < ncols; ++j) {
        size_t cidx = j; // target column index
        auto row = rowmat;
        for (size_t i = 0; i < nrows; ++i, row += ncols) {
            ptxt[i] = row[cidx];
            ptxt[i + half_slot_count] = ptxt[i]; // both columns are the same
            // cidx == (i + j) % ncols
            if (++cidx == ncols)
                cidx = 0;
        }
        encoder.encode(ptxt, ptxts[j]);
    }
    return ptxts;
}

template< typename Iter >
struct repeat {
    Iter idx, begin, end;

    explicit repeat(Iter b, Iter e)
        : idx(b), begin(b), end(e) { }

    auto operator()() {
        auto res = *idx++;
        if (idx == end)
            idx = begin;
        return res;
    }
};

/*
 * colmat is an array of nrows*ncols int64_t values. It is interpreted
 * in COLUMN-MAJOR order, that is column 0 is {colmat[0], ..., colmat[nrows-1]},
 * and row 0 is {colmat[0], colmat[ncols], ..., colmat[ncols * (nrows-1)]}
 */
static vector<seal::Plaintext>
encode_right_matrix(const int64_t *colmat, size_t nrows, size_t ncols, seal::BatchEncoder &encoder)
{
    assert(nrows > 0 && ncols > 0);

    size_t half_slot_count = encoder.slot_count() / 2;
    // TODO: Relax this restriction
    assert(half_slot_count % nrows == 0);
    // How many columnt repetitions must we do to fill the plaintext:
    size_t reps_per_col = half_slot_count / nrows;

    size_t i = 0, nptxts = (ncols + 1) / 2; // ceil(ncols / 2.0)
    vector<seal::Plaintext> ptxts(nptxts);

    // Iterate over the columns of colmat, two at a time.
    vector<int64_t> ptxt(2 * nrows * reps_per_col);
    auto halfway = ptxt.begin() + nrows * reps_per_col;
    auto end = colmat + nrows * ncols;
    for (auto col = colmat; col < end; col += 2*nrows, ++i) {
        auto col1 = col, col2 = col1 + nrows;

        std::generate(ptxt.begin(), halfway, repeat(col1, col1 + nrows));
        std::generate(halfway, ptxt.end(), repeat(col2, col2 + nrows));

        encoder.encode(ptxt, ptxts[i]);
    }
    // FIXME: Handle last column when ncols is not even
    return ptxts;
}


static seal::Encryptor
get_encryptor(
    const seclink_ctx_t ctx,
    const char *pubkey, size_t pubkeybytes)
{
    imemstream in(pubkey, pubkeybytes);
    seal::PublicKey pkey;
    pkey.load(ctx->context, in);
    return seal::Encryptor(ctx->context, pkey);
}


static vector<seal::Ciphertext>
encrypt_all(
    const seclink_ctx_t ctx,
    const std::vector<seal::Plaintext> &ptxts,
    const char *pubkey, size_t pubkeybytes)
{
    seal::Encryptor encryptor = get_encryptor(ctx, pubkey, pubkeybytes);
    std::vector<seal::Ciphertext> res;
    for (auto &ptxt : ptxts) {
        seal::Ciphertext ctxt;
        encryptor.encrypt(ptxt, ctxt);
        res.push_back(ctxt);
    }
    return res;
}


void
seclink_encrypt_left(
    const seclink_ctx_t ctx,
    seclink_emat_t *outmat,
    const int64_t *rowmat, size_t nrows, size_t ncols,
    const char *pubkey, size_t pubkeybytes)
{
    auto ptxts = encode_left_matrix(rowmat, nrows, ncols, ctx->encoder);
    // TODO: This possibly involves creating a copy of the entire
    // encrypted matrix; see if there's a way to
    // 'std::move/std::forward' it instead.
    *outmat = new seclink_emat(nrows, ncols,
            encrypt_all(ctx, ptxts, pubkey, pubkeybytes));
}


void
seclink_encrypt_right(
    const seclink_ctx_t ctx,
    seclink_emat_t *outmat,
    const int64_t *colmat, size_t nrows, size_t ncols,
    const char *pubkey, size_t pubkeybytes)
{
    auto ptxts = encode_right_matrix(colmat, nrows, ncols, ctx->encoder);
    // TODO: This possibly involves creating a copy of the entire
    // encrypted matrix; see if there's a way to
    // 'std::move/std::forward' it instead.
    *outmat = new seclink_emat(nrows, ncols,
            encrypt_all(ctx, ptxts, pubkey, pubkeybytes));
}
