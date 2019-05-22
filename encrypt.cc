#include <cassert>
#include <vector>
#include <algorithm> // rotate, generate

#include "common.h"

using namespace std;
using namespace seal;

vector<Plaintext>
encode_left_matrix(const vector<CLK> &clks, BatchEncoder &encoder) {
    size_t clksz = clks[0].size();

    size_t half_slot_count = encoder.slot_count() / 2;
    assert(half_slot_count % clksz == 0);
    assert(clks.size() <= half_slot_count); // FIXME relax this with chunking

    vector< vector<int64_t> > diag_matrix;
    for (size_t i = 0; i < clks.size(); ++i) {
        vector<int64_t> cpy(clks[i]);
        std::rotate(begin(cpy), begin(cpy) + (i % cpy.size()), end(cpy));
        diag_matrix.push_back(cpy);
    }

    // Transpose diag_matrix
    vector< vector<int64_t> > diag_matrix_tr(diag_matrix[0].size());
    for (auto &v : diag_matrix_tr)
        v.resize(diag_matrix.size());
    for (size_t i = 0; i < diag_matrix.size(); ++i)
        for (size_t j = 0; j < diag_matrix[0].size(); ++j)
            diag_matrix_tr[j][i] = diag_matrix[i][j];

    vector<Plaintext> ptxts(clksz);
    for (size_t i = 0; i < clksz; ++i) {
        vector<int64_t> cpy(diag_matrix_tr[i]);
        // duplicate diag_matrix_tr[i]
        // TODO: can we use repeat (below) instead?
        cpy.insert(end(cpy), begin(cpy), end(cpy));
        encoder.encode(cpy, ptxts[i]);
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
vector<Plaintext>
encode_right_matrix(const int64_t *colmat, size_t nrows, size_t ncols, BatchEncoder &encoder)
{
    assert(nrows > 0 && ncols > 0);

    size_t half_slot_count = encoder.slot_count() / 2;
    // TODO: Relax this restriction
    assert(half_slot_count % nrows == 0);
    // How many columnt repetitions must we do to fill the plaintext:
    size_t reps_per_col = half_slot_count / nrows;

    size_t i = 0, nptxts = (ncols + 1) / 2; // ceil(ncols / 2.0)
    vector<Plaintext> ptxts(nptxts);

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
    // FIXME: Handle last CLK
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


static std::vector<seal::Ciphertext>
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


static std::vector<CLK>
make_clks(const int64_t *inmat, size_t nrows, size_t ncols)
{
    std::vector<CLK> clks;
    clks.reserve(nrows);
    for (size_t i = 0; i < nrows; ++i) {
        const int64_t *mat = inmat + i*ncols;
        clks.emplace_back(mat, mat + ncols);
    }
    return clks;
}


void
seclink_encrypt_left(
    const seclink_ctx_t ctx,
    seclink_emat_t *outmat,
    const int64_t *rowmat, size_t nrows, size_t ncols,
    const char *pubkey, size_t pubkeybytes)
{
    std::vector<CLK> clks = make_clks(rowmat, nrows, ncols);
    auto ptxts = encode_left_matrix(clks, ctx->encoder);
    *outmat = new seclink_emat;
    (*outmat)->data = encrypt_all(ctx, ptxts, pubkey, pubkeybytes);
}


void
seclink_encrypt_right(
    const seclink_ctx_t ctx,
    seclink_emat_t *outmat,
    const int64_t *colmat, size_t nrows, size_t ncols,
    const char *pubkey, size_t pubkeybytes)
{
    // TODO: Double-check: why do we have to switch nrows and ncols here?
    auto ptxts = encode_right_matrix(colmat, nrows, ncols, ctx->encoder);
    *outmat = new seclink_emat;
    (*outmat)->data = encrypt_all(ctx, ptxts, pubkey, pubkeybytes);
}
