#include <cassert>

#include "common.h"

using namespace std;
using namespace seal;

vector<Plaintext>
clks_to_left_matrix(const vector<CLK> &clks, BatchEncoder &encoder) {
    size_t clksz = clks[0].size();

    size_t half_slot_count = encoder.slot_count() / 2;
    assert(half_slot_count % clksz == 0);
    assert(clks.size() <= half_slot_count); // FIXME relax this with chunking

    vector< vector<int64_t> > diag_matrix;
    for (size_t i = 0; i < clks.size(); ++i) {
        vector<int64_t> cpy(clks[i]);
        rotate(begin(cpy), begin(cpy) + (i % cpy.size()), end(cpy));
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
        cpy.insert(end(cpy), begin(cpy), end(cpy));
        encoder.encode(cpy, ptxts[i]);
    }
    return ptxts;
}

template< template<typename> class C, typename T >
struct repeat {
    typename C<T>::const_iterator idx, begin, end;

    explicit repeat(const C<T> &seq)
        : idx(std::begin(seq)), begin(std::begin(seq)), end(std::end(seq)) { }

    T operator()() {
        T res = *idx++;
        if (idx == end)
            idx = begin;
        return res;
    }
};

vector<Plaintext>
clks_to_right_matrix(const vector<CLK> &clks, BatchEncoder &encoder) {
    assert(clks.size() > 0);
    int clksz = clks[0].size();
    CLK empty_clk(clksz, 0);

    int half_slot_count = encoder.slot_count() / 2;
    assert(half_slot_count % clksz == 0);
    int clks_per_col = half_slot_count / clksz;

    size_t nptxts = (clks.size() + 1) / 2; // ceil(clks.size() / 2.0)
    vector<Plaintext> ptxts(nptxts);
    for (size_t i = 0, j = 0; j < clks.size(); ++i, j += 2) {
        vector<int64_t> col(2 * clksz * clks_per_col);
        vector<int64_t>::iterator halfway = col.begin() + clksz * clks_per_col;
        generate(col.begin(), halfway, repeat(clks[j]));
        generate(halfway, col.end(), repeat(clks[j + 1]));
        encoder.encode(col, ptxts[i]);
    }
    // FIXME: Handle last CLK
    return ptxts;
}


static seal::Encryptor
get_encryptor(
    const seclink_ctx_t ctx,
    const char *pubkey, int pubkeybytes)
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
    const char *pubkey, int pubkeybytes)
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
make_clks(
    const void *inmat, int nrows, int ncols, int eltbytes)
{
    static constexpr int BUFBYTES = 8;
    char valbuf[BUFBYTES];
    const char *mat = static_cast<const char *>(inmat);
    assert(eltbytes <= BUFBYTES);

    std::vector<CLK> clks;
    clks.resize(nrows);
    for (int i = 0; i < nrows; ++i) {
        clks[i].resize(ncols);
        for (int j = 0; j < ncols; ++j) {
            const char *begin = mat + (i * ncols + j) * eltbytes;
            std::memset(valbuf, 0, BUFBYTES);
            std::memcpy(valbuf, begin, eltbytes);
            imemstream buf(begin, 8);
            std::int64_t val;
            buf >> val;
            clks[i][j] = val;
        }
    }
    return clks;
}


void
seclink_encrypt_left(
    const seclink_ctx_t ctx,
    seclink_emat_t *outmat,
    const void *inmat, int nrows, int ncols, int eltbytes,
    const char *pubkey, int pubkeybytes)
{
    std::vector<CLK> clks = make_clks(inmat, nrows, ncols, eltbytes);
    auto ptxts = clks_to_left_matrix(clks, ctx->encoder);
    *outmat = new seclink_emat;
    (*outmat)->data = encrypt_all(ctx, ptxts, pubkey, pubkeybytes);
}


void
seclink_encrypt_right(
    const seclink_ctx_t ctx,
    seclink_emat_t *outmat,
    const void *inmat, int nrows, int ncols, int eltbytes,
    const char *pubkey, int pubkeybytes)
{
    std::vector<CLK> clks = make_clks(inmat, nrows, ncols, eltbytes);
    auto ptxts = clks_to_right_matrix(clks, ctx->encoder);
    *outmat = new seclink_emat;
    (*outmat)->data = encrypt_all(ctx, ptxts, pubkey, pubkeybytes);
}
