#include "memstream.h"
#include "seclink_internal.h"

using namespace std;
using namespace seal;

static Ciphertext
emat_evec_prod(
        const vector<Ciphertext> &mat,
        const Ciphertext &vec,
        Evaluator &eval,
        const GaloisKeys &galois_keys) {
    Ciphertext res(vec);
    eval.multiply_inplace(res, mat[0]);
    for (unsigned i = 1; i < mat.size(); ++i) {
        Ciphertext v(vec);
        eval.rotate_rows_inplace(v, i, galois_keys);
        eval.multiply_inplace(v, mat[i]);
        eval.add_inplace(res, v);
    }
    return res;
}

#if 0
/*
 * OMP-enabled version of above
 */
static Ciphertext
emat_evec_prod_omp(
        const vector<Ciphertext> &mat,
        const Ciphertext &vec,
        Evaluator &eval,
        const GaloisKeys &galois_keys) {
    vector<Ciphertext> res(mat.size());
    res[0] = vec;
    eval.multiply_inplace(res[0], mat[0]);

    #pragma omp parallel for
    for (unsigned i = 1; i < mat.size(); ++i) {
        Ciphertext v(vec);
        eval.rotate_rows_inplace(v, i, galois_keys);
        eval.multiply(v, mat[i], res[i]);
    }
    Ciphertext r(res[0]);
    for (unsigned i = 1; i < res.size(); ++i)
        eval.add_inplace(r, res[i]);
    return r;
}
#endif

static vector<Ciphertext>
emat_emat_prod(
        const vector<Ciphertext> &X,
        const vector<Ciphertext> &Y,
        Evaluator &eval,
        const GaloisKeys &galois_keys) {
    vector<Ciphertext> res(Y.size());

    #pragma omp parallel for
    for (size_t i = 0; i < Y.size(); ++i)
        res[i] = emat_evec_prod(X, Y[i], eval, galois_keys);
    return res;
}

void seclink_multiply(const seclink_ctx_t ctx,
        seclink_emat_t *res,
        const seclink_emat_t left,
        const seclink_emat_t right,
        const char *galkeys, size_t galkeysbytes)
{
    imemstream in(galkeys, galkeysbytes);
    seal::GaloisKeys gkeys;
    gkeys.load(ctx->context, in);

    Evaluator evaluator(ctx->context);
    // TODO: This possibly involves creating a copy of the entire
    // encrypted matrix; see if there's a way to
    // 'std::move/std::forward' it instead.
    *res = new seclink_emat(left->nrows, right->ncols,
            emat_emat_prod(left->data, right->data, evaluator, gkeys));
}
