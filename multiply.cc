#include <thread>
#include <numeric> // inner_product

#include "common.h"

using namespace std;
using namespace seal;

vector<int64_t>
mat_vec_prod(const vector<CLK> &clks) {
    vector<int64_t> res;
    CLK vec;

    vec= clks[0];
    for (auto &clk : clks)
        res.push_back(inner_product(begin(clk), end(clk), begin(vec), 0L));
    vec = clks[1];
    for (auto &clk : clks)
        res.push_back(inner_product(begin(clk), end(clk), begin(vec), 0L));
    return res;
}

Ciphertext
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

Ciphertext
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

//std::mutex g_mutex;

unsigned NTHREADS = 1; //std::thread::hardware_concurrency();

Ciphertext
emat_evec_prod_thread(
        const vector<Ciphertext> &mat,
        const Ciphertext &vec,
        Evaluator &eval,
        const GaloisKeys &galois_keys) {
    unsigned nelts_per_thread = mat.size() / NTHREADS;
    if (mat.size() % NTHREADS != 0) {
        cout << " *** nthreads doesn't divide matrix size" << endl;
        abort();
    }
    if (mat.size() > (1 << 20)) {
        cout << " *** matrix size is too big" << endl;
        abort();
    }

    cout << "#ciphertexts: " << mat.size() << endl;
    vector<Ciphertext> res{mat.size()};
    vector<int> times((int)NTHREADS, -1);
    vector<thread> grp;
    for (unsigned i = 0; i < mat.size(); i += nelts_per_thread) {
        grp.emplace_back([i, nelts_per_thread, &vec, &eval, &galois_keys, &mat, &res, &times] () {
                    auto t1 = chrono::high_resolution_clock::now();
                    // See memorymanager.h for reasons why one might use a thread local memory pool.
                    // Using the thread local memory pool didn't help
                    //auto pool = MemoryPoolHandle::ThreadLocal();
                    for (unsigned j = i; j < i + nelts_per_thread; ++j) {
                        Ciphertext v{vec};
                        // Using placement new to avoid copying didn't help
                        //Ciphertext *v = new (&res[j]) Ciphertext(vec);
                        eval.rotate_rows_inplace(v, j, galois_keys);
                        eval.multiply_inplace(v, mat[j]);

                        // Writing to different elements of res from
                        // different threads is okay, apparently.
                        //lock_guard<mutex> guard{g_mutex};

                        res[j] = v;
                    }
                    auto t2 = chrono::high_resolution_clock::now();
                    times[i / nelts_per_thread] = chrono::duration_cast<chrono::milliseconds>(t2 - t1).count();
            });
    }
    for (auto &t : grp)
        t.join();

    cout << "thread ms:";
    for (auto t : times)
        cout << "  " << t;
    cout << "  (avg: " << accumulate(times.begin(), times.end(), 0) / (float) times.size() << ")";
    cout << endl;

    Ciphertext r(res[0]);
    for (unsigned i = 1; i < res.size(); ++i)
        eval.add_inplace(r, res[i]);
    return r;
}

Ciphertext
mat_evec_prod(
        const vector<Plaintext> &mat,
        const Ciphertext &vec,
        Evaluator &eval,
        const GaloisKeys &galois_keys) {
    Ciphertext res(vec);
    eval.multiply_plain_inplace(res, mat[0]);
    for (unsigned i = 1; i < mat.size(); ++i) {
        Ciphertext v(vec);
        // TODO: Rotate rows takes the vast majority of the runtime of this function.
        eval.rotate_rows_inplace(v, i, galois_keys);
        eval.multiply_plain_inplace(v, mat[i]);
        eval.add_inplace(res, v);
    }
    return res;
}

Ciphertext
emat_vec_prod(
        const vector<Ciphertext> &mat,
        const Plaintext &vec,
        Evaluator &eval,
        BatchEncoder &encoder) {
    vector<int64_t> pdata(encoder.slot_count());
    vector<int64_t>::iterator halfway = pdata.begin() + pdata.size()/2;
    encoder.decode(vec, pdata);

    Ciphertext res(mat[0]);
    eval.multiply_plain_inplace(res, vec);
    for (unsigned i = 1; i < mat.size(); ++i) {
        Ciphertext c(mat[i]);
        Plaintext p;
        // This junk could be precomputed outside this function; doesn't seem to
        // improve runtime much though.
        rotate(pdata.begin(), pdata.begin() + 1, halfway);
        rotate(halfway, halfway + 1, pdata.end());
        encoder.encode(pdata, p);

        eval.multiply_plain_inplace(c, p);
        eval.add_inplace(res, c);
    }
    return res;
}

vector<Ciphertext>
emat_emat_prod(
        const vector<Ciphertext> &X,
        const vector<Ciphertext> &Y,
        Evaluator &eval,
        const GaloisKeys &galois_keys) {
    vector<Ciphertext> res(Y.size());

    #pragma omp parallel for
    for (size_t i = 0; i < Y.size(); ++i)
        res[i] = emat_evec_prod(X, Y[i], eval, galois_keys);
    // for (auto &y : Y)
    //     res.push_back(emat_evec_prod(X, y, eval, galois_keys));
    return res;
}


vector<Ciphertext>
emat_mat_prod(
        const vector<Ciphertext> &X,
        const vector<Plaintext> &Y,
        Evaluator &eval,
        BatchEncoder &encoder) {
    vector<Ciphertext> res(Y.size());
    #pragma omp parallel for
    for (size_t i = 0; i < Y.size(); ++i)
        res[i] = emat_vec_prod(X, Y[i], eval, encoder);
    // for (auto &y : Y)
    //     res.push_back(emat_vec_prod(X, y, eval, encoder));
    return res;
}

vector<Ciphertext>
mat_emat_prod(
        const vector<Plaintext> &X,
        const vector<Ciphertext> &Y,
        Evaluator &eval,
        const GaloisKeys &galois_keys) {
    vector<Ciphertext> res;
    for (auto &y : Y)
        res.push_back(mat_evec_prod(X, y, eval, galois_keys));
    return res;
}


void seclink_multiply(const seclink_ctx_t ctx,
        seclink_emat_t *res,
        const seclink_emat_t left,
        const seclink_emat_t right,
        const char *galkeys, size_t galkeysbytes) {
    imemstream in(galkeys, galkeysbytes);
    seal::GaloisKeys gkeys;
    gkeys.load(ctx->context, in);

    Evaluator evaluator(ctx->context);
    *res = new seclink_emat;
    (*res)->data = emat_emat_prod(left->data, right->data, evaluator, gkeys);
}
