// -*- compile-command: "g++ -O3 -Wall -Wextra -pedantic -std=gnu++17 -o secure-linkage secure-linkage.cc -pthread -fopenmp /usr/local/lib/libseal.a" -*-

#include <cassert>
#include <iostream>
#include <numeric>
#include <memory>
#include <vector>
#include <random>
#include <algorithm>
#include <functional>
#include <chrono>
#include <cstdint>
#include <thread>

#include <seal/seal.h>

using namespace seal;
using namespace std;

typedef vector<int64_t> CLK;

void generate_clks(vector<CLK> &clks, int nclks, int clksz) {
    // From: https://stackoverflow.com/a/23143753

    // First create an instance of an engine.
    random_device rnd_device;
    // Specify the engine and distribution.
    mt19937 mersenne_engine {rnd_device()};  // Generates random integers
    uniform_int_distribution<int> dist {0, 1};

    auto gen = [&dist, &mersenne_engine](){
        return dist(mersenne_engine);
    };

    clks.resize(nclks);
    for (auto &v : clks) {
        v.resize(clksz);
        generate(begin(v), end(v), gen);
    }
}

/*
Helper function: Prints the parameters in a SEALContext.
*/
void print_parameters(shared_ptr<SEALContext> context)
{
    // Verify parameters
    if (!context)
    {
        throw invalid_argument("context is not set");
    }
    auto &context_data = *context->context_data();

    /*
    Which scheme are we using?
    */
    string scheme_name;
    switch (context_data.parms().scheme())
    {
    case scheme_type::BFV:
        scheme_name = "BFV";
        break;
    case scheme_type::CKKS:
        scheme_name = "CKKS";
        break;
    default:
        throw invalid_argument("unsupported scheme");
    }

    cout << "/ Encryption parameters:" << endl;
    cout << "| scheme: " << scheme_name << endl;
    cout << "| poly_modulus_degree: " << 
        context_data.parms().poly_modulus_degree() << endl;

    /*
    Print the size of the true (product) coefficient modulus.
    */
    cout << "| coeff_modulus size: " << context_data.
        total_coeff_modulus_bit_count() << " bits" << endl;

    /*
    For the BFV scheme print the plain_modulus parameter.
    */
    if (context_data.parms().scheme() == scheme_type::BFV)
    {
        cout << "| plain_modulus: " << context_data.
            parms().plain_modulus().value() << endl;
    }

    cout << "\\ noise_standard_deviation: " << context_data.
        parms().noise_standard_deviation() << endl;
    cout << endl;
}

void noise_test(int poldeg) {
    int plain_mod = poldeg == 2048 ? 12289 : 40961;
    EncryptionParameters parms(scheme_type::BFV);

    parms.set_poly_modulus_degree(poldeg);
    parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(poldeg));
    parms.set_plain_modulus(plain_mod);

    auto context = SEALContext::Create(parms);
    print_parameters(context);

    auto qualifiers = context->context_data()->qualifiers();
    cout << "Batching enabled: " << boolalpha << qualifiers.using_batching << endl;

    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();

    int relin_key_bits = 30;
    auto relin_keys = keygen.relin_keys(relin_key_bits);

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    BatchEncoder encoder(context);
    vector<CLK> clks;
    generate_clks(clks, 2, encoder.slot_count());

    Plaintext plain1, plain2;
    encoder.encode(clks[0], plain1);
    encoder.encode(clks[1], plain2);

    Ciphertext encrypted1, encrypted2;
    encryptor.encrypt(plain1, encrypted1);
    encryptor.encrypt(plain2, encrypted2);

    cout << "Noise budget in inputs: "
        << decryptor.invariant_noise_budget(encrypted1) << " bits" << endl;

    evaluator.multiply_inplace(encrypted1, encrypted2);
    cout << "Noise budget in product: "
        << decryptor.invariant_noise_budget(encrypted1) << " bits" << endl;

    //int galois_key_bits = 30;
    //auto galois_keys = keygen.galois_keys(galois_key_bits);

    for (int bits = 5; bits < 60; bits += 5) {
        auto galois_keys = keygen.galois_keys(bits);
        evaluator.rotate_rows_inplace(encrypted2, 1, galois_keys);
        cout << "Noise budget after " << bits << " bit rotation: "
             << decryptor.invariant_noise_budget(encrypted2) << " bits" << endl;
    }
}

/*
Helper function: Prints the `parms_id' to std::ostream.
*/
ostream &operator <<(ostream &stream, parms_id_type parms_id)
{
    stream << hex << parms_id[0] << " " << parms_id[1] << " "
        << parms_id[2] << " " << parms_id[3] << dec;
    return stream;
}

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

template< typename Res, typename Func >
Res timeit(string pre, Func fn) {
    auto t1 = chrono::high_resolution_clock::now();
    Res res = fn();
    auto t2 = chrono::high_resolution_clock::now();
    cout << pre << ": "
         << chrono::duration_cast<chrono::milliseconds>(t2 - t1).count()
         << " ms\n";
    return res;
}

void check_result(string pre,
                  const vector<int64_t> &expected,
                  Ciphertext &cres,
                  Decryptor &decryptor,
                  BatchEncoder &decoder) {
    Plaintext pres;
    decryptor.decrypt(cres, pres);

    vector<int64_t> res;
    decoder.decode(pres, res);

    if (res.size() != expected.size()) {
        cout << pre << ": dimension error: expected size "
             << expected.size() << ", got size "
             << res.size() << endl;
        return;
    }

    int first_wrong = -1, nwrong = 0;
    for (size_t i = 0; i < res.size(); ++i) {
        if (res[i] != expected[i]) {
            ++nwrong;
            if (first_wrong < 0)
                first_wrong = (int)i;
        }
    }
    if (nwrong > 0) {
        cout << pre << ": " << nwrong << "/" << res.size()
            << " failures (first: " << first_wrong << ")" << endl;
    }
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        int thds = atoi(argv[1]);
        if (thds > 0 && thds <= 64) {
            NTHREADS = (unsigned) thds;
        } else {
            cout << "WARN: nthreads must be > 0 and <= 64; "
                 << "continuing single-threaded" << endl;
        }
    }
    cout << "Using " << NTHREADS << "/"
            << thread::hardware_concurrency() << " threads" << endl;
    //int poldeg = 2048;
    //int plain_mod = 12289;
    int poldeg = 4096;
    int plain_mod = 40961;
    EncryptionParameters parms(scheme_type::BFV);

    parms.set_poly_modulus_degree(poldeg);
    parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(poldeg));
    parms.set_plain_modulus(plain_mod);

    auto context = SEALContext::Create(parms);
    print_parameters(context);

    auto qualifiers = context->context_data()->qualifiers();
    cout << "Batching enabled: " << boolalpha << qualifiers.using_batching << endl;

    KeyGenerator keygen(context);
    auto public_key = keygen.public_key();
    auto secret_key = keygen.secret_key();

    int relin_key_bits = 30;
    auto relin_keys = keygen.relin_keys(relin_key_bits);

    int galois_key_bits = 30;
    auto galois_keys = keygen.galois_keys(galois_key_bits);

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    BatchEncoder batch_encoder(context);

    int nclks = poldeg / 2;
    int clksz = 512;
    vector<CLK> clks;
    generate_clks(clks, nclks, clksz);
    vector<int64_t> expected = mat_vec_prod(clks);

    vector<Plaintext> lhs_ptxts =
        timeit< vector<Plaintext> >(" LHS clks", [&clks, &batch_encoder] {
                return clks_to_left_matrix(clks, batch_encoder);
            });
    assert(lhs_ptxts.size() == (size_t)clksz);

    vector<Plaintext> rhs_ptxts =
        timeit< vector<Plaintext> >(" RHS clks", [&clks, &batch_encoder] {
                return clks_to_right_matrix(clks, batch_encoder);
            });
    assert(rhs_ptxts.size() == (clks.size() + 1)/2);

    auto encrypt = [&encryptor] (string pre, const vector<Plaintext> &ptxts) {
        return timeit< vector<Ciphertext> >(pre, [&ptxts, &encryptor] () {
                vector<Ciphertext> res;
                for (auto &ptxt : ptxts) {
                    Ciphertext ctxt;
                    encryptor.encrypt(ptxt, ctxt);
                    res.push_back(ctxt);
                }
                return res;
            });
    };

    vector<Ciphertext> lhs_ctxts = encrypt(" LHS  enc", lhs_ptxts);
    vector<Ciphertext> rhs_ctxts = encrypt(" RHS  enc", rhs_ptxts);

    Ciphertext cres;
#if 0
    cres = timeit<Ciphertext>("emat  vec", [&rhs_ptxts, &lhs_ctxts, &evaluator, &batch_encoder] () {
            return emat_vec_prod(lhs_ctxts, rhs_ptxts[0], evaluator, batch_encoder);
        });
    check_result("emat  vec", expected, cres, decryptor, batch_encoder);

    cres = timeit<Ciphertext>(" mat evec", [&lhs_ptxts, &rhs_ctxts, &evaluator, &galois_keys] () {
            return mat_evec_prod(lhs_ptxts, rhs_ctxts[0], evaluator, galois_keys);
        });
    check_result(" mat evec", expected, cres, decryptor, batch_encoder);
#endif
    cres = timeit<Ciphertext>("emat evec", [&lhs_ctxts, &rhs_ctxts, &evaluator, &galois_keys] () {
            return emat_evec_prod_thread(lhs_ctxts, rhs_ctxts[0], evaluator, galois_keys);
        });
    check_result("emat evec", expected, cres, decryptor, batch_encoder);

    vector<Ciphertext> cmat;
#if 0
    cmat = timeit<vector<Ciphertext>>("emat emat", [&lhs_ctxts, &rhs_ctxts, &evaluator, &galois_keys] () {
            return emat_emat_prod(lhs_ctxts, rhs_ctxts, evaluator, galois_keys);
        });
    cmat = timeit<vector<Ciphertext>>("emat  mat", [&lhs_ctxts, &rhs_ptxts, &evaluator, &batch_encoder] () {
            return emat_mat_prod(lhs_ctxts, rhs_ptxts, evaluator, batch_encoder);
        });
#endif


    auto t1 = chrono::high_resolution_clock::now();
    vector<Plaintext> junk;
    for (auto &c : rhs_ctxts) {
        Plaintext pres;
        decryptor.decrypt(c, pres);
        junk.push_back(pres);
    }
    auto t2 = chrono::high_resolution_clock::now();
    cout << "Decryption: "
         << chrono::duration_cast<chrono::milliseconds>(t2 - t1).count()
         << " ms\n";
    cout << junk.size() << endl;

    // cout << endl << endl;
    // noise_test(2048);
    // cout << endl;
    // noise_test(4096);

    return 0;
}
