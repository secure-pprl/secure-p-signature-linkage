#include <cassert>
#include <iostream>
#include <fstream>
#include <memory>
#include <random>
#include <functional>
#include <chrono>

#include "common.h"

using namespace seal;
using namespace std;


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

    std::uint64_t plain_mod = 40961;
    std::size_t poldeg = 4096;
    int nclks = poldeg / 2;
    int clksz = 512;

    char *Linmat = new char[nclks * clksz];
    for (int i = 0; i < nclks * clksz; ++i) {
        Linmat[i] = (i*17 % 31) & 1;
    }
    char *Rinmat = Linmat;
    int nrows = nclks;
    int ncols = clksz;
    int eltbytes = 1;

    char *output = new char[nclks * 2];

    /* Context */
    seclink_ctx_t ctx;
    seclink_init_ctx(&ctx, poldeg, plain_mod, NULL);

    /* Key generation */
    char *pubkey, *seckey, *galkeys;
    size_t pubkeybytes, seckeybytes, galkeysbytes;
    int galkey_bits = 30;
    seclink_keygen(ctx, &pubkey, &pubkeybytes, &seckey, &seckeybytes,
            &galkeys, &galkeysbytes, galkey_bits, 0, 0, 0);

    seclink_emat_t left, right, prod;

    /* Encoding/encryption */
    cout << "encrypting left..." << endl;
    seclink_encrypt_left(ctx, &left, Linmat, nrows, clksz, eltbytes, pubkey, pubkeybytes);
    cout << "encrypting right..." << endl;
    // FIXME: Something is wrong with transposes here
    seclink_encrypt_right(ctx, &right, Rinmat, clksz, 2, eltbytes, pubkey, pubkeybytes);

    /* Linkage */
    cout << "multiplying..." << endl;
    seclink_multiply(ctx, &prod, left, right, galkeys, galkeysbytes);

    /* Decryption */
    cout << "decrypting..." << endl;
    seclink_decrypt(ctx, output, nrows, 2, eltbytes, prod, seckey, seckeybytes);

    /* Clean up */
    cout << "cleaning up..." << endl;
    seclink_clear_ctx(ctx);
    seclink_clear_emat(left);
    seclink_clear_emat(right);
    seclink_clear_emat(prod);

    delete[] Linmat;
    delete[] output;

    delete[] pubkey;
    delete[] seckey;
    delete[] galkeys;

#if 0
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

#endif
    return 0;
}
