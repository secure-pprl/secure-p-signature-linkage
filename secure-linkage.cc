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

void
check_result(string pre,
    const vector<int64_t> &expected,
    const vector<int64_t> &output)
{
    if (output.size() != expected.size()) {
        cout << pre << ": dimension error: expected size "
             << expected.size() << ", got size "
             << output.size() << endl;
        return;
    }

    int first_wrong = -1, nwrong = 0;
    for (size_t i = 0; i < output.size(); ++i) {
        if (output[i] != expected[i]) {
            ++nwrong;
            if (first_wrong < 0)
                first_wrong = (int)i;
        }
    }
    if (nwrong > 0) {
        cout << pre << ": " << nwrong << "/" << output.size()
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

    vector<int64_t> Linmat(nclks * clksz);
    for (int i = 0; i < nclks * clksz; ++i) {
        Linmat[i] = (i*17 % 31) & 1;
    }
    vector<int64_t> &Rinmat = Linmat;
    int nrows = nclks;
    //int ncols = clksz;


    /* Context */
    seclink_ctx_t ctx;
    seclink_init_ctx(&ctx, poldeg, plain_mod, NULL);

    print_parameters(ctx->context);

    /* Key generation */
    char *pubkey, *seckey, *galkeys;
    size_t pubkeybytes, seckeybytes, galkeysbytes;
    int galkey_bits = 30;
    seclink_keygen(ctx, &pubkey, &pubkeybytes, &seckey, &seckeybytes,
            &galkeys, &galkeysbytes, galkey_bits, 0, 0, 0);

    seclink_emat_t left, right, prod;

    /* Encoding/encryption */
    cout << "encrypting left..." << endl;
    seclink_encrypt_left(ctx, &left, Linmat.data(), nrows, clksz, pubkey, pubkeybytes);
    cout << "encrypting right..." << endl;
    seclink_encrypt_right(ctx, &right, Rinmat.data(), clksz, 2, pubkey, pubkeybytes);

    /* Linkage */
    cout << "multiplying..." << endl;
    seclink_multiply(ctx, &prod, left, right, galkeys, galkeysbytes);

    /* Decryption */
    cout << "decrypting..." << endl;
    vector<int64_t> output;
    output.resize(nclks * 2);
    seclink_decrypt(ctx, output.data(), nrows, 2, prod, seckey, seckeybytes);

    /* Check result */
    vector<vector<int64_t>> clks;
    clks.reserve(nclks);
    auto iter = Linmat.begin();
    for (int i = 0; i < nclks; ++i) {
        clks.emplace_back(iter, iter + clksz);
        iter += clksz;
    }
    vector<int64_t> expected = mat_vec_prod(clks);
    check_result("emat  vec", expected, output);

    /* Clean up */
    cout << "cleaning up..." << endl;
    seclink_clear_ctx(ctx);
    seclink_clear_emat(left);
    seclink_clear_emat(right);
    seclink_clear_emat(prod);

    delete[] pubkey;
    delete[] seckey;
    delete[] galkeys;

    return 0;
}
