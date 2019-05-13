#include <cassert>
#include <iostream>
#include <memory>
#include <random>
#include <algorithm>
#include <functional>
#include <chrono>

#include "common.h"

using namespace seal;
using namespace std;


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
