#include <fstream>
#include <seal/seal.h>

using namespace seal;
using namespace std;

/*
 * Helper function: Prints the parameters in a SEALContext.
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

int main() {
    const char *pubkey_fname = "public-key";
    const char *seckey_fname = "secret-key";
    const char *galoiskeys_fname = "galois-keys";
    const char *relinkeys_fname = "relinearisation-keys";
    const char *params_fname = "encryption-params";

    int poldeg = 4096;
    int plain_mod = 40961;
    EncryptionParameters params(scheme_type::BFV);

    // FIXME: SEAL's PRNG system is at best misleading; if we specify
    // a seed here, then the same PRNG starting at that seed will be
    // used at several different points. OTOH, there's no way to read
    // off the seed that they use if it's just generated
    // randomly. Might need to derive my own PRNG for deployment.
    uint64_t seed[2] = { 0, 0 };
    params.set_random_generator(
        std::make_shared<FastPRNGFactory>(seed[0], seed[1]));

    params.set_poly_modulus_degree(poldeg);
    params.set_coeff_modulus(DefaultParams::coeff_modulus_128(poldeg));
    params.set_plain_modulus(plain_mod);

    auto context = SEALContext::Create(params);
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


    ofstream file1(pubkey_fname, ios::binary);
    public_key.save(file1);
    ofstream file2(seckey_fname, ios::binary);
    secret_key.save(file2);
    ofstream file3(galoiskeys_fname, ios::binary);
    galois_keys.save(file3);
    ofstream file4(relinkeys_fname, ios::binary);
    relin_keys.save(file4);
    ofstream file5(params_fname, ios::binary);
    EncryptionParameters::Save(params, file5);
}
