#include <sstream>
#include <cassert>

#include "memstream.h"
#include "seclink_internal.h"

void seclink_init_ctx(seclink_ctx_t *ctx,
        size_t polmod_deg, uint64_t plain_mod,
        uint64_t prng_seed[2])
{
    // FIXME: SEAL's PRNG system is at best misleading; if we specify
    // a seed here, then the same PRNG starting at that seed will be
    // used at several different points. OTOH, there's no way to read
    // off the seed that they use if it's just generated
    // randomly. Might need to derive my own PRNG for deployment.
    uint64_t seed[2] = { 0, 0 };
    if ( ! prng_seed)
        prng_seed = seed;

    // TODO: use EncryptionParameters::parms_id()?
    seal::EncryptionParameters params(seal::scheme_type::BFV);

    params.set_random_generator(
        std::make_shared<seal::FastPRNGFactory>(seed[0], seed[1]));

    params.set_poly_modulus_degree(polmod_deg);
    params.set_coeff_modulus(seal::CoeffModulus::BFVDefault(polmod_deg));
    // params.set_plain_modulus(seal::PlainModulus::Batching(plain_mod));
    params.set_plain_modulus(plain_mod);

    *ctx = new seclink_ctx(seal::SEALContext::Create(params));
}

void seclink_clear_ctx(seclink_ctx_t ctx) {
    delete ctx;
}

void seclink_clear_emat(seclink_emat_t mat) {
    delete mat;
}


template< typename T >
static void
save_key_data(
    const T &key,
    char **out_arr, std::size_t *out_bytes,
    std::vector<char> &buf)
{
    omemstream os(buf.data(), buf.size());
    key.save(os);
    // FIXME: check that os.good() is all I need to check to detect overflow.
    assert(os.good());

    std::size_t nbytes = os.written();
    assert(nbytes < buf.size()); // should be guaranteed after os.good()
    *out_bytes = nbytes;
    // NB: must match the delete[] statement in 'seclink_clear_key()'.
    *out_arr = new char[nbytes];

    auto it = buf.begin();
    std::copy(it, it + nbytes, *out_arr);
}

// Create keys. galois_keys_* and/or relin_keys_* can be zero to
// signal not to generate those keys.
//
// Note it is the caller's responsibility to delete[] the memory
// returned in the *_arr pointers!
void seclink_keygen(const seclink_ctx_t ctx,
        char **public_key_arr, size_t *public_key_bytes,
        char **secret_key_arr, size_t *secret_key_bytes,
        char **galois_keys_arr, size_t *galois_keys_bytes,
        char **relin_keys_arr, size_t *relin_keys_bytes)
{
    seal::KeyGenerator keygen(ctx->context);

    // TODO: Determine a tighter bound on how much memory we could
    // possibly need. Galois keys can be 11 MB though...
    static constexpr std::size_t SCRATCH_BYTES = 1U << 24;
    std::vector<char> scratch(SCRATCH_BYTES);

    auto public_key = keygen.public_key();
    save_key_data(public_key, public_key_arr, public_key_bytes, scratch);

    auto secret_key = keygen.secret_key();
    save_key_data(secret_key, secret_key_arr, secret_key_bytes, scratch);

    if (galois_keys_arr && galois_keys_bytes) {
        auto galois_keys = keygen.galois_keys();
        save_key_data(galois_keys, galois_keys_arr, galois_keys_bytes, scratch);
    }

    if (relin_keys_arr && relin_keys_bytes) {
        auto relin_keys = keygen.relin_keys();
        save_key_data(relin_keys, relin_keys_arr, relin_keys_bytes, scratch);
    }
}

void seclink_clear_key(char *key)
{
    // NB: must match the new[] statement in 'save_key_data()'.
    delete[] key;
}


void seclink_emat_shape(size_t *nrows, size_t *ncols, const seclink_emat_t mat)
{
    *nrows = mat->nrows;
    *ncols = mat->ncols;
}
