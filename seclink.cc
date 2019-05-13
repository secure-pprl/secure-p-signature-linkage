#include "common.h"

void seclink_init_ctx(seclink_ctx_t *ctx) {
    // TODO: these should be read in from elsewhere
    int poldeg = 4096;
    int plain_mod = 40961;
    // TODO: use EncryptionParameters::parms_id()
    seal::EncryptionParameters params(seal::scheme_type::BFV);

    params.set_poly_modulus_degree(poldeg);
    params.set_coeff_modulus(seal::DefaultParams::coeff_modulus_128(poldeg));
    params.set_plain_modulus(plain_mod);

    *ctx = new seclink_ctx(seal::SEALContext::Create(params));
}

void seclink_clear_ctx(seclink_ctx_t ctx) {
    delete ctx;
}

void seclink_clear_emat(seclink_emat_t mat) {
    delete mat;
}
