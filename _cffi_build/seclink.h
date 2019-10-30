#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/* Context management */

typedef struct seclink_ctx *seclink_ctx_t;

void seclink_init_ctx(seclink_ctx_t *ctx,
        size_t polmod_deg, uint64_t plain_mod,
        uint64_t prng_seed[2]);

void seclink_clear_ctx(seclink_ctx_t ctx);


/* Key generation */

void seclink_keygen(const seclink_ctx_t ctx,
        char **public_key, size_t *public_key_bytes,
        char **secret_key, size_t *secret_key_bytes,
        char **galois_keys, size_t *galois_keys_bytes,
        char **relin_keys, size_t *relin_keys_bytes);

void seclink_clear_key(char *key);


/* Linkage */

typedef struct seclink_emat *seclink_emat_t;

void seclink_emat_shape(size_t *nrows, size_t *ncols, const seclink_emat_t mat);
void seclink_clear_emat(seclink_emat_t mat);

void seclink_encrypt_left(const seclink_ctx_t ctx,
        seclink_emat_t *outmat,
        const int64_t *rowmat, size_t nrows, size_t ncols,
        const char *pubkey, size_t pubkeybytes);

void seclink_encrypt_right(const seclink_ctx_t ctx,
        seclink_emat_t *outmat,
        const int64_t *colmat, size_t nrows, size_t ncols,
        const char *pubkey, size_t pubkeybytes);

void seclink_multiply(const seclink_ctx_t ctx,
        seclink_emat_t *res,
        const seclink_emat_t left,
        const seclink_emat_t right,
        const char *galkeys, size_t galkeysbytes);

void seclink_decrypt(const seclink_ctx_t ctx,
        int64_t *outmat, size_t nrows, size_t ncols,
        const seclink_emat_t inmat,
        const char *seckey, size_t seckeybytes);


#ifdef __cplusplus
}
#endif
