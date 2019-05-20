#pragma once

#ifdef __cplusplus
extern "C" {
#endif


/* Context management */

typedef struct seclink_ctx *seclink_ctx_t;

void seclink_init_ctx(seclink_ctx_t *ctx,
        std::size_t polmod_deg, std::uint64_t plain_mod,
        std::uint64_t prng_seed[2]);

void seclink_clear_ctx(seclink_ctx_t ctx);


/* Key generation */

void seclink_keygen(const seclink_ctx_t ctx,
        char **public_key, size_t *public_key_bytes,
        char **secret_key, size_t *secret_key_bytes,
        char **galois_keys, size_t *galois_keys_bytes, int galois_key_bits,
        char **relin_keys, size_t *relin_keys_bytes, int relin_key_bits);


/* Linkage */

typedef struct seclink_emat *seclink_emat_t;

void seclink_clear_emat(seclink_emat_t mat);

void seclink_encrypt_left(const seclink_ctx_t ctx,
        seclink_emat_t *outmat,
        const void *inmat, int nrows, int ncols, int eltbytes,
        const char *pubkey, int pubkeybytes);

void seclink_encrypt_right(const seclink_ctx_t ctx,
        seclink_emat_t *outmat,
        const void *inmat, int nrows, int ncols, int eltbytes,
        const char *pubkey, int pubkeybytes);

void seclink_multiply(const seclink_ctx_t ctx,
        seclink_emat_t *res,
        const seclink_emat_t left,
        const seclink_emat_t right,
        const char *galkeys, int galkeysbytes);

void seclink_decrypt(const seclink_ctx_t ctx,
        void *outmat, int nrows, int ncols, int eltbytes,
        const seclink_emat_t inmat,
        const char *seckey, int seckeybytes);


#ifdef __cplusplus
}
#endif
