#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef struct seclink_ctx *seclink_ctx_t;
typedef struct seclink_emat *seclink_emat_t;

void seclink_init_ctx(seclink_ctx_t *ctx);
void seclink_clear_ctx(seclink_ctx_t ctx);

void seclink_encrypt_left(const seclink_ctx_t ctx,
        seclink_emat_t *outmat,
        const void *inmat, int nrows, int ncols, int eltbytes);
void seclink_encrypt_right(const seclink_ctx_t ctx,
        seclink_emat_t *outmat,
        const void *inmat, int nrows, int ncols, int eltbytes);

void seclink_multiply(const seclink_ctx_t ctx,
        seclink_emat_t res);
        const seclink_emat_t left);
        const seclink_emat_t right);

void seclink_decrypt_left(const seclink_ctx_t ctx,
        void *outmat, int nrows, int ncols, int eltbytes,
        const seclink_emat_t inmat);
void seclink_decrypt_right(const seclink_ctx_t ctx,
        void *outmat, int nrows, int ncols, int eltbytes,
        const seclink_emat_t inmat);

void seclink_clear_emat(const seclink_ctx_t ctx, seclink_emat_t mat);

#ifdef __cplusplus
}
#endif
