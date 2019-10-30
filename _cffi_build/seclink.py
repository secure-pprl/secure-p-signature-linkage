import os.path

from cffi import FFI

ffibuilder = FFI()

_path = os.path.dirname(__file__)
sourcefile = os.path.join(_path, 'seclink.cc')

with open(sourcefile, 'r') as f:
    source = f.read()


ffibuilder.set_source(
    "_libseclink",
    source,
    source_extension='.cc',
    extra_compile_args=['-Wall', '-Wextra', '-std=gnu++17', '-O3'],
    include_dirs=["./", "_cffi_build/"],
    libraries=['seal'],
    sources=['_cffi_build/encrypt.cc', '_cffi_build/decrypt.cc', '_cffi_build/multiply.cc',
             '_cffi_build/secure-linkage.cc']
)

ffibuilder.cdef("""
    typedef struct seclink_ctx *seclink_ctx_t;

void seclink_init_ctx(seclink_ctx_t *ctx,
        size_t polmod_deg, uint64_t plain_mod,
        uint64_t prng_seed[2]);

void seclink_clear_ctx(seclink_ctx_t ctx);


void seclink_keygen(const seclink_ctx_t ctx,
        char **public_key, size_t *public_key_bytes,
        char **secret_key, size_t *secret_key_bytes,
        char **galois_keys, size_t *galois_keys_bytes,
        char **relin_keys, size_t *relin_keys_bytes);

void seclink_clear_key(char *key);


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
""")


if __name__ == "__main__":
    ffibuilder.compile(verbose=True)

