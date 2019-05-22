from cffi import FFI
import weakref

ffi = FFI()
lib = ffi.dlopen('libseclink.so')
print('Loaded lib {0}'.format(lib))

# Copypasta from 'seclink.h'
ffi.cdef('''
typedef struct seclink_ctx *seclink_ctx_t;

void seclink_init_ctx(seclink_ctx_t *ctx,
        size_t polmod_deg, uint64_t plain_mod,
        uint64_t prng_seed[2]);

void seclink_clear_ctx(seclink_ctx_t ctx);


void seclink_keygen(const seclink_ctx_t ctx,
        char **public_key, size_t *public_key_bytes,
        char **secret_key, size_t *secret_key_bytes,
        char **galois_keys, size_t *galois_keys_bytes, int galois_key_bits,
        char **relin_keys, size_t *relin_keys_bytes, int relin_key_bits);


typedef struct seclink_emat *seclink_emat_t;

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
''')


def create_ctx(poldeg = 4096, plain_mod = 40961):
    def clr_ctx(ctx):
        lib.seclink_clear_ctx(ctx[0])

    ctx = ffi.new('seclink_ctx_t *')
    lib.seclink_init_ctx(ctx, poldeg, plain_mod, ffi.NULL)
    weakref.finalize(ctx, clr_ctx, ctx)

    # See https://cffi.readthedocs.io/en/latest/using.html for why we
    # need to use "subscript 0".
    return ctx[0];


def keygen(ctx):
    # TODO: There must be a way to create a kind of memoryview over
    # the char array rather than copying
    def key_to_bytes(carr, nbytes):
        return b''.join(carr[0][j] for j in range(nbytes[0]))

    pkey = ffi.new('char **'); plen = ffi.new('size_t *')
    skey = ffi.new('char **'); slen = ffi.new('size_t *')
    gkey = ffi.new('char **'); glen = ffi.new('size_t *')
    rkey = ffi.new('char **'); rlen = ffi.new('size_t *')

    lib.seclink_keygen(ctx, pkey, plen, skey, slen, gkey, glen, 30, rkey, rlen, 30)

    pkey_ = key_to_bytes(pkey, plen)
    skey_ = key_to_bytes(skey, slen)
    gkey_ = key_to_bytes(gkey, glen)
    rkey_ = key_to_bytes(rkey, rlen)

    lib.seclink_clear_key(pkey[0])
    lib.seclink_clear_key(skey[0])
    lib.seclink_clear_key(gkey[0])
    lib.seclink_clear_key(rkey[0])

    return pkey_, skey_, gkey_, rkey_


def encrypt_left(ctx, rowmat, pkey):
    pass


def encrypt_right(ctx, rowmat, pkey):
    pass


def matmul(ctx, lmat, rmat, gkeys):
    pass


def decrypt(ctx, mat, skey):
    pass
