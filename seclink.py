from cffi import FFI
import weakref
import numpy as np

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
''')


def create_ctx(poldeg = 4096, plain_mod = 40961):
    def clear_ctx(ctx):
        lib.seclink_clear_ctx(ctx[0])

    ctx = ffi.new('seclink_ctx_t *')
    lib.seclink_init_ctx(ctx, poldeg, plain_mod, ffi.NULL)
    weakref.finalize(ctx, clear_ctx, ctx)

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


def _clear_emat(emat):
    lib.seclink_clear_emat(emat[0])


def _encrypt_matrix(ctx, mat, pkey, encrypt_fn):
    # TODO: Use the other elements of __array_interface__ to handle
    # more complicated arrays, with offsets, striding, etc.

    assert mat.dtype == np.int64
    nrows, ncols = mat.__array_interface__['shape']
    mat_data, ro_flag = mat.__array_interface__['data']
    assert mat_data is not None

    mat_p = ffi.cast("int64_t *", mat_data)
    pkey_buf = ffi.from_buffer(pkey)

    emat = ffi.new('seclink_emat_t *')
    encrypt_fn(ctx, emat, mat_p, nrows, ncols, pkey_buf, len(pkey));
    weakref.finalize(emat, _clear_emat, emat)

    return emat[0];


def encrypt_left(ctx, mat, pkey):
    mat = mat.reshape(mat.shape, order='C') # Ensure matrix is row-major
    return _encrypt_matrix(ctx, mat, pkey, lib.seclink_encrypt_left)


def encrypt_right(ctx, mat, pkey):
    mat = mat.reshape(mat.shape, order='F') # Ensure matrix is column-major
    return _encrypt_matrix(ctx, mat, pkey, lib.seclink_encrypt_right)


def matmul(ctx, lmat, rmat, gkeys):
    prod = ffi.new('seclink_emat_t *')
    gkeys_buf = ffi.from_buffer(gkeys)
    lib.seclink_multiply(ctx, prod, lmat, rmat, gkeys_buf, len(gkeys))
    weakref.finalize(prod, _clear_emat, prod)

    return prod[0]

def _emat_shape(emat):
    nrows = ffi.new('size_t *')
    ncols = ffi.new('size_t *')
    lib.seclink_emat_shape(nrows, ncols, emat)
    return nrows[0], ncols[0]


def decrypt(ctx, inmat, skey):
    nrows, ncols = _emat_shape(inmat)
    outmat = np.empty(shape = (nrows, ncols), dtype = np.int64)
    outmat_data, ro_flag = outmat.__array_interface__['data']
    assert outmat_data is not None
    assert ro_flag is False

    outmat_p = ffi.cast("int64_t *", outmat_data)
    skey_buf = ffi.from_buffer(skey)
    lib.seclink_decrypt(ctx, outmat_p, nrows, ncols, inmat, skey_buf, len(skey))

    return outmat


def run_test():
    print('creating context')
    ctx = create_ctx()
    print('generating keys...')
    pk, sk, gk, _ = keygen(ctx)

    nrows = 8
    ncols = 4
    A = np.ones(shape=(nrows, ncols), dtype=np.int64)
    B = (3*A).reshape(ncols, nrows, order='F')

    print('encrypting left matrix...')
    eA = encrypt_left(ctx, A, pk)
    print('encrypting right matrix...')
    eB = encrypt_right(ctx, B, pk)

    print('multiplying encrypted matrices...')
    prod = matmul(ctx, eA, eB, gk)
    print('decrypting product matrix...')
    out = decrypt(ctx, prod, sk)

    print('out =')
    print(out)
    print('')
    print('A*B = ')
    print(A @ B)
    print('')
    okay = (out == A @ B).all()
    print('result is correct? ', okay)
