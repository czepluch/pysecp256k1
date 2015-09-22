# cffi specific setup.
from cffi import FFI
ffi = FFI()

ffi.set_source("secp256k1._secp", None)
ffi.cdef('''
            typedef struct secp256k1_context_struct secp256k1_context_t;

            /** Flags to pass to secp256k1_context_create. */
            # define SECP256K1_CONTEXT_VERIFY 0
            # define SECP256K1_CONTEXT_SIGN   1

            secp256k1_context_t* secp256k1_context_create(
              int flags
            );

            typedef int (*secp256k1_nonce_function_t)(
              unsigned char *nonce32,
              const unsigned char *msg32,
              const unsigned char *key32,
              unsigned int attempt,
              const void *data
            );

            extern const secp256k1_nonce_function_t secp256k1_nonce_function_default;

            int secp256k1_ecdsa_sign_compact(
              const secp256k1_context_t* ctx,
              const unsigned char *msg32,
              unsigned char *sig64,
              const unsigned char *seckey,
              secp256k1_nonce_function_t noncefp,
              const void *ndata,
              int *recid
            );

            int secp256k1_ecdsa_recover_compact(
              const secp256k1_context_t* ctx,
              const unsigned char *msg32,
              const unsigned char *sig64,
              unsigned char *pubkey,
              int *pubkeylen,
              int compressed,
              int recid
            );
         ''')

if __name__ == '__main__':
    ffi.compile()
