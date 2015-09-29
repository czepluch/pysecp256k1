# cffi specific setup.
from cffi import FFI
ffi = FFI()

ffi.set_source("secp256k1._secp256k1", None)
ffi.cdef('''
            typedef struct secp256k1_context_struct secp256k1_context;

            typedef struct {
                unsigned char data[65];
            } secp256k1_ecdsa_recoverable_signature;

            typedef struct {
                unsigned char data[64];
            } secp256k1_pubkey;

            /** Flags to pass to secp256k1_context_create. */
            # define SECP256K1_CONTEXT_VERIFY 0
            # define SECP256K1_CONTEXT_SIGN   1

            secp256k1_context* secp256k1_context_create(
              unsigned int flags
            );

            typedef int (*secp256k1_nonce_function)(
                unsigned char *nonce32,
                const unsigned char *msg32,
                const unsigned char *key32,
                const unsigned char *algo16,
                void *data,
                unsigned int attempt
            );

            extern const secp256k1_nonce_function secp256k1_nonce_function_default;

            int secp256k1_ecdsa_recoverable_signature_serialize_compact(
                const secp256k1_context* ctx,
                unsigned char *output64,
                int *recid,
                const secp256k1_ecdsa_recoverable_signature* sig
            );

            int secp256k1_ecdsa_sign_recoverable(
              const secp256k1_context* ctx,
              secp256k1_ecdsa_recoverable_signature *sig,
              const unsigned char *msg32,
              const unsigned char *seckey,
              secp256k1_nonce_function noncefp,
              const void *ndata
            );

            int secp256k1_ecdsa_recover(
              const secp256k1_context* ctx,
              secp256k1_pubkey *pubkey,
              const secp256k1_ecdsa_recoverable_signature *sig,
              const unsigned char *msg32
            );
         ''')

if __name__ == '__main__':
    ffi.compile()
