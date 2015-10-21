# cffi specific setup.
from cffi import FFI
ffi = FFI()

ffi.set_source("c_secp256k1._c_secp256k1", None)
ffi.cdef('''
            typedef struct secp256k1_context_struct secp256k1_context;

            typedef struct {
                unsigned char data[65];
            } secp256k1_ecdsa_recoverable_signature;

            typedef struct {
                unsigned char data[64];
            } secp256k1_pubkey;

            typedef struct {
                unsigned char data[64];
            } secp256k1_ecdsa_signature;

            /** Flags to pass to secp256k1_context_create. */
            # define SECP256K1_CONTEXT_VERIFY 0
            # define SECP256K1_CONTEXT_SIGN   1

            /** Flag to pass to secp256k1_ec_pubkey_serialize and secp256k1_ec_privkey_export. */
            # define SECP256K1_EC_COMPRESSED  0

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

            int secp256k1_ecdsa_recoverable_signature_parse_compact(
                const secp256k1_context* ctx,
                secp256k1_ecdsa_recoverable_signature* sig,
                const unsigned char *input64,
                int recid
            );

            int secp256k1_ecdsa_recoverable_signature_serialize_compact(
                const secp256k1_context* ctx,
                unsigned char *output64,
                int *recid,
                const secp256k1_ecdsa_recoverable_signature* sig
            );

            int secp256k1_ec_pubkey_parse(
                const secp256k1_context* ctx,
                secp256k1_pubkey* pubkey,
                const unsigned char *input,
                size_t inputlen
            );

            int secp256k1_ec_pubkey_serialize(
                const secp256k1_context* ctx,
                unsigned char *output,
                size_t *outputlen,
                const secp256k1_pubkey* pubkey,
                unsigned int flags
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

            int secp256k1_ecdsa_verify(
              const secp256k1_context* ctx,
              const secp256k1_ecdsa_signature *sig,
              const unsigned char *msg32,
              const secp256k1_pubkey *pubkey
            );

            int secp256k1_ecdsa_recoverable_signature_convert(
              const secp256k1_context* ctx,
              secp256k1_ecdsa_signature* sig,
              const secp256k1_ecdsa_recoverable_signature* sigin
            );

            int secp256k1_ec_pubkey_create(
              const secp256k1_context* ctx,
              secp256k1_pubkey *pubkey,
              const unsigned char *seckey
            );

            int secp256k1_ec_seckey_verify(
              const secp256k1_context* ctx,
              const unsigned char *seckey
            );

            int secp256k1_ecdsa_signature_parse_der(
              const secp256k1_context* ctx,
              secp256k1_ecdsa_signature* sig,
              const unsigned char *input,
              size_t inputlen
            );

            int secp256k1_ecdsa_signature_serialize_der(
              const secp256k1_context* ctx,
              unsigned char *output,
              size_t *outputlen,
              const secp256k1_ecdsa_signature* sig
            );
         ''')

if __name__ == '__main__':
    ffi.compile()
