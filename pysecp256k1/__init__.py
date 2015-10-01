from glob import glob
from os import path
import random

try:
    from ._secp256k1 import ffi
except ImportError:
    raise RuntimeError("Required CFFI extension not found. You need to install this package before use. See README.")

try:
    obj_name = glob(path.abspath(path.join(path.dirname(__file__), "libsecp256k1*")))[0]
except RuntimeError:
    raise RuntimeError("Required secp2561 extension not found. You need to install this package before use. See README.")

lib = ffi.dlopen(obj_name)

# ffi definition of the context
ctx = lib.secp256k1_context_create(3)
# arbitrary data used by the nonce generation function
ndata = ffi.new("unsigned char[]", ''.join(chr(random.randint(0, 255)) for i in range(32)))


def secp256k1_ecdsa_sign(msg32, seckey):
    # Make a recoverable signature of 65 bytes
    sig64 = ffi.new("secp256k1_ecdsa_recoverable_signature *")

    lib.secp256k1_ecdsa_sign_recoverable(
        ctx,
        sig64,
        msg32,
        seckey,
        ffi.addressof(lib, "secp256k1_nonce_function_default"),
        ndata,
    )

    # Assign 65 bytes to output
    output64 = ffi.new("unsigned char[65]")
    # ffi definition of recid
    recid = ffi.new("int *")

    lib.secp256k1_ecdsa_recoverable_signature_serialize_compact(
        ctx,
        output64,
        recid,
        sig64
    )

    # Assign recid to the last byte in the output array
    output64[64] = recid[0]
    return output64


def secp256k1_ecdsa_recover(msg32, sig):
    # Setting the pubkey array
    pubkey = ffi.new("secp256k1_pubkey *")
    # Make a recoverable signature of 65 bytes
    rec_sig = ffi.new("secp256k1_ecdsa_recoverable_signature *")
    # Retrieving the recid from the last byte of the signed key
    recid = sig[64]

    lib.secp256k1_ecdsa_recoverable_signature_parse_compact(
        ctx,
        rec_sig,
        sig,
        recid
    )

    lib.secp256k1_ecdsa_recover(
        ctx,
        pubkey,
        rec_sig,
        msg32
    )

    serialized_pubkey = ffi.new("unsigned char[65]")
    outputlen = ffi.new("size_t *")

    lib.secp256k1_ec_pubkey_serialize(
        ctx,
        serialized_pubkey,
        outputlen,
        pubkey,
        0  # SECP256K1_EC_COMPRESSED
    )

    buf = ffi.buffer(serialized_pubkey, 65)
    return buf[:]
