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
# ffi definition of the sig uint array
# sig64 = ffi.new("secp256k1_ecdsa_recoverable_signature[65]")
sig64 = ffi.new("secp256k1_ecdsa_recoverable_signature *")
# ffi definition of recid
recid = ffi.new("int *")
# arbitrary data used by the nonce generation function
ndata = ffi.new("unsigned char[]", ''.join(chr(random.randint(0, 255)) for i in range(32)))
output64 = ffi.new("unsigned char[64]")


def secp256k1_ecdsa_sign(msg32, seckey):
    lib.secp256k1_ecdsa_sign_recoverable(
        ctx,
        sig64,
        msg32,
        seckey,
        ffi.addressof(lib, "secp256k1_nonce_function_default"),
        ndata,
    )
    return sig64


def secp256k1_ecdsa_recoverable_signature_serialize_compact(sig64):
    lib.secp256k1_ecdsa_recoverable_signature_serialize_compact(
        ctx,
        output64,
        recid,
        sig64
    )
    recbuf = ffi.buffer(recid, 1)
    rec = recbuf[:]
    print('Recid: ' + rec)
    buf = ffi.buffer(output64, 64)
    output = buf[:]
    print(output.encode('hex'))
    return output

# Setting the pubkey array
pubkey = ffi.new("secp256k1_pubkey *")


def secp256k1_ecdsa_recover(msg32, vrs):
    lib.secp256k1_ecdsa_recover(
        ctx,
        pubkey,
        vrs,
        msg32
    )
    buf = ffi.buffer(pubkey, 65)
    return buf[:]
