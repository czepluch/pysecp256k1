from glob import glob
from os import path
import random

try:
    from ._secp256k1 import ffi
except ImportError:
    raise RuntimeError("Required CFFI extension not found. You need to install this package before use. See README.")

try:
    obj_name = glob(path.abspath(path.join(path.dirname(__file__), "secp*")))[0]
except RuntimeError:
    raise RuntimeError("Required secp2561 extension not found. You need to install this package before use. See README.")

lib = ffi.dlopen(obj_name)


# ffi definition of the context
ctx = lib.secp256k1_context_create(3)
# ffi definition of the sig uint array
sig64 = ffi.new("unsigned char[]", 65)
# ffi definition of recid
recid = ffi.new("int *")
# arbitrary data used by the nonce generation function
ndata = ffi.new("unsigned char[]", ''.join(chr(random.randint(0, 255)) for i in range(32)))


def secp256k1_ecdsa_sign_compact(msg32, seckey):
    lib.secp256k1_ecdsa_sign_compact(
        ctx,
        msg32,
        sig64,
        seckey,
        ffi.addressof(lib, "secp256k1_nonce_function_default"),
        ndata,
        recid
    )
    sig = ffi.buffer(sig64, 65)
    v = ffi.buffer(recid, 1)
    sig[64] = v
    return sig[:]

# Setting the pubkey array
pubkey = ffi.new("unsigned char[]", 65)
# Int to hold the length of the pubkey
pubkeylen = ffi.new("int *")
# Whether to recover a compressed or uncompressed pubkey
compressed = ffi.new("int *")
compressed[0] = 0
# signed message
# vrs = secp256k1_ecdsa_sign_compact(msg32, seckey)


def secp256k1_ecdsa_recover_compact(msg32, vrs):
    lib.secp256k1_ecdsa_recover_compact(
        ctx,
        msg32,
        vrs,
        pubkey,
        pubkeylen,
        compressed[0],
        int(vrs[64].encode('hex'))
    )
    buf = ffi.buffer(pubkey, 65)
    return buf[:]
