from glob import glob
from os import path
# from ethereum.utils import zpad, int_to_big_endian
import random

try:
    from ._c_secp256k1 import ffi
except ImportError:
    raise RuntimeError("Required CFFI extension not found. You need to install this package before use. See README.")

try:
    obj_name = glob(path.abspath(path.join(path.dirname(__file__), "libsecp256k1*")))[0]
except RuntimeError:
    raise RuntimeError("Required secp256k1 extension not found. You need to run 'python setup.py build' or se README")

lib = ffi.dlopen(obj_name)

# ffi definition of the context
ctx = lib.secp256k1_context_create(3)
# arbitrary data used by the nonce generation function
ndata = ffi.new("unsigned char[]", ''.join(chr(random.randint(0, 255)) for i in range(32)))


def secp256k1_ecdsa_sign(msg32, seckey):
    """
        Takes a message of 32 bytes and a private key
        Returns a unsigned char array of length 65 containing the signed message
    """
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
    """
     Takes the message of length 32 and the signed message
     Returns the public key of the private key from the sign function
    """
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


# Convert a signed key to a tuple
def to_python_tuple(output):
    """
    Takes the output from the secp256k1_ecdsa_sign function 
    Return a tuple  (v, r, s)
    """
    buf = ffi.buffer(output, 65)
    v = buf[64]
    r = buf[:32]
    s = buf[32:64]
    vrs = long(v.encode('hex'), 16) + 27, long(r.encode('hex'), 16), long(s.encode('hex'), 16)
    return vrs


def from_python_tuple((v, r, s)):
    """
    Takes the tuple (v, r, s) and returns a unsigned char[65] array
    """
    # Assign 65 bytes to output
    sig = ffi.new("unsigned char[65]")
    sig[64] = int(bytearray.fromhex('{:01x}'.format(v)))
    sig[:32] = int(bytearray.fromhex('{:016x}'.format(r)))
    sig[32:64] = int(bytearray.fromhex('{:016x}'.format(s)))
    return sig[:]


# Function matching the signature that pyethereum already uses
def ecdsa_raw_sign(rawhash, key):
    """
     Takes a rawhash message and a private key and returns a tuple
     of the v, r, s values.
    """
    output = secp256k1_ecdsa_sign(rawhash, key)
    return to_python_tuple(output)


def ecdsa_raw_recover(rawhash, (v, r, s)):
    """
     Takes a rawhash message of length 32 bytes and a (v, r, s) tuple
     Returns a public key for the private key used in the sign function
    """
    vrs = from_python_tuple((v, r, s))
    return ecdsa_raw_recover(rawhash, vrs)








