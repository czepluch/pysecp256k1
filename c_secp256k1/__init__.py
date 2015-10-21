from glob import glob
from os import path
import random
from bitcoin import electrum_sig_hash as _b_electrum_sig_hash
from bitcoin import encode_pubkey as _b_encode_pubkey
from bitcoin import ecdsa_raw_verify as _b_ecdsa_raw_verify
from bitcoin import encode_sig as _b_encode_sig
from bitcoin import decode_sig as _b_decode_sig

try:
    from ._c_secp256k1 import ffi
except ImportError as e:
    raise ImportError(
        "CFFI extension not found. You need to install this package before use. %r" % e)

try:
    obj_name = glob(path.abspath(path.join(path.dirname(__file__), "libsecp256k1*")))[0]
except Exception as e:
    raise ImportError(
        "secp256k1 lib not found. You need to run 'python setup.py build' or see README %r" % e)

lib = ffi.dlopen(obj_name)

# ffi definition of the context
ctx = lib.secp256k1_context_create(3)
# arbitrary data used by the nonce generation function
ndata = ffi.new("unsigned char[]", ''.join(chr(random.randint(0, 255)) for i in range(32)))

# helpers


def _int_to_big_endian(value):
    cs = []
    while value > 0:
        cs.append(chr(value % 256))
        value /= 256
    s = ''.join(reversed(cs))
    return s


def _big_endian_to_int(value):
    return int(value.encode('hex'), 16)


def _lzpad32(x):
    return '\x00' * (32 - len(x)) + x


def _encode_sig(v, r, s):
    assert isinstance(v, (int, long))
    assert v in (27, 28)
    vb, rb, sb = chr(v - 27), _int_to_big_endian(r), _int_to_big_endian(s)
    return _lzpad32(rb) + _lzpad32(sb) + vb


def _decode_sig(sig):
    return ord(sig[64]) + 27, _big_endian_to_int(sig[0:32]), _big_endian_to_int(sig[32:64])


def _verify_seckey(seckey):
    # Validate seckey
    is_valid = lib.secp256k1_ec_seckey_verify(ctx, seckey)
    return is_valid


def _deserialize_pubkey(pub):
    pubkey = ffi.new("secp256k1_pubkey *")
    # Return 1 if pubkey is valid
    valid_pub = lib.secp256k1_ec_pubkey_parse(
        ctx,        # const secp256k1_context*
        pubkey,     # secp256k1_pubkey*
        pub,        # const unsigned char
        len(pub)    # size_t
    )
    assert valid_pub == 1
    return pubkey


def _serialize_pubkey(pub):
    serialized_pubkey = ffi.new("unsigned char[65]")
    outputlen = ffi.new("size_t *")

    # Serialize a pubkey object into a serialized byte sequence.
    lib.secp256k1_ec_pubkey_serialize(
        ctx,
        serialized_pubkey,
        outputlen,
        pub,
        0  # SECP256K1_EC_COMPRESSED
    )
    return serialized_pubkey


def _der_deserialize_signature(in_sig):
    sig = ffi.new("secp256k1_ecdsa_signature *")
    # Return 1 when signature could be parsed
    valid_sig = lib.secp256k1_ecdsa_signature_parse_der(
        ctx,        # const secp256k1_context*
        sig,        # secp256k1_ecdsa_signature*
        in_sig,     # const unsigned char
        len(in_sig)    # size_t
    )
    assert valid_sig == 1
    return sig


def _der_serialize_pubkey(sig):
    serialized_pubkey = ffi.new("unsigned char[65]")
    outputlen = ffi.new("size_t *")

    # Serialize a pubkey object into a serialized byte sequence.
    lib.secp256k1_ecdsa_signature_serialize_der(
        ctx,
        serialized_pubkey,
        outputlen,
        sig,                # secp256k1_ecdsa_signature *
        0  # SECP256K1_EC_COMPRESSED
    )
    return serialized_pubkey


# compact encoding


def ecdsa_sign_recoverable(msg32, seckey):
    """
        Takes a message of 32 bytes and a private key
        Returns a recoverable signature of length 64
    """
    assert isinstance(msg32, bytes)
    assert isinstance(seckey, bytes)
    assert len(msg32) == len(seckey) == 32
    assert _verify_seckey(seckey) == 1

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
    return sig64


def ecdsa_sign_compact(msg32, seckey):
    """
        Takes the same message and seckey as ecdsa_sign_recoverable
        Returns an unsigned char array of length 65 containing the signed message
    """
    # Assign 65 bytes to output
    output64 = ffi.new("unsigned char[65]")
    # ffi definition of recid
    recid = ffi.new("int *")

    lib.secp256k1_ecdsa_recoverable_signature_serialize_compact(
        ctx,
        output64,
        recid,
        ecdsa_sign_recoverable(msg32, seckey)
    )

    # Assign recid to the last byte in the output array
    r = ffi.buffer(output64)[:64] + chr(recid[0])
    assert len(r) == 65, len(r)
    return r


def ecdsa_parse_recoverable_signature(sig):
    """
        Takes a signed compact message 
        Returns a parsed recoverable signature of length 65 bytes
    """
    # Buffer for getting values of signature object
    assert isinstance(sig, bytes)
    assert len(sig) == 65

    # Make a recoverable signature of 65 bytes
    rec_sig = ffi.new("secp256k1_ecdsa_recoverable_signature *")
    # Retrieving the recid from the last byte of the signed key
    recid = ord(sig[64])

    # Parse a revoverable signature
    parsable_sig = lib.secp256k1_ecdsa_recoverable_signature_parse_compact(
        ctx,
        rec_sig,
        sig,
        recid
    )
    # Verify that the signature is parsable
    assert parsable_sig == 1

    return rec_sig


def ecdsa_recover_compact(msg32, sig):
    """
        Takes the a message and a parsed recoverable signature
        Returns the serialized public key from the private key in the sign function
    """
    assert isinstance(msg32, bytes)
    assert len(msg32) == 32
    # Check that recid is of valid value
    if not (_big_endian_to_int(sig[64]) >= 0 and
            _big_endian_to_int(sig[64]) <= 3):
        # raise Exception("invalid recid")
        return

    # Setting the pubkey array
    pubkey = ffi.new("secp256k1_pubkey *")

    lib.secp256k1_ecdsa_recover(
        ctx,
        pubkey,
        ecdsa_parse_recoverable_signature(sig),
        msg32
    )

    serialized_pubkey = _serialize_pubkey(pubkey)

    buf = ffi.buffer(serialized_pubkey, 65)
    r = buf[:]
    assert isinstance(r, bytes)
    assert len(r) == 65, len(r)
    return r


def ecdsa_verify_compact(msg32, sig, pub):
    """
        Takes a message of length 32 and a signed message and a pubkey
        Returns True if the signature is valid
    """
    assert isinstance(msg32, bytes)
    assert len(msg32) == 32
    assert len(pub) == 65
    assert len(sig) == 65

    # Setting the pubkey array
    c_sig = ffi.new("secp256k1_ecdsa_signature *")

    # converts the recoverable signature to a signature
    lib.secp256k1_ecdsa_recoverable_signature_convert(
        ctx,
        c_sig,
        sig
    )

    is_valid = lib.secp256k1_ecdsa_verify(
        ctx,
        c_sig,  # const secp256k1_ecdsa_signature
        msg32,  # const unsigned char
        _deserialize_pubkey(pub)  # const secp256k1_pubkey
    )
    print("verify returned"), is_valid
    return is_valid == 1


# raw encoding (v, r, s)


def ecdsa_sign_raw_recoverable(msg32, seckey):
    """
        Takes a message of 32 bytes and a private key
        Returns a recoverable signature of length 64
    """
    return ecdsa_sign_recoverable(msg32, seckey)


def ecdsa_sign_raw(rawhash, key):
    """
        Takes a rawhash message and a private key and returns a tuple
        of the v, r, s values.
    """
    return _decode_sig(ecdsa_sign_compact(rawhash, key))


def ecdsa_parse_raw_recoverable_signature(vrs):
    """
        Takes a raw signed message
        Returns a pased recoverable signature of length 65 bytes
    """
    return ecdsa_parse_recoverable_signature(_encode_sig(*vrs))


def ecdsa_recover_raw(rawhash, vrs):
    """
        Takes a rawhash message of length 32 bytes and a (v, r, s) tuple
        Returns a public key for the private key used in the sign function
    """
    assert len(vrs) == 3
    return ecdsa_recover_compact(rawhash, _encode_sig(*vrs))


def ecdsa_verify_raw(msg32, sig, pub):
    """
        Takes a message, the signature being verified and a pubkey
        Returns 1 if signature is valid with given pubkey
    """
    return ecdsa_verify_compact(msg32, sig, pub)


# DER encoding

def ecdsa_sign_der_recoverable(msg32, seckey):
    return ecdsa_sign_recoverable(msg32, seckey)


def ecdsa_sign_der(msg, seckey):
    return _b_encode_sig(*ecdsa_sign_raw(_b_electrum_sig_hash(msg), seckey))


def ecdsa_recover_der(msg, sig):
    return _b_encode_pubkey(ecdsa_recover_raw(_b_electrum_sig_hash(msg), _b_decode_sig(sig)),
                            'hex')


def ecdsa_verify_der(msg, sig, pub):
    return ecdsa_verify_raw(_b_electrum_sig_hash(msg), _b_decode_sig(sig), pub.decode('hex'))
