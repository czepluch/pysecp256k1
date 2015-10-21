# -*- coding: utf-8 -*-
import random
random.seed(12312421412)
from bitcoin import privtopub, encode_pubkey
from bitcoin import ecdsa_raw_sign as b_ecdsa_raw_sign
from bitcoin import ecdsa_raw_recover as b_ecdsa_raw_recover
from bitcoin import ecdsa_sign as b_ecdsa_sign_der
from bitcoin import ecdsa_recover as b_ecdsa_recover_der
import time
from c_secp256k1 import ecdsa_recover_compact as c_ecdsa_recover_compact
from c_secp256k1 import ecdsa_sign_compact as c_ecdsa_sign_compact
from c_secp256k1 import ecdsa_verify_compact as c_ecdsa_verify_compact
from c_secp256k1 import ecdsa_sign_raw as c_ecdsa_sign_raw
from c_secp256k1 import ecdsa_verify_raw as c_ecdsa_verify_raw
from c_secp256k1 import ecdsa_recover_raw as c_ecdsa_recover_raw
from c_secp256k1 import ecdsa_sign_raw_recoverable as c_ecdsa_sign_raw_recoverable
from c_secp256k1 import ecdsa_parse_raw_recoverable_signature as c_ecdsa_parse_raw_recoverable_signature
from c_secp256k1 import ecdsa_sign_der as c_ecdsa_sign_der
from c_secp256k1 import ecdsa_recover_der as c_ecdsa_recover_der
from c_secp256k1 import ecdsa_verify_der as c_ecdsa_verify_der
from c_secp256k1 import ecdsa_sign_der_recoverable as c_ecdsa_sign_der_recoverable
from c_secp256k1 import ecdsa_sign_recoverable as c_ecdsa_sign_recoverable
from c_secp256k1 import ecdsa_parse_recoverable_signature as c_ecdsa_parse_recoverable_signature
from c_secp256k1 import _encode_sig as c_encode_sig
from c_secp256k1 import _decode_sig as c_decode_sig


priv = ''.join(chr(random.randint(0, 255)) for i in range(32))
pub = privtopub(priv)
msg32 = ''.join(chr(random.randint(0, 255)) for i in range(32))
msgN = ''.join(chr(random.randint(0, 255)) for i in range(128))


def test_raw():
    vrs1 = b_ecdsa_raw_sign(msg32, priv)
    assert isinstance(vrs1, tuple)
    assert len(vrs1) == 3
    vrs3 = c_ecdsa_sign_raw(msg32, priv)
    p1 = b_ecdsa_raw_recover(msg32, vrs1)
    p3 = c_ecdsa_recover_raw(msg32, vrs1)
    p4 = c_ecdsa_recover_raw(msg32, vrs3)
    p5 = b_ecdsa_raw_recover(msg32, vrs3)

    # Ensure that recovered pub key is the same
    assert encode_pubkey(p1, 'bin') == pub
    assert encode_pubkey(p3, 'bin') == pub
    assert encode_pubkey(p4, 'bin') == pub
    assert encode_pubkey(p5, 'bin') == pub

    # Verify
    # revoverable signature
    rsig = c_ecdsa_sign_raw_recoverable(msg32, priv)
    # parsed signature
    psig = c_ecdsa_parse_raw_recoverable_signature(vrs3)

    assert c_ecdsa_verify_raw(msg32, rsig, p3)
    assert c_ecdsa_verify_raw(msg32, psig, p3)

    # check wrong pub
    wrong_vrs = c_ecdsa_sign_raw(msg32, 'x'*32)
    p2 = c_ecdsa_recover_raw(msg32, wrong_vrs)
    assert encode_pubkey(p2, 'bin') != pub
    assert not c_ecdsa_verify_raw(msg32, rsig, p2)
    assert not c_ecdsa_verify_raw(msg32, psig, p2)


def test_compact():
    vrs_compact = c_ecdsa_sign_compact(msg32, priv)
    # Recoverable signature
    rsig = c_ecdsa_sign_recoverable(msg32, priv)
    # Parsed signature
    psig = c_ecdsa_parse_recoverable_signature(vrs_compact)
    assert isinstance(vrs_compact, bytes)
    assert len(vrs_compact) == 65
    p3 = c_ecdsa_recover_compact(msg32, vrs_compact)

    assert encode_pubkey(p3, 'bin') == pub
    assert c_ecdsa_verify_compact(msg32, rsig, p3)
    assert c_ecdsa_verify_compact(msg32, psig, p3)

    # check wrong pub
    wrong_vrs = c_ecdsa_sign_compact(msg32, 'x'*32)
    p4 = c_ecdsa_recover_compact(msg32, wrong_vrs)
    assert encode_pubkey(p4, 'bin') != pub
    assert not c_ecdsa_verify_compact(msg32, rsig, p4)
    assert not c_ecdsa_verify_compact(msg32, psig, p4)


def test_robustness():
    vrs_compact = c_ecdsa_sign_compact(msg32, priv)
    p3 = c_ecdsa_recover_compact(msg32, vrs_compact[:-1] + 'x')  # should not segfault


def test_der():
    vrs_der = c_ecdsa_sign_der(msgN, priv)
    assert isinstance(vrs_der, bytes)
    p3 = c_ecdsa_recover_der(msgN, vrs_der)
    assert p3 == pub.encode('hex')
    p2 = b_ecdsa_recover_der(msgN, vrs_der)
    assert p2 == pub.encode('hex')

    rsig = c_ecdsa_sign_der_recoverable(msg32, priv)
    # psig = c_ecdsa_parse_der_recoverable_signature(vrs_der)
    assert encode_pubkey(p3, 'bin') == pub
    assert c_ecdsa_verify_der(msg32, vrs_der, p3)
    # assert c_ecdsa_verify_der(msg32, psig, p3)

    # check wrong pub
    p4 = c_ecdsa_recover_der(msg32, 'x' + vrs_compact[1:])
    assert encode_pubkey(p4, 'bin') != pub
    assert not c_ecdsa_verify_der(msg32, rsig, p4)
    assert not c_ecdsa_verify_der(msg32, psig, p4)

# Recovery with pure python solution


def test_ecrecover(rounds=100):
    vrs1 = b_ecdsa_raw_sign(msg32, priv)
    st = time.time()
    for i in range(rounds):
        p = b_ecdsa_raw_recover(msg32, vrs1)
    elapsed = time.time() - st
    print 'py took: %.2fsecs / %dμs per op / %d recoveries per sec' % \
        (elapsed, elapsed / rounds * 10**6, rounds / elapsed)


# Recovery with same random private key using cffi
def test_cecrecover(rounds=100):
    vrs_compact = c_ecdsa_sign_compact(msg32, priv)
    st = time.time()
    for i in range(rounds):
        p = c_ecdsa_recover_compact(msg32, vrs_compact)
    elapsed = time.time() - st
    print 'cffi took: %.2fsecs / %dμs per op  / %d recoveries per sec' % \
        (elapsed, elapsed / rounds * 10**6, rounds / elapsed)
    print 'c  takes: 300μs per op / 3000 recoveries per sec'  # c wraped in go, according to gustav


def rand32bytes():
    return ''.join(chr(random.randint(0, 255)) for i in range(32))


def perf(rounds=1000):
    privkeys = [rand32bytes() for i in range(rounds)]
    messages = [rand32bytes() for i in range(rounds)]
    # test sign
    signatures = []
    st = time.time()
    for priv, msg in zip(privkeys, messages):
        s = c_ecdsa_sign_compact(msg32, priv)
        signatures.append(s)
    elapsed = time.time() - st
    print 'cffi took: %.2fsecs / %dμs per op  / %d signs per sec' % \
        (elapsed, elapsed / rounds * 10**6, rounds / elapsed)

    # test recover
    pubs = []
    st = time.time()
    for sig, msg in zip(signatures, messages):
        p = c_ecdsa_recover_compact(msg32, sig)
        pubs.append(p)
    elapsed = time.time() - st
    print 'cffi took: %.2fsecs / %dμs per op  / %d recovers per sec' % \
        (elapsed, elapsed / rounds * 10**6, rounds / elapsed)

    # check
    for pub, privkey in zip(pubs, privkeys)[:100]:
        assert privtopub(privkey) == pub

if __name__ == '__main__':
    test_ecrecover(100)
    test_cecrecover(10000)
    perf(10000)
