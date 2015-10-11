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
from c_secp256k1 import ecdsa_raw_sign as c_ecdsa_raw_sign
from c_secp256k1 import ecdsa_raw_verify as c_ecdsa_raw_verify
from c_secp256k1 import ecdsa_raw_recover as c_ecdsa_raw_recover
from c_secp256k1 import ecdsa_sign_der as c_ecdsa_sign_der
from c_secp256k1 import ecdsa_recover_der as c_ecdsa_recover_der


priv = ''.join(chr(random.randint(0, 255)) for i in range(32))
pub = privtopub(priv)
msg32 = ''.join(chr(random.randint(0, 255)) for i in range(32))
msgN = ''.join(chr(random.randint(0, 255)) for i in range(128))


def test_raw():
    vrs1 = b_ecdsa_raw_sign(msg32, priv)
    assert isinstance(vrs1, tuple)
    assert len(vrs1) == 3
    vrs3 = c_ecdsa_raw_sign(msg32, priv)
    p1 = b_ecdsa_raw_recover(msg32, vrs1)
    p3 = c_ecdsa_raw_recover(msg32, vrs1)
    p4 = c_ecdsa_raw_recover(msg32, vrs3)
    p5 = b_ecdsa_raw_recover(msg32, vrs3)

    # Ensure that recovered pub key is the same
    assert encode_pubkey(p1, 'bin') == pub
    assert encode_pubkey(p3, 'bin') == pub
    assert encode_pubkey(p4, 'bin') == pub
    assert encode_pubkey(p5, 'bin') == pub


def test_compact():
    vrs_compact = c_ecdsa_sign_compact(msg32, priv)
    assert isinstance(vrs_compact, bytes)
    assert len(vrs_compact) == 65
    p3 = c_ecdsa_recover_compact(msg32, vrs_compact)

    assert encode_pubkey(p3, 'bin') == pub
    assert c_ecdsa_verify_compact(msg32, vrs_compact, p3)

    # check wrong pub
    p4 = c_ecdsa_recover_compact(msg32, 'x' + vrs_compact[1:])
    assert encode_pubkey(p4, 'bin') != pub
    assert not c_ecdsa_verify_compact(msg32, vrs_compact, p4)


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
