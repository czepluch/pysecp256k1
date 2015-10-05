# -*- coding: utf-8 -*-
import random
random.seed(12312421412)
from bitcoin import privtopub, encode_pubkey, ecdsa_raw_sign, ecdsa_raw_recover
import time
from pysecp256k1 import secp256k1_ecdsa_sign, secp256k1_ecdsa_recover, to_python_tuple

priv = ''.join(chr(random.randint(0, 255)) for i in range(32))
pub = privtopub(priv)
msg = ''.join(chr(random.randint(0, 255)) for i in range(32))
vrs1 = ecdsa_raw_sign(msg, priv)
vrs2 = secp256k1_ecdsa_sign(msg, priv)

p1 = ecdsa_raw_recover(msg, vrs1)
p2 = secp256k1_ecdsa_recover(msg, vrs2)

# Ensure that recovered pub key is the same
assert encode_pubkey(p1, 'bin') == pub
assert encode_pubkey(p2, 'bin') == pub


# Recovery with pure python solution
def test_ecrecover(rounds=100):
    st = time.time()
    for i in range(rounds):
        p = ecdsa_raw_recover(msg, vrs1)
    elapsed = time.time() - st
    print 'py took: %.2fsecs / %dμs per op / %d recoveries per sec' % \
        (elapsed, elapsed / rounds * 10**6, rounds / elapsed)


# Recovery with same random private key using cffi
def test_cecrecover(rounds=100):
    st = time.time()
    for i in range(rounds):
        p = secp256k1_ecdsa_recover(msg, vrs2)
    elapsed = time.time() - st
    print 'pypy took: %.2fsecs / %dμs per op  / %d recoveries per sec' % \
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
        s = secp256k1_ecdsa_sign(msg, priv)
        signatures.append(s)
    elapsed = time.time() - st
    print 'cffi took: %.2fsecs / %dμs per op  / %d signs per sec' % \
        (elapsed, elapsed / rounds * 10**6, rounds / elapsed)

    # test recover
    pubs = []
    st = time.time()
    for sig, msg in zip(signatures, messages):
        p = secp256k1_ecdsa_recover(msg, sig)
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
