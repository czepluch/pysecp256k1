# -*- coding: utf-8 -*-
import random
random.seed(12312421412)
from bitcoin import privtopub, encode_pubkey, ecdsa_raw_sign, ecdsa_raw_recover
import time
from pysecp256k1 import secp256k1_ecdsa_sign, secp256k1_ecdsa_recover

priv = ''.join(chr(random.randint(0, 255)) for i in range(32))
pub = privtopub(priv)
msg = ''.join(chr(random.randint(0, 255)) for i in range(32))
vrs1 = ecdsa_raw_sign(msg, priv)
vrs2 = secp256k1_ecdsa_sign(msg, priv)

p1 = ecdsa_raw_recover(msg, vrs1)
p2 = secp256k1_ecdsa_recover(msg, vrs2)

assert encode_pubkey(p1, 'bin') == pub
assert encode_pubkey(p2, 'bin') == pub


def test_ecrecover(rounds=100):
    st = time.time()
    for i in range(rounds):
        p = ecdsa_raw_recover(msg, vrs1)
    elapsed = time.time() - st
    print 'py took: %.2fsecs / %dμs per op / %d recoveries per sec' % \
        (elapsed, elapsed / rounds * 10**6, rounds / elapsed)


def test_cecrecover(rounds=100):
    st = time.time()
    for i in range(rounds):
        p = secp256k1_ecdsa_recover(msg, vrs2)
    elapsed = time.time() - st
    print 'pypy took: %.2fsecs / %dμs per op  / %d recoveries per sec' % \
        (elapsed, elapsed / rounds * 10**6, rounds / elapsed)
    print 'c  takes: 300μs per op / 3000 recoveries per sec'  # c wraped in go, according to gustav


def profile():
    def test_profile():
        for i in range(100):
            p = secp256k1_ecdsa_recover(msg, vrs2)

    import pstats
    import cProfile

    cProfile.runctx("test_profile()", globals(), locals(), "Profile.prof")
    s = pstats.Stats("Profile.prof")
    s.strip_dirs().sort_stats("time").print_stats()


if __name__ == '__main__':
    # test_ecrecover()
    # test_cecrecover()
    # profile()
    test_ecrecover(100)
    test_cecrecover(10000)
