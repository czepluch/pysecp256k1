Bitcoin secp256k1 C library wrapped with CFFI to use with Python2 and PyPy2.

Benchmarks
----------
These results are achieved on an Intel Core i5-4200U CPU @ 1.6GHz::

    cffi took: 0.75secs / 74μs per op  / 13391 signs per sec

    cffi took: 1.09secs / 109μs per op  / 9170 recovers per sec

Usage
-----
This library offers sign and recover from the secp256k1 bitcoin lib used like this::

    sig = secp256k1_ecdsa_sign(msg32, seckey)

    pubkey = secp256k1_ecdsa_recover(msg32, sig)

Installation
------------
Clone repo::

    git clone https://github.com/czepluch/pysecp256k1.git

Development
-----------

To install::

    python setup.py develop


Install
-------

To install package::

    python setup.py install

Test
----

To test and install test dependenceis::

    python setup.py test


Generate source & binary pakacages
----------------------------------

To generate installable source and binary packages::

    python setup.py sdist bdist_wheel
