Bitcoin secp256k1 C library wrapped with CFFI.

Benchmarks
----------
These results are achieved on an Intel Core i5-4200U CPU @ 1.6GHz::

    cffi took: 0.75secs / 74μs per op  / 13391 signs per sec

    cffi took: 1.09secs / 109μs per op  / 9170 recovers per sec

Usage
-----
This library offers sign, recover and verify from the secp256k1 bitcoin lib used like this::

    sign = ecdsa_sign_raw(msg32, seckey)

    pubkey = ecdsa_recover_raw(msg32, sig)

    ecdsa_verify_raw(msg32, sig, pubkey)

Dependencies
------------
On Ubuntu::

    # install dependencies
    $ sudo apt-get install libssl-dev libffi-dev libtool python-dev autoconf automake

    # test dependencies
    $ sudo apt-get install python-tox


Installation
------------
Clone repo::

    git clone https://github.com/czepluch/pysecp256k1.git


Install
-------

To install package::

    python setup.py install


Development
-----------

To install::

    python setup.py develop


Test
----

To test and install test dependenceis::

    python setup.py test


Generate source & binary pakacages
----------------------------------

To generate installable source and binary packages::

    python setup.py sdist bdist_wheel
