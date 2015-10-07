secp256k1 C library wrapped with CFFI to use with Python2 and PyPy2.

Benchmarks
----------
These results are achieved on an Intel Core i5-4200U CPU @ 1.6GHz::

    cffi took: 0.75secs / 74μs per op  / 13391 signs per sec

    cffi took: 1.09secs / 109μs per op  / 9170 recovers per sec

Installation
-----------
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
