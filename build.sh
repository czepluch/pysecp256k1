#!/bin/bash

tar -xzf secp256k1.tar.gz &&
cd bitcoin-secp256k1* &&
./autogen.sh &&
./configure --enable-shared --enable-module-recovery &&
make &&
cp .libs/libsecp256k1.so ../pysecp256k1 &&
cd ..
