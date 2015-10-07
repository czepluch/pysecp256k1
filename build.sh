#!/bin/bash

tar -xzf secp256k1.tar.gz &&
cd bitcoin-secp256k1* &&
./autogen.sh &&
./configure --enable-shared --enable-module-recovery &&
make &&
unamestr=`uname`
if [[ "$unamestr" == 'Linux' ]]; then
    cp .libs/libsecp256k1.so ../pysecp256k1
elif [[ "$unamestr" == 'Darwin' ]]; then
    cp .libs/libsecp256k1.0.dylib ../pysecp256k1
fi &&
cd ..
