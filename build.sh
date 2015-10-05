#!/bin/bash

cd secp256k1 &&
./autogen.sh &&
./configure --enable-shared --enable-module-recovery &&
make &&
cp .libs/libsecp256k1.so ../pysecp256k1 &&
cd ..
