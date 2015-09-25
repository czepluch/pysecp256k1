#!/bin/bash

cd ./webthree-helpers/utils/
mkdir build
cd build
cmake ..
make
cd ../../..
cp ./webthree-helpers/utils/build/secp256k1/libsecp256k1.so ./secp256k1/
