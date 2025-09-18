#!/bin/bash

set -e

mkdir -p build
cd build

cmake ..
make

cp libcrypto.so ../src/python_wrapper/
echo "complete: libcrypto.so copiada a src/python_wrapper/"