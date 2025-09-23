#!/bin/bash

set -e

#gcc -fPIC -shared -o libcrypto.so crypto.c -lsodiium
mkdir -p build
cd build

cmake ..
make

cp libterminus_core.so ../src/python_wrapper/
echo "complete: libterminus_core.so copiada a src/python_wrapper"
