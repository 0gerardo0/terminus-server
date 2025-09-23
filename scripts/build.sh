#!/bin/bash

set -e

#gcc -fPIC -shared -o libcrypto.so crypto.c -lsodiium
mkdir -p build
cd build

cmake ..
make

cp libcrypto.so ../src/python_wrapper/
echo "complete: libcrypto.so copiada a src/python_wrapper/"

cp libserver_core.so ../src/python_wrapper/
echo "complete: libserver_core.so copiada a src/python_wrapper"
