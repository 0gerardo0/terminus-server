#!/bin/bash

set -e

#gcc -fPIC -shared -o libcrypto.so crypto.c -lsodiium
mkdir -p build
cd build

cmake ..
make

echo "complete: build/libterminus_core.so"
