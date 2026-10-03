#!/bin/sh
# Build and run the automated tests (Linux / WSL, gcc). Run from the repo root.
set -e
gcc -g -Wall -Itests/stub -I. -fsanitize=address,undefined \
    user.c hash.c tests/test_blockchain.c \
    -Wl,--wrap=time -Wl,--wrap=SSHA -o tests/test_blockchain
ASAN_OPTIONS=detect_leaks=0 ./tests/test_blockchain
