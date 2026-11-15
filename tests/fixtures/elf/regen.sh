#!/bin/sh
# regen.sh - rebuilds the fixture objects and their expectations. The committed .o/.so/exe and .expect files are what the test
# uses; this script is only needed to change a fixture. It needs gcc, g++ and python3 with pyelftools (pip install pyelftools).
#   usage: tests/fixtures/elf/regen.sh
set -eu
cd "$(dirname "$0")"
COMMON="-O2 -ffunction-sections -fdata-sections -g1 -fno-stack-protector"
gcc  -c $COMMON -ffreestanding -fno-pic -fno-pie -mcmodel=kernel -mno-red-zone -mno-sse -mno-mmx kmod.c -o kmod.o
g++  -c -O1 -ffunction-sections -fdata-sections -g1 -fno-pic -fno-pie cxx.cc -o cxx.o
gcc  -shared -fPIC -nostdlib $COMMON -ffreestanding -Wl,--hash-style=gnu -Wl,-soname,libfixture.so -Wl,--build-id=none lib.c -o lib.so
gcc  -static -no-pie -nostdlib $COMMON -ffreestanding -Wl,-e,_start -Wl,--build-id=none exe.c -o exe
strip --strip-all -o exe.stripped exe
strip --strip-all -o lib.stripped.so lib.so
for f in kmod.o cxx.o lib.so exe lib.stripped.so exe.stripped; do python3 make_expect.py "$f" > "$f.expect"; done
{ echo "gcc: $(gcc --version | head -1)"; echo "g++: $(g++ --version | head -1)"; echo "ld: $(ld --version | head -1)"; } > TOOLCHAIN
ls -l kmod.o cxx.o lib.so exe lib.stripped.so exe.stripped *.expect
