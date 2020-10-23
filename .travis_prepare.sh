#!/bin/bash
cd test/artificial_samples/
./install_cross_compilers.sh
scons
cd ../unit/
./specify_test_files_for_compilation.sh
cd ../..
docker build -t cwe-checker .
docker build -t cwe-checker-ghidra -f ghidra.Dockerfile .