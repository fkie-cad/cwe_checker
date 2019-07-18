#!/bin/bash
cd test/artificial_samples/
./install_cross_compilers.sh
scons
cd ../..
docker build -t cwe-checker .
