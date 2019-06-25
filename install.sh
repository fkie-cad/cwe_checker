#!/usr/bin/env bash

echo "Cleaning up"
make clean

echo "Building docker container"
docker build --build-arg=http{,s}_proxy --build-arg=HTTP{,S}_PROXY -t cwe-checker .

exit 0
