#!/usr/bin/env bash

echo "Cleaning up"
rm -rf src/_build
rm -f src/cwe_checker.plugin 

echo "Building docker container"
docker build --build-arg=http{,s}_proxy --build-arg=HTTP{,S}_PROXY -t cwe-checker .

exit 0
