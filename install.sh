#!/usr/bin/env bash

echo "Cleaning up"
rm -rf src/_build
rm -f src/cwe_checker.plugin 

echo "Building docker container"
docker build --build-arg http_proxy=$http_proxy --build-arg https_proxy=$https_proxy --build-arg HTTP_PROXY=$http_proxy --build-arg HTTPS_PROXY=$https_proxy -t cwe-checker .

exit 0
