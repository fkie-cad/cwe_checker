#!/usr/bin/env bash

# Script that builds the sample kernel modules and places them in ./build.

set -xeuo pipefail

DOCKER="sudo -E docker"
NAME=lkm_samples

$DOCKER build --progress plain -t ${NAME} .

sudo rm -rf build/

# Create a dummy container, copy the modules, and delete it.
ID=$($DOCKER create ${NAME} /does/not/exist)
$DOCKER cp ${ID}:/build .
$DOCKER rm ${ID}
sudo chown $(id -u):$(id -g) -R ./build
