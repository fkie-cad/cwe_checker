#!/bin/bash

#!/bin/bash
cd test/artificial_samples/
./install_cross_compilers.sh
scons-3
cd ../..
docker build -t cwe-checker .
