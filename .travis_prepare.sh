#!/bin/bash

#!/bin/bash
cd test/artificial_samples/
./install_cross_compilers.sh
make
cd ../..
docker build -t cwe-checker .
