#!/bin/bash
echo "Installing cross compiler for ARM architecture."
sudo apt install -y gcc-arm-linux-gnueabi
echo "Installing cross compiler for MIPS architecture."
sudo apt install -y gcc-mips-linux-gnu
echo "Installing cross compiler for PPC architecture."
sudo apt install -y gcc-powerpc-linux-gnu
echo "Done."
