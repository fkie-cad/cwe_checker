#!/bin/bash
echo "Installing cross compiler for ARM architecture."
sudo apt install -y gcc-multilib-arm-linux-gnueabi g++-arm-linux-gnueabi
echo "Installing cross compiler for MIPS architecture."
sudo apt install -y gcc-multilib-mips-linux-gnu g++-5-mips-linux-gnu
echo "Installing cross compiler for PPC architecture."
sudo apt install -y gcc-multilib-powerpc-linux-gnu g++-5-powerpc-linux-gnu
echo "Installing dependencies for x86 compilation"
sudo dpkg --add-architecture i386
sudo apt install -y libc6-dev-i386 libstdc++-5-dev:i386 libc6:i386
echo "Done."
