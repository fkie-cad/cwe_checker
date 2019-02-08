#!/bin/bash
echo "Installing cross compiler for ARM architecture."
sudo apt install -y gcc-multilib-arm-linux-gnueabi g++-arm-linux-gnueabi
echo "Installing cross compiler for MIPS architecture."
sudo apt install -y gcc-multilib-mips-linux-gnu g++-7-mips-linux-gnu
echo "Installing cross compiler for PPC architecture."
sudo apt install -y gcc-multilib-powerpc-linux-gnu g++-7-powerpc-linux-gnu
echo "Installing dockcross image for x86 C++ cross-compiler"
docker pull dockcross/linux-x86
docker run --rm dockcross/linux-x86 > ./dockcross-linux-x86
chmod +x ./dockcross-linux-x86
echo "Done."
