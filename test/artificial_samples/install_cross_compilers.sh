#!/bin/bash

expected_version="18.04"
actual_version=`lsb_release -r | awk '{ print $2 }'`

echo "Installing cross compiler for Portable Executable x86/x86_64"
sudo apt install -y mingw-w64


echo "Installting multilibs for gcc and g++"
sudo apt install -y gcc-multilib g++-multilib
if [ "$expected_version" != "$actual_version" ]; then
    echo "Installing cross compiler for ELF x86 architecture."
    sudo apt install -y gcc-i686-linux-gnu g++-i686-linux-gnu
fi
echo "Installing cross compiler for ELF ARM architecture."
sudo apt install -y gcc-arm-linux-gnueabi g++-arm-linux-gnueabi
sudo apt install -y gcc-aarch64-linux-gnu g++-aarch64-linux-gnu
echo "Installing cross compiler for ELF MIPS architecture."
sudo apt install -y gcc-mips-linux-gnu g++-mips-linux-gnu
sudo apt install -y gcc-mipsel-linux-gnu g++-mipsel-linux-gnu
sudo apt install -y gcc-mips64-linux-gnuabi64 g++-mips64-linux-gnuabi64
sudo apt install -y gcc-mips64el-linux-gnuabi64 g++-mips64el-linux-gnuabi64
echo "Installing cross compiler for ELF PPC architecture."
sudo apt install -y gcc-powerpc-linux-gnu g++-powerpc-linux-gnu
sudo apt install -y gcc-powerpc64-linux-gnu g++-powerpc64-linux-gnu
sudo apt install -y gcc-powerpc64le-linux-gnu g++-powerpc64le-linux-gnu

echo "Installing llvm compiler backend"
sudo apt install -y llvm
echo "Installing clang compiler frontend"
sudo apt install -y clang

sudo ln -s /usr/include/asm-generic /usr/include/asm

echo "Done."
