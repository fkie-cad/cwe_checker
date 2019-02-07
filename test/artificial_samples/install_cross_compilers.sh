#!/bin/bash
echo "Installing cross compiler for ARM architecture."
docker pull dockcross/linux-armv7
docker run --rm dockcross/linux-armv7 > ./dockcross-linux-armv7
chmod +x ./dockcross-linux-armv7
echo "Installing cross compiler for MIPS architecture."
docker pull dockcross/linux-mips
docker run --rm dockcross/linux-mips > ./dockcross-linux-mips
chmod +x ./dockcross-linux-mips
echo "Installing cross compiler for PPC architecture."
docker pull dockcross/linux-ppc64le
docker run --rm dockcross/linux-ppc64le > ./dockcross-linux-ppc64le
chmod +x ./dockcross-linux-ppc64le
echo "Installing dockcross image for x86 C++ cross-compiler"
docker pull dockcross/linux-x86
docker run --rm dockcross/linux-x86 > ./dockcross-linux-x86
chmod +x ./dockcross-linux-x86
echo "Done."
