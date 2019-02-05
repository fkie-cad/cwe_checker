#!/bin/bash
echo "Installing cross compiler for ARM architecture."
sudo docker pull dockcross/linux-arm64
sudo docker run -rm dockcross/linux-arm64 > ./dockcross-linux-arm64
chmod +x ./dockcross-linux-arm64
echo "Installing cross compiler for MIPS architecture."
sudo docker pull dockcross/linux-mips
sudo docker run -rm dockcross/linux-mips > ./dockcross-linux-mips
chmod +x ./dockcross-linux-mips
echo "Installing cross compiler for PPC architecture."
sudo docker pull dockcross/linux-ppc64le
sudo docker run -rm dockcross/linux-ppc64le > ./dockcross-linux-ppc64le
chmod +x ./dockcross-linux-ppc64le
echo "Installing dockcross image for x86 C++ cross-compiler"
sudo docker pull dockcross/linux-x86
sudo docker run -rm dockcross/linux-x86 > ./dockcross-linux-x86
chmod +x ./dockcross-linux-x86
echo "Done."
