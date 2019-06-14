#!/bin/bash
expected_version="18.04"
actual_version=`lsb_release -r | awk '{ print $2 }'`

if [ "$expected_version" != "$actual_version" ]; then
	echo "Probably running on Travis CI"
    echo "Installing cross compiler for MIPS architecture."
    sudo apt install -y gcc-multilib-mips-linux-gnu g++-5-mips-linux-gnu
    echo "Installing cross compiler for PPC architecture."
    sudo apt install -y gcc-multilib-powerpc-linux-gnu g++-5-powerpc-linux-gnu
else
    echo "Running on Ubuntu $expected_version"
    echo "Installing cross compiler for MIPS architecture."
    sudo apt install -y gcc-multilib-mips-linux-gnu g++-7-mips-linux-gnu
    echo "Installing cross compiler for PPC architecture."
    sudo apt install -y gcc-multilib-powerpc-linux-gnu g++-7-powerpc-linux-gnu
fi

echo "Installing cross compiler for ARM architecture."
sudo apt install -y gcc-multilib-arm-linux-gnueabi g++-arm-linux-gnueabi
echo "Installing dependencies for x86 compilation"
sudo docker pull dockcross/linux-x86
sudo docker run --rm dockcross/linux-x86 > ./dockcross-linux-x86
chmod +x ./dockcross-linux-x86
echo "Done."
