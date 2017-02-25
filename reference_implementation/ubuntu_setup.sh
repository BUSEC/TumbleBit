#!/bin/sh

# Tested on Ubuntu 16.04.1 LTS

sudo apt-get update
sudo apt-get install libtool pkg-config build-essential autoconf automake

# Install python3 & pip
sudo apt install python3-pip
pip3 install --upgrade pip

# Install LibreSSL
wget https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-2.5.1.tar.gz
tar -xzvf libressl-2.5.1.tar.gz
cd libressl-2.5.1
./configure
make
sudo make install
sudo ldconfig
cd ..
rm -rf libressl-2.5.1
rm libressl-2.5.1.tar.gz
