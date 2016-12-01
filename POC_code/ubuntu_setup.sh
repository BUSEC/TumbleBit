#!/bin/bash

# Configure Ubuntu

# Build essentials, OpenSSL & Boost
sudo apt-get update
sudo apt-get install libtool pkg-config build-essential autoconf automake
sudo apt-get install libboost-all-dev
sudo apt-get install libzmq3-dev
sudo apt-get install python-pip

# Install ZMQ
git clone https://github.com/zeromq/libzmq
CPPFLAGS=-DZMQ_MAKE_VALGRIND_HAPPY
cd libzmq
./autogen.sh
./configure
make -j 4
make check
make install
sudo ldconfig
cd ..
rm -rf libzmq/

# Install LibreSSL
wget http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-2.3.4.tar.gz
tar -xzvf libressl-2.3.4.tar.gz
cd libressl-2.3.4
./configure
make
sudo make install
sudo ldconfig
cd ..
rm -rf libressl-2.3.4
rm libressl-2.3.4.tar.gz

# Install python dependencies
pip install -r requirements.txt

sudo apt-get install libzmq-dev
