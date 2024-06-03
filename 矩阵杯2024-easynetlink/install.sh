#!/bin/sh
sudo apt install autoconf automake libtool

git clone git://git.netfilter.org/libmnl
cd libmnl
./autogen.sh
./configure --prefix=/usr && make
sudo make install
cd ..
