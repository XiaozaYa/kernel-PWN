#!/bin/sh

gcc -w -static -masm=intel -Os -pthread exp.c -o fs/exp

cd fs
find . | cpio -o --format=newc > ../rootfs.cpio

cd ..
gzip rootfs.cpio
mv rootfs.cpio.gz rootfs.cpio
