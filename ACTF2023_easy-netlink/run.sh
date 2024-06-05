#!/bin/bash

#gcc -o fs/home/ctf/exploit exploit.c -lmnl
#cd fs/home/ctf
#patchelf --replace-needed libc.so.6 ./libc.so.6 exploit
#patchelf --set-interpreter ./ld-linux-x86-64.so.2 exploit
#patchelf --replace-needed libmnl.so.0 ./libmnl.so.0 exploit
#cd ../../
#find . | cpio -o --format=newc > ../rootfs.cpio
#cd ..
#gzip rootfs.cpio

#exec timeout 300 qemu-system-x86_64 \
qemu-system-x86_64 \
    -m 128M \
    -nographic \
    -kernel ./bzImage \
    -append 'console=ttyS0 oops=panic panic=1 quiet loglevel=3 kaslr' \
    -monitor /dev/null \
    -initrd ./rootfs.cpio.gz  \
    -smp cores=2,threads=2 \
    -cpu kvm64,smep,smap \
    -no-reboot \
    -s
