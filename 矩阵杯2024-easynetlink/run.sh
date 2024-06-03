#!/bin/sh

#gcc -o fs/exploit exploit.c -lmnl

#cd fs
#find . | cpio -o --format=newc > ../rootfs.img
#cd ..


qemu-system-x86_64 \
    -m 4G \
    -kernel bzImage \
    -initrd rootfs.img \
    -monitor /dev/null \
    -append "root=/dev/ram console=ttyS0 oops=panic quiet panic=1 kaslr" \
    -cpu kvm64,+smep,+smap\
    -netdev user,id=t0, -device e1000,netdev=t0,id=nic0 \
    -nographic \
    -no-reboot \
    -s
