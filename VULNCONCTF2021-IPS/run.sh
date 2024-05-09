#!/bin/sh

gcc -static -w exploit.c -o fs/exploit
cd fs
find . | cpio -o --format=newc > ../initramfs.cpio
cd ..
gzip initramfs.cpio

qemu-system-x86_64 \
  -m 256M \
  -initrd initramfs.cpio.gz \
  -kernel ./bzImage -nographic \
  -monitor /dev/null \
  -append "kpti=1 +smep +smap kaslr root=/dev/ram rw console=ttyS0 oops=panic paneic=1 quiet" \
  -s
