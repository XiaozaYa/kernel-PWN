#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/syscalls.h>

#ifndef __NR_BROHAMMER
#define __NR_BROHAMMER 333
#endif

unsigned long flips = 0;

SYSCALL_DEFINE2(brohammer, long *, addr, long, bit)
{
        if (flips >= 1)
        {
                printk(KERN_INFO "brohammer: nope\n");
                return -EPERM;
        }

        *addr ^= (1ULL << (bit));
        (*(long *) &flips)++;

        return 0;
}
