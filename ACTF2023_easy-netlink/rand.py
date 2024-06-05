import random

xx = []
for i in range(1024):
    x = random.randint(1, 255)
    while x == ord('"'):
        x = random.randint(1, 255)
    xx.append(x)

for i in xx:
    print("\\"+"x"+hex(i)[2:].zfill(2), end="")
print("")


