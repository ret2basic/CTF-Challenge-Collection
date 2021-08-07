#!/usr/bin/env sage
from pwn import *
from Crypto.Util.number import long_to_bytes

#--------Setup--------#

host = "05.cr.yp.toc.tf"
port = 33371

#--------Data--------#

r = remote(host, port)
r.readuntil(b"[Q]uit\n")
r.sendline("C")
data = r.readuntil(b"[Q]uit\n")
enc = int(data.split()[3].decode().strip())

#--------Helper function--------#

def encrypt_int(n):
    r.sendline("T")
    r.readuntil(" your message to encrypt:\n")
    r.sendline(str(n))
    data = r.readuntil(b"[Q]uit\n")
    b = int(data.split()[3].decode().strip())
    return b

#--------Step 1: compute b--------#

b = encrypt_int(0)

#--------Step 2: compute a--------#

c = encrypt_int(1)
a = c - b - 1

#--------Step 3: compute p--------#

enc_kp = encrypt_int(100)
kp = (100**3 + a*100 + b) - enc_kp
p = max(f[0] for f in factor(kp))

#--------Step 4: recover m--------$

PR.<x> = PolynomialRing(GF(p))
f = x^3 + a * x + b - enc
roots = f.roots()
print(roots)

for root in roots:
    flag = root[0]
    print(long_to_bytes(flag))

r.interactive()