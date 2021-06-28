#!/usr/bin/env python3

from pwn import * 

conn = remote('140.113.207.240',8833)

conn.send('hi\n')
conn.send('n\n')
conn.send(chr(28)+chr(22)+chr(33)+chr(27)+'\n')

conn.recvuntil('language: ')
print(conn.recvall())

conn.close()
