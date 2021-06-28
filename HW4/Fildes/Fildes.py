#!/usr/bin/env python3

from pwn import * 

conn = remote('140.113.207.240',8831)

conn.send('-559038801\n')
conn.send('YOUSHALLNOTPASS\n')

conn.recvuntil(':)\n')
print(conn.recvall())

conn.close()

