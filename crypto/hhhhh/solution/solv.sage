from hashlib import md5
from binteger import Bin
from tqdm import tqdm

# solution implemented by joseph

F = GF(2)
V = F^128

TARGET = b'h' * 16

def xor(A, B):
    return bytes([a ^^ b for a, b in zip(A, B)])

def bytes_to_F2_vec(b):
    return V(Bin(b, n=128).list)

def h(prefix, A):
    r = bytes([0] * 16)
    for j in range(len(prefix), len(prefix+A)):
        r = xor(r, md5((prefix+A)[:j+1]).digest())
    return r

prefix = b'a' * 128
blocks = []
with open("f2a.bin", "rb") as fa:
	with open("f2b.bin", "rb") as fb:
		for _ in range(128):
			blocks.append([fa.read(128), fb.read(128)])

M = []
curr_prefix = prefix
rhs = bytes_to_F2_vec(b'\x00' * 16)
for i in tqdm(range(128)):
    A, B = blocks[i]
    hA, hB = bytes_to_F2_vec(h(curr_prefix, A)), bytes_to_F2_vec(h(curr_prefix, B))
    M.append(hA - hB)
    rhs += hB
    curr_prefix += A
M = Matrix(F, M).T
target = bytes_to_F2_vec(TARGET) - bytes_to_F2_vec(h(b'', prefix)) - rhs
sol = M.solve_right(target)
ans = prefix
for i, v in enumerate(sol):
    ans += blocks[i][1-v]

print('result:', h(b'', ans))
print(ans.hex())

from pwn import *
# conn = process(['python3', '../src/hhhhh.py'])
conn = remote('0.0.0.0', int(1337))
conn.sendlineafter(b'h: ', ans.hex().encode())
print(conn.recvline().decode())
