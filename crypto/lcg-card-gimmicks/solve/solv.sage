from pwn import *
from random import randint
import time
from tqdm import tqdm

DECK = [f'{val}{suit}' for suit in 'CDHS' for val in ['A', '2', '3', '4', '5', '6', '7', '8', '9', '10', 'J', 'Q', 'K']] + ['RJ', 'BJ']
M = 2**64

class LCG:
    def __init__(self, seed, A=None, C=None):
        self.M = 2**64
        if A is None:
            self.A = randint(1, self.M) | 1
        else:
            self.A = A
        if C is None:
            self.C = randint(1, self.M)
        else:
            self.C = C
        self.seed = seed

    def __str__(self):
        o = f'A = {self.A}\n'
        o += f'C = {self.C}\n'
        o += f'M = {self.M}'
        return o

    def next(self):
        self.seed = (self.A * self.seed + self.C) % self.M
        return self.seed

    def between(self, lo, hi):
        r = self.next()
        return lo + (r >> 16) % (hi - lo)

def ith_const(i, x1_L, A, C, M):
    return (A^i * x1_L + sum(A^j for j in range(i)) * C)

def attempt():
    # conn = process('../src/hard.py')
    conn = remote('0.0.0.0', int(1337))

    A = int(conn.recvline().decode().split('A = ')[1])
    C = int(conn.recvline().decode().split('C = ')[1])
    M = int(conn.recvline().decode().split('M = ')[1])
    hand = conn.recvline().decode().split('My hand: ')[1].strip().split()
    outputs = [DECK.index(card) for card in hand]
    bound = 54

    # get candidates for x1_L
    O0 = [x % 2 for x in outputs]
    O1 = [(x + 1) % 2 for x in outputs]
    x1_L_cands = []
    for lower_16_bits in tqdm(range(2^16)):
        my_rng = LCG(lower_16_bits, A=A, C=C)
        my_hand = [my_rng.between(0, 52) % 2 for _ in range(len(outputs))]
        if my_hand == O0 or my_hand == O1:
            x1_L_cand = (A * lower_16_bits + C) % 2^16
            x1_L_cands.append(x1_L_cand)

    for x1_L in tqdm(x1_L_cands):
        m = len(outputs)
        B = Matrix(ZZ, [2^16 * y for y in outputs])
        B = B.stack(vector([(2^16 * A^i) % M for i in range(m)]))
        B = B.stack(vector([(z := ith_const(i, x1_L, A, C, M)) - (z % 2^16) for i in range(m)]))
        B = B.stack(2^16 * bound * Matrix.identity(m))
        B = B.stack(2^64 * Matrix.identity(m))
        B = B.augment(Matrix.identity(m+3).stack(Matrix.zero(m, m+3)))

        for i in range(m):
            B.rescale_col(i, 2^1024)
        B.rescale_col(m, 2^48)
        B.rescale_col(m+2, 2^48)
        for i in range(m+3, m+3+m):
            B.rescale_col(i, bound)

        B = B.LLL()
        for r in B:
            if abs(r[m+2]) == 2^48:
                ans = set([abs(r[m+1]), -r[m+1] % 2^48, r[m+1] % 2^48])
                for x1_U in ans:
                    seed = (int(x1_U) << 16) | x1_L
                    my_lcg = LCG(seed, A=A, C=C)
                    if outputs[1:] == [my_lcg.between(0, 54) for _ in range(12)]:
                        print('good!')
                        seed = ((seed - C) * pow(A, -1, M)) % M
                        conn.sendlineafter(b'Show me a magic trick: ', str(seed).encode())
                        print(conn.recv().decode())
                        return True

    conn.close()
    return False

while not attempt():
    pass
