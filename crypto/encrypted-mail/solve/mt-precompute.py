from binteger import Bin
import pickle

class MT:
    w, n, m, r = 32, 624, 397, 31
    a = 0x9908b0df
    u, d = 11, 0xffffffff
    s, b = 7, 0x9d2c5680
    t, c = 15, 0xefc60000
    l = 18
    lower_mask = (1 << r) - 1
    upper_mask = ~lower_mask & d

    def __init__(self, state, idx=n):
        self.state = state
        self.idx = idx

    def _twist(self, state):
        state = [x for x in state]
        for k in range(MT.n):
            x = (state[k] & MT.upper_mask) | (state[(k+1) % MT.n] & MT.lower_mask)
            xA = x >> 1
            if x & 1:
                xA = xA ^ MT.a
            state[k] = state[(k + MT.m) % MT.n] ^ xA
        return state

    def _temper(self, y):
        y ^= (y >> MT.u) & MT.d
        y ^= (y << MT.s) & MT.b
        y ^= (y << MT.t) & MT.c
        y ^= (y >> MT.l)
        return y

    # initial idx should be n (so twist gets triggered immediately)
    def extract_number(self):
        if self.idx >= MT.n:
            if self.idx > MT.n:
                raise ValueError('Generator was never seeded')
            self.state = self._twist(self.state)
            self.idx = 0
        y = self.state[self.idx]
        y = self._temper(y)
        self.idx += 1
        return y

from tqdm import tqdm

print('building MT objects...')
mts = []
for si in tqdm(range(624*32-1, -1, -1)):
    S = Bin(1 << si, n=624*32).list
    state = [Bin(S[i:i+32]).int for i in range(0, 624*32, 32)]
    mt = MT(state)
    mts.append(mt)

print('building images...')
images = []
k_start = 0
for k in tqdm(range(50*624*32)):
    Z = [mt.extract_number() for mt in mts]
    if k % 50 == 0:
        v = [i for i in range(624*32) if (Z[i] >> 31) & 1]
        images.append(v)

fn = f'mt-images-precomp.pickle'
pickle.dump(images, open(fn, 'wb'), protocol=5)
print(f'written precomp to {fn}')
