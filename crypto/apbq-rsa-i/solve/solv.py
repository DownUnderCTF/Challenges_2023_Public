import itertools
from Crypto.Util.number import long_to_bytes
from tqdm import tqdm
from math import gcd

# n, c, hints
exec(open('../src/output.txt', 'r').read())

for a1, a2 in tqdm(list(itertools.product(range(2**12), repeat=2))):
    kq = gcd(a1 * hints[0] - a2 * hints[1], n)
    if 1 < kq < n:
        print('find!', kq, a1, a2)
        break
for i in range(2**16, 1, -1):
    if kq % i == 0:
        kq //= i
q = kq
p = n // kq
d = pow(0x10001, -1, (p - 1) * (q - 1))
m = pow(c, d, n)
flag = long_to_bytes(m).decode()
print(flag)
