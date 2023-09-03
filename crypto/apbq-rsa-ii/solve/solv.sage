import itertools
from Crypto.Util.number import long_to_bytes

# n, c, hints
exec(open('../src/output.txt', 'r').read())

V = hints
k = 2^800
M = Matrix.column([k * v for v in V]).augment(Matrix.identity(len(V)))
B = [b[1:] for b in M.LLL()]
M = (k * Matrix(B[:len(V)-2])).T.augment(Matrix.identity(len(V)))
B = [b[-len(V):] for b in M.LLL() if set(b[:len(V)-2]) == {0}]

for s, t in itertools.product(range(4), repeat=2):
    T = s*B[0] + t*B[1]
    a1, a2, a3 = T
    kq = gcd(a1 * hints[1] - a2 * hints[0], n)
    if 1 < kq < n:
        print('find!', kq, s, t)
        break
for i in range(2**16, 1, -1):
    if kq % i == 0:
        kq //= i
q = int(kq)
p = int(n // kq)
d = pow(0x10001, -1, (p - 1) * (q - 1))
m = pow(c, d, n)
flag = long_to_bytes(m).decode()
print(flag)
