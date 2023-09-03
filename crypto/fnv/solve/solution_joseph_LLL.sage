TARGET = 0x1337133713371337
h0 = 0xcbf29ce484222325
p = 0x00000100000001b3
MOD = 2^64

n = 10
M = Matrix.column([p^(n - i - 1) for i in range(n)] + [-(TARGET - h0*p^n), MOD])
M = M.augment(identity_matrix(n+1).stack(vector([0] * (n+1))))
Q = Matrix.diagonal([2^128] + [2^4] * n + [2^8])
M *= Q
M = M.BKZ()
M /= Q
for r in M:
    if r[0] == 0 and abs(r[-1]) == 1:
        r *= r[-1]
        good = r[1:-1]
        print(good)
        break
inp = []
y = int(h0*p)
t = (h0*p^n + good[0] * p^(n-1)) % MOD
for i in range(n):
    for x in range(256):
        y_ = (int(y) ^^ int(x)) * p^(n-i-1) % MOD
        if y_ == t:
            print('good', i, x)
            inp.append(x)
            if i < n-1:
                t = (t + good[i+1] * p^(n-i-2)) % MOD
                y = ((int(y) ^^ int(x)) * p) % MOD
            break
    else:
        print('bad', i)
print(bytes(inp).hex())
