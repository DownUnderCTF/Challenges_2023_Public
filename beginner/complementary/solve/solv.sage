from Crypto.Util.number import long_to_bytes

n = int(open('../publish/output.txt', 'r').read())
for d in divisors(n):
    m1 = long_to_bytes(d)
    m2 = long_to_bytes(n//d)
    flag = m1 + m2
    if flag.startswith(b'DUCTF'):
        print(flag.decode())
        break
