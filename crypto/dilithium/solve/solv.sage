from tqdm import tqdm
from time import time
from hashlib import shake_256
from os import urandom
from ortools.sat.python import cp_model

from dilithium_util import *

pk_bytes = open('../src/pk.bin', 'rb').read()
rho, t1 = unpack_pk(pk_bytes)

sigs_dat = open('../src/signatures.dat', 'rb').read()
sigs = [sigs_dat[i:i+1272] for i in range(0, len(sigs_dat), 1272)]
print(f'[!] processing {len(sigs)} signatures')

cs_mappings = []
for k in range(N):
    m = list(range(k, -1, -1)) + list(range(-(N-1), -k))
    cs_mappings.append(m)
models = [cp_model.CpModel() for _ in range(L)]
s1_cp_vars = [[models[i].NewIntVar(-2, 2, f's_{i}_{j}') for j in range(N)] for i in range(L)]

num_points = [0] * L
for target in [GAMMA1 - 2, GAMMA1 - 1, GAMMA1]:
    for sig in tqdm(sigs):
        c, z, h = unpack_sig(sig)

        # we cant have both contain a max element or else we might have an incorrect constraint
        is_neg = False
        can_do = [False, False]
        good_j = [None, None]
        for i in range(L):
            cnt = 0
            for j in range(N):
                zij = int(z[i][j])
                if abs(balanced_mod(zij)) == target:
                    if target == GAMMA1:
                        is_neg = verify(sig, pk_bytes) == False
                    if balanced_mod(zij) < 0:
                        is_neg = True
                    good_j[i] = j
                    cnt += 1
            if cnt == 1:
                can_do[i] = True
        if can_do.count(True) != 1:
            continue

        i = can_do.index(True)
        j = good_j[i]

        c_ = [balanced_mod(c_) for c_ in poly_challenge(c).list()]
        idxs = [0] * N
        for l in range(N):
            idxs[abs(cs_mappings[j][l])] = (sgn(cs_mappings[j][l]) | 1) * c_[l]
        cs = sum([int(idxs[l]) * s1_cp_vars[i][l] for l in range(N)])

        if is_neg:
            models[i].AddLinearConstraint(cs, -BETA, GAMMA1 - target - 1)
        else:
            models[i].AddLinearConstraint(cs, target - GAMMA1, BETA)

        num_points[i] += 1

print('[+] got', num_points, 'constraints')

s1_ = []
for i in range(L):
    start = time()
    print(f'[!] solving for s1[{i}]')
    solver = cp_model.CpSolver()
    status = solver.Solve(models[i])
    print('[i] status:', status, 'took', time() - start, 'seconds')
    s1__ = [solver.Value(s1_cp_vars[i][j]) for j in range(N)]
    print(f'[+] recovered s1[{i}]:', s1__)
    s1_.append(s1__)
s1 = (R**L)([R(s1__) for s1__ in s1_])

Ahat = matrix_expand(rho)
As1 = compute_A_mul_v(Ahat, s1)

TARGET_MESSAGE = b'dilithium crystals'
mu = shake_256(shake_256(pk_bytes).digest(int(32)) + TARGET_MESSAGE).digest(int(64))

while True:
    y = polyvecl_uniform_gamma1(urandom(64))
    w = compute_A_mul_v(Ahat, y)
    w1, _ = polyveck_decompose(w)
    w1_packed = polyveck_pack_w1(w1)
    c = shake_256(mu + w1_packed).digest(int(32))
    cp = poly_challenge(c)
    z = y + cp * s1
    verify_w1 = compute_A_mul_v(Ahat, z) - cp * t1 * 2^D
    verify_w1, _ = polyveck_decompose(verify_w1)
    h = verify_w1 - w1
    n = flatten([list(h_) for h_ in h]).count(1)
    if n > OMEGA:
        continue
    sig = pack_sig(c, z, h) + TARGET_MESSAGE
    if verify(sig, pk_bytes) != False:
        break

print(f'[+] forged signature for {TARGET_MESSAGE}:', sig.hex())
