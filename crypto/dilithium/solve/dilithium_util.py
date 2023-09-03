import ctypes
from sage.all import GF, PolynomialRing, Matrix

dilithium_lib = ctypes.CDLL('../src/libpqcrystals_dilithium2_ref.so')
K = 4
L = 2
q = 2**23 - 2**13 + 1
D = 13
GAMMA1 = 1 << 17
OMEGA = 80
BETA = 78
N = 256
F = GF(q)
P = PolynomialRing(F, 'X')
X = P.gens()[0]
R = P.quotient_ring(X**N + 1, 'Xbar')

poly_t = ctypes.c_int32 * N
polyveck_t = poly_t * K
polyvecl_t = poly_t * L

def balanced_mod(v):
    return int((v + q//2) % q) - q//2

def ll_to_polylist(l):
    return list(map(list, list(l)))

def to_bytes(v):
    return bytes(list(v))

def to_R(v):
    return R(list(v))

def to_RL(v):
    return (R**L)(ll_to_polylist(v))

def to_polyvecl(v, balanced=False):
    if balanced:
        return polyvecl_t(*[poly_t(*[balanced_mod(x) for x in list(v[i])]) for i in range(L)])
    return polyvecl_t(*[poly_t(*list(v[i])) for i in range(L)])

def to_polyveck(v, balanced=False):
    if balanced:
        return polyveck_t(*[poly_t(*[balanced_mod(x) for x in list(v[i])]) for i in range(K)])
    return polyveck_t(*[poly_t(*list(v[i])) for i in range(K)])

def to_RK(v):
    return (R**K)(ll_to_polylist(v))

def unpack_sig(sig_bytes):
    c = (ctypes.c_uint8 * 32)()
    z = polyvecl_t()
    h = polyveck_t()
    dilithium_lib.pqcrystals_dilithium2_ref_unpack_sig(c, z, h, ctypes.c_buffer(sig_bytes))
    return (to_bytes(c), to_RL(z), to_RK(h))

def pack_sig(c, z, h):
    sig = (ctypes.c_uint8 * 1268)()
    z_ = to_polyvecl(z, balanced=True)
    h_ = to_polyveck(h)
    dilithium_lib.pqcrystals_dilithium2_ref_pack_sig(sig, ctypes.c_buffer(c), z_, h_)
    return to_bytes(sig)

def poly_challenge(seed):
    c = poly_t()
    dilithium_lib.pqcrystals_dilithium2_ref_poly_challenge(c, ctypes.c_buffer(seed))
    return to_R(c)

def unpack_pk(pk_bytes):
    rho = (ctypes.c_uint8 * 32)()
    t1 = polyveck_t()
    dilithium_lib.pqcrystals_dilithium2_ref_unpack_pk(rho, t1, ctypes.c_buffer(pk_bytes))
    return (to_bytes(rho), to_RK(t1))

# note the returned mat (ctypes object) is Ahat, i.e. A in NTT domain
def matrix_expand(rho):
    mat = (polyvecl_t * K)()
    dilithium_lib.pqcrystals_dilithium2_ref_polyvec_matrix_expand(mat, ctypes.c_buffer(rho))
    return mat

def compute_A_mul_v(Ahat, v):
    vhat = to_polyvecl(v)
    Av = polyveck_t()
    dilithium_lib.pqcrystals_dilithium2_ref_polyvecl_ntt(vhat)
    dilithium_lib.pqcrystals_dilithium2_ref_polyvec_matrix_pointwise_montgomery(Av, Ahat, vhat)
    dilithium_lib.pqcrystals_dilithium2_ref_polyveck_reduce(Av)
    dilithium_lib.pqcrystals_dilithium2_ref_polyveck_invntt_tomont(Av)
    return to_RK(Av)

def polyvecl_uniform_gamma1(seed, nonce=0):
    y = polyvecl_t()
    dilithium_lib.pqcrystals_dilithium2_ref_polyvecl_uniform_gamma1(y, ctypes.c_buffer(seed), ctypes.c_uint16(nonce))
    return to_RL(y)

def polyveck_decompose(v):
    v1 = polyveck_t()
    v0 = polyveck_t()
    v_ = to_polyveck(v)
    dilithium_lib.pqcrystals_dilithium2_ref_polyveck_decompose(v1, v0, v_)
    return (to_RK(v1), to_RK(v0))

def polyveck_pack_w1(w1):
    r = (ctypes.c_uint8 * (K*192))()
    w1_ = to_polyveck(w1)
    dilithium_lib.pqcrystals_dilithium2_ref_polyveck_pack_w1(r, w1_)
    return to_bytes(r)

def verify(sm, pk):
    if len(sm) < 1268:
        return False
    msg_buf = ctypes.c_buffer(len(sm))
    msg_len = ctypes.c_size_t()
    sm_buf = ctypes.c_buffer(sm)
    pk_buf = ctypes.c_buffer(pk)
    verified = dilithium_lib.pqcrystals_dilithium2_ref_open(msg_buf, ctypes.byref(msg_len), sm_buf, len(sm), pk_buf)
    if verified != 0:
        return False
    return bytes(msg_buf)[:msg_len.value]
