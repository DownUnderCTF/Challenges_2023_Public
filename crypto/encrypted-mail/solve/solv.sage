from pwn import *
import ast, _pickle
from time import time
from string import ascii_letters, digits
from tqdm import tqdm
from binteger import Bin

g = 3
p = 1467036926602756933667493250084962071646332827366282684436836892199877831990586034135575089582195051935063743076951101438328248410785708278030691147763296367303874712247063207281890660681715036187155115101762255732327814001244715367

class Cipher:
    def __init__(self, key):
        self.n = 4
        self.idx = self.n
        self.state = [(key >> (32 * i)) & 0xffffffff for i in range(self.n)]

    def next(self):
        if self.idx == self.n:
            for i in range(self.n):
                x = self.state[i]
                v = x >> 1
                if x >> 31:
                    v ^^= 0xa9b91cc3
                if x & 1:
                    v ^^= 0x38ab48ef
                self.state[i] = v ^^ self.state[(i + 3) % self.n]
            self.idx = 0

        v = self.state[self.idx]
        x0, x1, x2, x3, x4 = (v >> 31) & 1, (v >> 24) & 1, (v >> 18) & 1, (v >> 14) & 1, v & 1
        y = x0 + x1 + x2 + x3 + x4

        self.idx += 1
        return y & 1

    def next_byte(self):
        return int(''.join([str(self.next()) for _ in range(8)]), 2)

    def xor(self, A, B):
        return bytes([a ^^ b for a, b in zip(A, B)])

    def decrypt(self, ciphertext):
        return self.xor(ciphertext, [self.next_byte() for _ in ciphertext])


class Symbolic_Cipher:
    a1 = 0xa9b91cc3
    a2 = 0x38ab48ef
    n = 4
    B = BooleanPolynomialRing(32 * n, 's')
    F = GF(2)
    A = Matrix(F, [Bin(a1 ^^ (1 << 30), n=32).list])
    A = A.stack(Matrix.column([0] * 30).augment(Matrix.column([0] * 30)).augment(Matrix.identity(30)))
    A = A.stack(vector(Bin(a2, n=32).list))

    def __init__(self, state=None, idx=n):
        if state is not None:
            self.state = state
        else:
            Bvars = list(Symbolic_Cipher.B.gens())
            self.state = [vector(Bvars[i:i+32]) for i in range(0, 32*Symbolic_Cipher.n, 32)]
        self.idx = idx

    def next(self):
        if self.idx == Symbolic_Cipher.n:
            for i in range(Symbolic_Cipher.n):
                x = self.state[i]
                self.state[i] = self.state[(i + 3) % Symbolic_Cipher.n] + x * Symbolic_Cipher.A.change_ring(x.base_ring())
            self.idx = 0

        v = self.state[self.idx]
        x0, x1, x2, x3, x4 = v[0], v[7], v[13], v[17], v[31]
        y = x0 + x1 + x2 + x3 + x4

        self.idx += 1
        return y

def register(username, pubkey):
    conn.sendlineafter(b'> ', b'R')
    conn.sendlineafter(b'Username: ', username.encode())
    conn.sendlineafter(b'Public key: ', str(pubkey).encode())

def get_login_challenges(username):
    conn.sendlineafter(b'> ', b'L')
    conn.sendlineafter(b'Username: ', username.encode())
    challenges = ast.literal_eval(conn.recvline().decode())
    conn.sendlineafter(b'Answers: ', b'0')
    return challenges

def login_with_privkey(username, privkey):
    conn.sendlineafter(b'> ', b'L')
    conn.sendlineafter(b'Username: ', username.encode())
    challenges = ast.literal_eval(conn.recvline().decode())
    answers = []
    for c in challenges:
        if pow(c[0], privkey, p) == c[1]:
            answers.append(1)
        else:
            answers.append(0)
    conn.sendlineafter(b'Answers: ', ' '.join(map(str, answers)).encode())

def login_with_rand(username, rand):
    conn.sendlineafter(b'> ', b'L')
    conn.sendlineafter(b'Username: ', username.encode())
    answers = []
    for _ in range(128):
        answers.append(int(round(rand.random())))
        rand.getrandbits(768)
        rand.getrandbits(768)
    conn.sendlineafter(b'Answers: ', ' '.join(map(str, answers)).encode())

def view_inbox():
    conn.sendlineafter(b'> ', b'V')
    o = conn.recvline().decode()
    if 'Log in first' in o or 'Inbox is empty' in o:
        return False
    n = int(o.split('You have ')[1].split(' messages')[0])
    inbox = []
    for _ in range(n):
        conn.recvline()
        msg_enc = bytes.fromhex(conn.recvline().decode())
        sig = ast.literal_eval(conn.recvline().decode())
        conn.recvline()
        inbox.append((msg_enc, sig))
    return inbox

def send_forged_message(recipient, key, ct, sig):
    conn.sendlineafter(b'> ', b'S')
    conn.sendlineafter(b'Recipient user: ', recipient.encode())
    recipient_pubkey = int(conn.recvline().decode().split('Recipient public key: ')[1])
    r = 1337
    c1 = pow(g, r, p)
    c2 = pow(recipient_pubkey, r, p) * key % p
    key_enc = int(c1).to_bytes(96, 'big') + int(c2).to_bytes(96, 'big')
    conn.sendlineafter(b'Encrypted message: ', (key_enc + ct).hex().encode())
    conn.sendlineafter(b'Signature: ', ' '.join(map(str, sig)).encode())

offline_start = time()
print('loading precomp images...')
fn = f'mt-images-precomp.pickle'
images = _pickle.load(open(fn, 'rb'))

M = []
print('building matrix rows...')
for i in range(624*32):
    row = [0] * 624*32
    for k in images[i]:
        row[k] = 1
    row = [row[0]] + row[32:]
    M.append(row)

print('building matrix...')
M = Matrix(GF(2), M)

print('precomputing symbolic cipher outputs...')
sym_cipher = Symbolic_Cipher()
prefix_sym_bits = [sym_cipher.next() for _ in range(13*8)]
name_sym_bits = [sym_cipher.next() for _ in range(8*8)]

online_start = time()
print('coming online now...')
conn = remote('0.0.0.0', int(1337))
# conn = process(['python3', 'server.py'])

print('gathering random.random() outputs...')
mtwister_privkey = 1234
mtwister_pubkey = pow(g, mtwister_privkey, p)
register('mtwister', mtwister_pubkey)
mt_randoms = []
for _ in tqdm(range(156)):
    challenges = get_login_challenges('mtwister')
    for c in challenges:
        if pow(c[0], mtwister_privkey, p) == c[1]:
            mt_randoms.append(1)
        else:
            mt_randoms.append(0)

print('adding outputs to matrix...')
M = M.augment(vector(mt_randoms))

print('checking nullity...')
print('nullity is', M.right_nullity())

print('checking solution')
sol = M.right_kernel_matrix()[0][:-1]
sol = [sol[0]] + [0] * 31 + list(sol[1:])
recovered_state = [Bin(sol[i:i+32]).int for i in range(0, 624*32, 32)]
random.setstate((3, tuple(recovered_state + [624]), None))
all_good = 1
for i in range(624*32):
    all_good &= round(random.random()) == mt_randoms[i]
    random.getrandbits(768)
    random.getrandbits(768)
print('all good:', bool(all_good))

# register some users to get messages from the admin, then try to solve
# for a key which will turn the decrypted plaintext into the give flag message
j = 0
while True:
    privkey = 31337 + j
    pubkey = pow(g, privkey, p)
    username = ''.join(random.Random().choices(ascii_letters+digits, k=12))
    register(username, pubkey)
    login_with_rand(username, random)
    inbox = view_inbox()
    assert len(inbox) == 1
    msg_enc, sig = inbox[0]
    msg_ct = msg_enc[192:]
    target_bits = Bin(xor(msg_ct[:13], b'Send flag to '), n=13*8).list
    name_target_bits = Bin(msg_ct[13:], n=64).list
    eqs = [prefix_sym_bits[i] - target_bits[i] for i in range(13*8)]
    eqs += [name_sym_bits[::8][i] - name_target_bits[::8][i] for i in range(8)]
    eqs += [name_sym_bits[1::8][i] - name_target_bits[1::8][i] - 1 for i in range(8)]
    M, V = Sequence(eqs).coefficient_matrix()
    print('cipher M nullity:', M.right_nullity())
    rk = M.right_kernel()
    for v in tqdm(rk):
        if rk[-1] == 0:
            continue
        st = Bin(sum([list(v[i:i+32]) for i in range(0, 128, 32)][::-1], [])).int
        C = Cipher(st)
        pt = C.decrypt(msg_ct)
        if pt.startswith(b'Send flag to ') and all(c in (ascii_letters+digits).encode() for c in pt[13:]):
                print('found good cipher key!', st)
                print('decrypts ct to:', pt)
                break
    else:
        j += 1
        continue
    break
        
forgery_key = st
target_username = pt[13:].decode()

print(f'registering {target_username}...')
privkey = 1337
pubkey = pow(g, privkey, p)
register(target_username, pubkey)

print('logging in as admin...')
login_with_rand('admin', random)
print('sending message as admin...')
send_forged_message('flag_haver', forgery_key, msg_ct, sig)

print(f'logging in as {target_username}...')
login_with_rand(target_username, random)
inbox = view_inbox()
assert len(inbox) == 2
msg_enc, _ = inbox[1]
key_enc, ct = msg_enc[:192], msg_enc[192:]
key_enc0, key_enc1 = int.from_bytes(key_enc[:96]), int.from_bytes(key_enc[96:])
key = key_enc1 * pow(key_enc0, -privkey, p) % p
flag = Cipher(key).decrypt(ct)
print(flag.decode())

print(f'took {time() - online_start}s online')
print(f'took {time() - offline_start}s total')
