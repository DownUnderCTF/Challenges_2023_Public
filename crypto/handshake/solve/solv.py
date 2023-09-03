from pwn import *
from Crypto.PublicKey import ECC
from Crypto.Hash import HMAC, SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import struct
import hlextend

you_cert = open('../src/public/you.cert', 'r').read()
admin_cert = open('../src/public/admin.cert', 'r').read()
you_privkey = ECC.import_key(open('../src/public/you-privkey.pem', 'r').read())
server_pubkey = ECC.import_key(open('../src/public/server-pubkey.pem', 'r').read())

def connect():
    return remote('0.0.0.0', 1337)
    # return process(['python3', 'server.py'], cwd='../src')

conn = connect()
conn.recvuntil(b'Please provide your certificate:\n')
conn.sendline(admin_cert.encode())
conn.sendlineafter(b'Client nonce: ', xor(b'DUCTF-2023' + b'\x00' * 54, b'\x36' * 64).hex().encode())
server_nonce1 = conn.recvline().decode().strip().split('Server nonce: ')[1]
shared_nonce1 = conn.recvline().decode().strip().split('Shared nonce: ')[1]
conn.close()

conn = connect()
conn.recvuntil(b'Please provide your certificate:\n')
conn.sendline(admin_cert.encode())
hl = hlextend.new('sha256')
append = hl.extend(b'', bytes.fromhex(server_nonce1), 64 + 32, shared_nonce1)
conn.sendlineafter(b'Client nonce: ', append.hex().encode())
server_nonce2 = conn.recvline().decode().strip().split('Server nonce: ')[1]
shared_nonce2 = conn.recvline().decode().strip().split('Shared nonce: ')[1]

hl = hlextend.new('sha256')
z = hl.extend(bytes.fromhex(server_nonce2 + shared_nonce2), bytes.fromhex(server_nonce1), 64 + 32, shared_nonce1)
hmac_inner = bytes.fromhex(hl.hexdigest())
prk = SHA256.new(xor(b'DUCTF-2023' + b'\x00' * 54, b'\x5c' * 64) + hmac_inner).digest()
hmac = HMAC.new(prk, struct.pack('B', 1), digestmod=SHA256)
derived_key = hmac.digest()[:32]

ct = bytes.fromhex(conn.recvline().decode())
aes = AES.new(derived_key, AES.MODE_ECB)
msg = unpad(aes.decrypt(ct), 16)
print(msg.decode())
