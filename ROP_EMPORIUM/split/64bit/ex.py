from pwn import *

e = ELF('./split')

e.search(b'/bin/cat\x00')
