from pwn import *
import base64

conn = remote('94.237.54.170',52118)

hex = conn.recvuntil('?').decode('utf-8').split('\n')[-2].split(' ')[-1]
print(hex)
conn.send(hex + '\n')

def get_bytes(i):
    binary = ELF(f'bin{i}.elf')
    lea_address = binary.read(binary.entry + 7, 4)
    offset = int.from_bytes(lea_address, 'little', signed=True)
    answer_bytes = binary.read(binary.entry + 11 + offset, 24).hex()
    print(answer_bytes)
    return answer_bytes

i = 0
while(True):
    elf = ''
    while(True):
        ans = conn.recvline().decode('utf-8')
        print(ans)
        if('ELF' in ans):
            elf = ans.split(' ')[-1]
            break
    with open(f'bin{i}.elf', 'wb') as f:
        print(elf)
        f.write(base64.b64decode(elf))
    print(conn.recvuntil('?').decode('utf-8'))
    conn.send(get_bytes(i) + '\n')
    i = i+1