from pwn import *
import re
from z3 import *

N = 128
_ROL_ = lambda x, i : ((x << i) | (x >> (N-i)))

conn = remote('83.136.253.251',31642)
conn.recvline()
for i in range(3):
    conn.recvline()
    round1 = conn.recvline().decode('utf-8').split(' ')
    print(conn.recv())

    srv_hash = int(re.search('\((.*)\)', round1[2]).group(1), 16)
    srv_msg = int(round1[-1].strip(), 16)
    print(srv_hash)
    h1 = srv_hash >> N
    h2 = srv_hash & (2**N - 1)
    print(f'h1: {h1}, h2: {h2}')

    print(srv_msg)
    m1 = srv_msg >> N
    m2 = srv_msg & (2**N - 1)
    print(f'm1: {m1}, m2: {m2}')

    hs0 = h1 ^ m1
    hs1 = h2 ^ m2
    print(f'hs0: {hs0}, hs1: {hs1}')

    x1 = BitVec('x1', 128)
    x2 = BitVec('x2', 128)
    x3 = BitVec('x3', 128)
    x4 = BitVec('x4', 128)
    x5 = BitVec('x5', 128)
    x6 = BitVec('x6', 128)

    s = Solver()
    s.add(x1 < 64)
    s.add(x2 < 64)
    s.add(x3 < 64)
    s.add(x4 < 64)
    s.add(x1 >= 0)
    s.add(x2 >= 0)
    s.add(x3 >= 0)
    s.add(x4 >= 0)
    s.add(x5 <= 2**127-1)
    s.add(x6 <= 2**127-1)
    s.add(x5 >= 0)
    s.add(x6 >= 0)

    s.add(_ROL_(x5, x1) ^ _ROL_(x6, x2) == hs0)
    s.add(_ROL_(x5, x3) ^ _ROL_(x6, x4) == hs1)
    print(s.check())
    print(s.model())
    conn.sendline(f'{s.model()[x1]},{s.model()[x2]},{s.model()[x3]},{s.model()[x4]},{s.model()[x5]},{s.model()[x6]}'.encode('utf-8'))
    conn.recvline()
print(conn.recvline())