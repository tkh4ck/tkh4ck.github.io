# HTB Cyber Apocalypse 2024: Hacker Royale - ROT128

## Challenge

> In the eerie stillness of the Bitting village, a dilapidated laboratory lies forgotten and forsaken, its ancient walls whispering secrets of unspeakable horrors. As you awaken within its confines, a shiver runs down your spine, the air thick with the weight of untold darkness. With no recollection of how you came to be here, you begin to explore the place. The dim glow of flickering lights casts long shadows across the worn floors, revealing rusted equipment and decaying machinery. The air is heavy with the scent of decay and abandonment, a tangible reminder of the atrocities that once transpired within these walls. Soon, you uncover the sinister truth lurking within the laboratory's forgotten depths. This place was a chamber of horrors, a breeding ground for abominable experiments in human cloning. The realization sends chills coursing through your veins, your mind reeling at the thought of the atrocities committed in the name of science. But there is no time to dwell on the horrors of the past, because a sinister countdown echoes through the laboratory, its ominous tones a harbinger of impending doom. Racing against the ticking clock, you discover the source of the impending catastrophe—a chemical reactor primed to unleash devastation upon the village. With the weight of the world upon your shoulders, you realize that you alone possess the knowledge to defuse the deadly device. As a chemist, you understand the delicate balance of chemical reactions, and you know that triggering a specific collision multiple times is the key to averting disaster. With steady hands and a racing heart, you get to work. As the seconds tick away, you feel the weight of the world bearing down upon you, but you refuse to falter.

## Metadata

- Difficulty: insane
- Creator: `makelaris`makelaris
- Files: [`server.py`](files/server.py)
- Docker: yes
- Tags: `custom hash`, `hash state`, `z3`
- Points: `325`
- Number of solvers: 

## Solution

Let's analyze the given [`server.py`](files/server.py) file.

```python
import random, os, signal
from Crypto.Util.number import long_to_bytes as l2b, bytes_to_long as b2l
from secret import FLAG

ROUNDS = 3
USED_STATES = []
_ROL_ = lambda x, i : ((x << i) | (x >> (N-i))) & (2**N - 1)
N = 128

def handler(signum, frame):
    print("\n\nToo slow, don't try to do sneaky things.")
    exit()

def validate_state(state):
    if not all(0 < s < 2**N-1 for s in user_state[-2:]) or not all(0 <= s < N for s in user_state[:4]):
        print('Please, make sure your input satisfies the upper and lower bounds.')
        return False
    
    if sorted(state[:4]) in USED_STATES:
        print('You cannot reuse the same state')
        return False
    
    if sum(user_state[:4]) < 2:
        print('We have to deal with some edge cases...')
        return False

    return True

class HashRoll:
    def __init__(self):
        self.reset_state()

    def hash_step(self, i):
        r1, r2 = self.state[2*i], self.state[2*i+1]
        return _ROL_(self.state[-2], r1) ^ _ROL_(self.state[-1], r2)

    def update_state(self, state=None):
        if not state:
            self.state = [0] * 6
            self.state[:4] = [random.randint(0, N) for _ in range(4)]
            self.state[-2:] = [random.randint(0, 2**N) for _ in range(2)]
        else:
            self.state = state
    
    def reset_state(self):
        self.update_state()

    def digest(self, buffer):
        buffer = int.from_bytes(buffer, byteorder='big')
        m1 = buffer >> N
        m2 = buffer & (2**N - 1)
        self.h = b''
        for i in range(2):
            self.h += int.to_bytes(self.hash_step(i) ^ (m1 if not i else m2), length=N//8, byteorder='big')
        return self.h


print('Can you test my hash function for second preimage resistance? You get to select the state and I get to choose the message ... Good luck!')

hashfunc = HashRoll()

for _ in range(ROUNDS):
    print(f'ROUND {_+1}/{ROUNDS}!')

    server_msg = os.urandom(32)
    hashfunc.reset_state()
    server_hash = hashfunc.digest(server_msg)
    print(f'You know H({server_msg.hex()}) = {server_hash.hex()}')

    signal.signal(signal.SIGALRM, handler)
    signal.alarm(2)

    user_state = input('Send your hash function state (format: a,b,c,d,e,f) :: ').split(',')

    try:
        user_state = list(map(int, user_state))

        if not validate_state(user_state):
            print("The state is not valid! Try again.")
            exit()

        hashfunc.update_state(user_state)

        if hashfunc.digest(server_msg) == server_hash:
            print(f'Moving on to the next round!')
            USED_STATES.append(sorted(user_state[:4]))
        else:
            print('Not today.')
            exit()
    except:
        print("The hash function's state must be all integers.")
        exit()
    finally:
       signal.alarm(0)

print(f'Uhm... how did you do that? I thought I had cryptanalyzed it enough ... {FLAG}')
```

- We have to solve 3 round correctly, but we have 2 seconds to solve each.
- For each round
    - The server generates a 32-byte long message (and sends it to us)
    - Creates a new hash state (a custom hashing algorithm)
    - Calculates the hash of the random byte array
    - Sends us the hash bytes
    - Our task is to send an initial hash state which generates the same hash from the same message
    - Basically we want a hash collition
- The custom hash function works in the following way
    - The state is 4 random numbers (x1, x2, x3, x4) between 0 and 128 and 2 random numbers (x5, x6) between 0 and 2**128
    - The hash is created from two subhashes eash 16 bytes long
    - The first half of the message is XORed with the x5 number rotated to the left (ROL) with x1 and with x6 ROLed with x2
    - The second half of the message is XORed with the x5 number rotated to the left (ROL) with x3 and with x6 ROLed with x4
    - The two results are concatenated

From the conditions and modifications presented above, we can create a `z3` solver which might be able to solve our problem. Luckily `z3` can easily handle the XOR and shift operation, we just have to speficy the proper constraints.

```python
from pwn import *
import re
from z3 import *

N = 128
_ROL_ = lambda x, i : ((x << i) | (x >> (N-i)))

conn = remote('94.237.54.164',32874)
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
print('Flag: ', conn.recvline())
```

Unfortunatelly if we set `x1`, `x2`, `x3`, `x4` to be between 0 and 128, `z3` can find the solution in 5-10 seconds in an average machine, which is too slow for us. But if we make stricter constraints like the `x1`, `x2`, `x3`, `x4` should be between 0 and 64, it can solve all rounds quite frequently.

```
$ python3 solve.py
[+] Opening connection to 83.136.253.251 on port 31642: Done
b'Send your hash function state (format: a,b,c,d,e,f) :: '
50597381508515034585982520077202462147092346992160647374697032567442834875238
h1: 148692340324148736990643251915777854015, h2: 277038186301223539561985887372416279398
81917277498908512220925028541038417474676954808691487713654377841547559700062
m1: 240733242336771603141910645754423230247, m2: 54521476199524853326921987942288590430
hs0: 290802766065384637431686555291955918104, hs1: 331558851194460112290604235603871032632
sat
[x4 = 24,
 x1 = 4,
 x2 = 3,
 x3 = 0,
 x5 = 29386813357627276224463523720420330121,
 x6 = 73687493677505928498998095713853496241]
b'Send your hash function state (format: a,b,c,d,e,f) :: '
424765841068298936598816846630032420972840847804925692171573945391058361053
h1: 1248274616495157522513033398029526199, h2: 101545945509390793597342470769734425309
89681579959895944078007257901417636739703106573448884926700596444324495587506
m1: 263550476539187379368838274950987074695, m2: 39574113266755026721271276490868881586
hs0: 264129890426801211636082278748415551536, hs1: 108502044041862521623446864512055435887
sat
[x2 = 40,
 x3 = 0,
 x5 = 7619901304059249349630393803481014095,
 x6 = 21123414901337982647501775099324080227,
 x4 = 54,
 x1 = 61]
b'Send your hash function state (format: a,b,c,d,e,f) :: '
112570112925464134437397425505690207859755486722335239936401829044927963454587
h1: 330813829538275146970100659252640986346, h2: 162237195916683824432416703835826674811
76244484255009604549456017424023477173910895948411658879488064078172200944775
m1: 224062401307806590745083154252408086888, m2: 3150552602993732582010605509795955847
hs0: 106923435032554842855487416458154169730, hs1: 159940783161147479491927354024463505660
sat
[x4 = 0,
 x1 = 48,
 x2 = 9,
 x3 = 0,
 x5 = 136656754650502424967691311674591582522,
 x6 = 40688691260265699873136264269994754502]
b'Uhm... how did you do that? I thought I had cryptanalyzed it enough ... HTB{k33p_r0t4t1ng_4nd_r0t4t1ng_4nd_x0r1ng_4nd_r0t4t1ng!}\n'
```

Flag: `HTB{k33p_r0t4t1ng_4nd_r0t4t1ng_4nd_x0r1ng_4nd_r0t4t1ng!}`