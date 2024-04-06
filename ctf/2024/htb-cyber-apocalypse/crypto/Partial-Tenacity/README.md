# HTB Cyber Apocalypse 2024: Hacker Royale - Partial Tenacity

## Challenge

> You find yourself in a labyrinthine expanse where movement is restricted to forward paths only. Each step presents both opportunity and uncertainty, as the correct route remains shrouded in mystery. Your mission is clear: navigate the labyrinth and reach the elusive endpoint. However, there's a twist—you have just one chance to discern the correct path. Should you falter and choose incorrectly, you're cast back to the beginning, forced to restart your journey anew. As you embark on this daunting quest, the labyrinth unfolds before you, its twisting passages and concealed pathways presenting a formidable challenge. With each stride, you must weigh your options carefully, considering every angle and possibility. Yet, despite the daunting odds, there's a glimmer of hope amidst the uncertainty. Hidden throughout the labyrinth are cryptic clues and hints, waiting to be uncovered by the keen-eyed. These hints offer glimpses of the correct path, providing invaluable guidance to those who dare to seek them out. But beware, for time is of the essence, and every moment spent deliberating brings you closer to the brink of failure. With determination and wit as your allies, you must press onward, braving the twists and turns of the labyrinth, in pursuit of victory and escape from the labyrinth's confounding embrace. Are you tenacious enough for that?

## Metadata

- Difficulty: medium
- Creator: `makelaris`
- Files: [`source.py`](files/source.py), [`output.txt`](files/output.txt)
- Docker: no
- Tags: `rsa`, `pkcs-oaep`, `modulo`, `alternating digits`
- Points: `300`
- Number of solvers: 

## Solution

We get a Python source ([`source.py`](files/source.py)) and the output of the program ([`output.txt`](files/output.txt)).

Let's analyze the Python file:

```python
from secret import FLAG
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

class RSACipher:
    def __init__(self, bits):
        self.key = RSA.generate(bits)
        self.cipher = PKCS1_OAEP.new(self.key)
    
    def encrypt(self, m):
        return self.cipher.encrypt(m)

    def decrypt(self, c):
        return self.cipher.decrypt(c)

cipher = RSACipher(1024)

enc_flag = cipher.encrypt(FLAG)

with open('output.txt', 'w') as f:
    f.write(f'n = {cipher.key.n}\n')
    f.write(f'ct = {enc_flag.hex()}\n')
    f.write(f'p = {str(cipher.key.p)[::2]}\n')
    f.write(f'q = {str(cipher.key.q)[1::2]}')
```

It is quite simple: The flag is encrypted with a 1024 bit `PKCS#1 OAEP (RSA)` algorithm. We get the `n`, the ciphertext (`ct`) and every second digit of `p` and `q`.

If we analyze the last printed digits of `n`, `p` and `q` (`3`, `3`, `5`) we can see that the only possible solution is that a program did not print the last digit of `q` and this last digit must be `1` (because the last digit of `n` == (last digit of `q` * last digit of `p`) % 10).

We have the alternating digits of `p` and `q`.

Now if we get the last two digits of `n`, `p`, `q` then the above equation becomes:

```
the last digit of n == (last digit of q * last digit of p) % 100
```

This is the same as:
```
n % 10**k == (p % 10**k * p % 10**k) % 10**k
```

With a concrete example (where `10 > x >= 0` is the second digit of `p`):
```
3 = (10*x + 3) * 51 % 100
3 = 510*x + 153 % 100
3 = 10*x + 53 % 100
50 = 10*x % 100
x = 5 
```

We can follow this thought and calculate the alternating digits of `p` and `q` and the decrypt the ciphertext ([`solve.py](files/solve.py)). It might be possible that there are multiple solutions for a digits, but it is more likely at the beginning, in our case it is unambiguous.

The output of the solution is:

```
p_start = 10501040401040703030507010306010502090805020106090800030907050205050901030005080705000904020808070308080200060909000609020701060704000202010607090002060403
q_start = 11050602040304020000050707040106060502050002040600080006070402060505070009030506070309020605020702030107050300010601050402020308040500080207040206090300051
p = 10541549431842783633587614316112542499895727166990860537947158205451961334065983715903944224868775308489240169949600619123741969714205272515647199022167453
q = 11254692541324720060752707148186767582750062945630785066774422168535575089335596479399029695524722638167959390210621853422825328846580189277644256392390351
b'HTB{v3r1fy1ng_pr1m3s_m0dul0_p0w3rs_0f_10!}'
```

Flag: `HTB{v3r1fy1ng_pr1m3s_m0dul0_p0w3rs_0f_10!}`
