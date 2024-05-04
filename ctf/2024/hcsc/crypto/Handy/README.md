# HCSC 2024 - Handy

## Description

Hallottam, hogy IT-s vagy, így egy nyomtató beállítása biztosan nem okozna gondot, ugye? Nade mi a helyzet a kriptográfiával? Az a helyzet, hogy megalkottam egy szupertitkos kriptográfiai megoldást, kódoltam egy fontos üzenetet, aztán elfelejtettem, mi volt az üzenet. Egyedül a kódolt verzió maradt meg: `440222077770222024{20_4033077706020660_906660777030_333066607770_60666022044405550330_704406660660330}`, illetve a titkosítóm.

Készítői kommentek:
* VPN kapcsolat szükséges
* a challenge egyetlen porton fut
* **a megoldás nem érzékeny a kis és nagybetűkre!**

**Flag formátum**: `hcsc24{...}`

*By MJ*

> Hint 1 (cost 100): Beszélgess velem pl a 10.10.1-9.10:54847 címen! Mit kapsz, ha kétszer egymás után ugyanazt kódolod? Fix az érték? Csak az ABC betűket titkosítja el?

## Metadata

- Tags: `mobile phone`, `oracle`, `encoding`
- Points: `200`
- Number of solvers: `81`
- Filename: -

## Solution

The backend of the challenge was running on: `10.10.(1-9).10:54847`

We need to decode / decrypt the given message using this TCP service.

If we connecto to it we get the following messages:

```
$ nc 10.10.1.10 54847
      ,-'""`-,               
,'        `.             
/    _,,,_   \            
/   ,'  |  `\/\\           
/   /,--' `--.  `           
|   /      ___\_            
|  | /  ______|             
|  | |  |_' \'|             
\ ,' (   _) -`|             
'--- \ '-.-- /             
______/`--'--<              
|    |`-.  ,;/``--._        
|    |-. _///     ,'`\      
|    |`-Y;'/     /  ,-'\    
|    | // <_    / ,'  ,-'\  
'----'// -- `-./,' ,-'  \/  
|   //[==]     \,' \_.,-\  
|  //      `  -- | \__.,-' 
// -[==]_      |   ____\ 
//          `-- |--' |   \
    [==__,,,,--'    |-'" 
---""''             |    
hjm          ___...____/     
    --------------------.
           ,.        --.|
          /||\        /||
           ||        /  |
           ||       /   |
            |      /    |

Beep, boop! Give me a message to encrypt: HCSC24{
Here ya go: 440222077770222024{
```

It is basically an encryption / encoding oracle which can be used to brute-force the plaintext. I've created a script for this [`solve.py`](files/solve.py):

```python
from pwn import *
import string

f = '440222077770222024{20_4033077706020660_906660777030_333066607770_60666022044405550330_704406660660330}'
d = {}

for ch in string.ascii_lowercase + string.digits:
    c = remote('10.10.5.10', 54847)
    c.sendlineafter('Beep, boop! Give me a message to encrypt: ', ch)
    c.recvuntil('Here ya go: ')
    r = c.recv().strip().decode()
    c.close()
    d[r] = ch

# {'20': 'a', '220': 'b', '2220': 'c', '30': 'd', '330': 'e', '3330': 'f', '40': 'g', '440': 'h', '4440': 'i', '50': 'j', '550': 'k', '5550': 'l', '60': 'm', '660': 'n', '6660': 'o', '70': 'p', '770': 'q', '7770': 'r', '77770': 's', '80': 't', '880': 'u', '8880': 'v', '90': 'w', '990': 'x', '9990': 'y', '99990': 'z', '0': '0', '1': '1', '2': '2', '3': '3', '4': '4', '5': '5', '6': '6', '7': '7', '8': '8', '9': '9'}
print(d)

f = '440222077770222024{20_4033077706020660_906660777030_333066607770_60666022044405550330_704406660660330}'
for f1 in f.split('{'):
    for f2 in f1.split('}'):
        for f3 in f2.split('_'):
            for f4 in f3.split('0'):
                if f4 == '': continue
                if f4+'0' in d:
                    print(d[f4+'0'], end='')
                else:
                    print(f4, end='')
            
            print('_', end='')
        
# hcsc24{a_german_word_for_mobile_phone}
```

It turns out that the encoding /encryption used is the `Phone Keypad Cipher`: <https://www.dcode.fr/phone-keypad-cipher>

The official write-up by `MJ` is available at: <https://github.com/NIK-SOC/hcsc_2024_mj/tree/main/ctf-handy>

Flag: `hcsc24{a_german_word_for_mobile_phone}`