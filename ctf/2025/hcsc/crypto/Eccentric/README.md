# HCSC 2025 - Eccentric

## Description

Alice and Bob are a weird duo every time I want to listen in on their conversation they always use some cryptographic algorithm to lock me out.
But this time I have the upper hand, I know Alice's secret is 1144 and Bob's is 2166. In the curve a is 1234, b is 5678 and p is 8837. Can you find out their shared secret and return it to me? :D

Ohh and I almost forgot G is (299, 6040)

**Note**: The flag is the shared secret's x coordinate hashed with SHA1

* No VPN connection is required
* Every piece of information is in the story of the challenge.

**Flag format**: `HCSC{<flag>}` where flag is the shared secret hashed with SHA1

*By incarrnati0n*

## Metadata

- Filename: -
- Tags: `crypto`, `ecdh`
- Points: 300
- Number of solvers: 104

## Solution

To be honest, I didn't even read or understand the question, because LLMs (ChatGPT) solved it immediatelly.

The question is about an ECDH (*Elliptic-curve Diffie–Hellman*) key exchange and we have to calculate the shared secret.

```python
from hashlib import sha1

# Elliptic curve parameters
a = 1234
b = 5678
p = 8837  # prime modulus

# Generator point
G = (299, 6040)

# Private keys
alice_secret = 1144
bob_secret = 2166

# Elliptic curve functions
def inverse_mod(k, p):
    if k == 0:
        raise ZeroDivisionError('division by zero')
    return pow(k, p - 2, p)

def point_add(P, Q, a, p):
    if P is None:
        return Q
    if Q is None:
        return P
    (x1, y1) = P
    (x2, y2) = Q

    if x1 == x2 and y1 != y2:
        return None
    if P == Q:
        m = (3 * x1 * x1 + a) * inverse_mod(2 * y1, p)
    else:
        m = (y2 - y1) * inverse_mod(x2 - x1, p)
    m %= p
    x3 = (m * m - x1 - x2) % p
    y3 = (m * (x1 - x3) - y1) % p
    return (x3, y3)

def scalar_mult(k, point, a, p):
    result = None
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend, a, p)
        addend = point_add(addend, addend, a, p)
        k >>= 1
    return result

# Compute public keys
alice_pub = scalar_mult(alice_secret, G, a, p)
bob_pub = scalar_mult(bob_secret, G, a, p)

# Compute shared secret
shared_secret = scalar_mult(alice_secret, bob_pub, a, p)

# Hash the x-coordinate of the shared secret
shared_x = shared_secret[0]
flag_hash = sha1(str(shared_x).encode()).hexdigest()

flag = f"HCSC{{{flag_hash}}}"
print(flag)
```

The flag is: `HCSC{6ef79c21dd35ea505e11d0c6673b8a2588fa650b}`