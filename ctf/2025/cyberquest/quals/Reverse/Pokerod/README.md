# CyberQuest 2025 - Pokerod

## Description

Which pokemon is the cutest? If you don't know, you examine this file!

Do you see it now?

Challenge difficulity: `medium`

## Metadata

- Filename: [`pokerod`](files/pokerod)
- Tags: `nim`, `xor`

## Solution

This was a medium reverse challenge developed in [Nim](https://github.com/nim-lang/Nim/).

I decompiled the binary with Ghidra and tried whether ChatGPT is able to solve the challenge and generate a Python code as a solution.

It was able to solve the challenge. The binary created a XOR key from a hardcoded seed value and used it to decrypt the flag:

```python
SEED = 0x14471187

def nsu_strip(s: bytes) -> bytes:
    # strip newline and surrounding whitespace similar to nsuStrip(...,1,1)
    # (leading+trailing whitespace) but preserve other bytes.
    return s.strip(b"\r\n\t ")

def xor_encrypt(data: bytes, seed: int) -> bytes:
    """LCG pad like the decompiled code and XOR with data."""
    out = bytearray(len(data))
    s = seed & 0xFFFFFFFF
    for i in range(len(data)):
        s = (s * 0x19660D + 0x3C6EF35F) & 0xFFFFFFFF
        pad = (s >> 16) & 0xFF
        out[i] = data[i] ^ pad
    return bytes(out)

if __name__ == "__main__":
    EXPECTED_HEX = "765e6aef45744271bf45af002a75ff654ee5c66e1c189bb30a4b3e2d1b6cc667"
    expected = bytes.fromhex(EXPECTED_HEX)

    got = xor_encrypt(expected, SEED)
    print(got)
```

Flag: `CQ25{sn0rl4x_sl33ps_0n_th3_tr33}`