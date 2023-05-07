# HTB Business CTF 2022 - ChromeMiner

## Challenge

> Discurd has filed a DMCA violation regarding a popular browser extension claiming to be conducting VIP giveaways on the company's product. The addon store has since taken down the extension to prevent any potential browser cryptomining malware from being distributed in the marketplace. Could you investigate what the 'Discurd Nitro Giveaway' addon does exactly?

- [rev_chromeminer.zip](files/rev_chromeminer.zip)

### Metadata

- Difficulty: `easy`
- Tags: `javascript`, `chrome`, `crypto`
- Points: `325`
- Number of solvers: `tbd`

## Solution

### <Step 1>

```bash
$ file DiscurdNitru.crx 
DiscurdNitru.crx: Google Chrome extension, version 3
```

```bash
$ binwalk -e DiscurdNitru.crx   

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
593           0x251           Zip archive data, at least v3.0 to extract, compressed size: 5959, uncompressed size: 43374, name: background.js
6615          0x19D7          Zip archive data, at least v3.0 to extract, compressed size: 3638, uncompressed size: 3638, name: icon128.png
10314         0x284A          Zip archive data, at least v3.0 to extract, compressed size: 309, uncompressed size: 309, name: icon16.png
10683         0x29BB          Zip archive data, at least v3.0 to extract, compressed size: 1003, uncompressed size: 1003, name: icon48.png
11746         0x2DE2          Zip archive data, at least v3.0 to extract, compressed size: 236, uncompressed size: 483, name: manifest.json
12332         0x302C          End of Zip archive, footer length: 22

$ ls -la _DiscurdNitru.crx.extracted/            
drwxr-xr-x manjaro manjaro  4.0 KB Tue Jul 26 22:25:50 2022  .
drwxr-xr-x manjaro manjaro  4.0 KB Tue Jul 26 22:25:50 2022  ..
.rw-r--r-- manjaro manjaro   12 KB Tue Jul 26 22:25:50 2022  251.zip
.rw-r--r-- manjaro manjaro   42 KB Mon May 16 06:20:58 2022  background.js
.rw-r--r-- manjaro manjaro  3.6 KB Tue Jun 28 22:19:00 2022  icon128.png
.rw-r--r-- manjaro manjaro  309 B  Tue Jun 28 22:19:52 2022  icon16.png
.rw-r--r-- manjaro manjaro 1003 B  Tue Jun 28 22:19:34 2022  icon48.png
.rw-r--r-- manjaro manjaro  483 B  Tue Jun 28 22:09:00 2022  manifest.json
```

Let's analyze [background.js](files/background.js)!

### <Step 2>

Placeholder

### Getting the flag

Placeholder

```txt
Running the solution script here
```

Flag: `flag{}`

## Review



## Files

* [solve.py](solve.py)