# HCSC 2024 - For'n sics

## Description

Csak a zip file letöltése szükséges!

A flag formátuma: `HCSC24{...}`

> Hint 1 (cost 125): For'n sics
> » fonetikus átirat:<br>
> szám [UK: fɔː(r)] [US: ˈfɔːr]<br>
> főnév, kötőszó [UK: ənd] [US: ænd]<br>
> szám [UK: sɪks] [US: ˈsɪks]<br>
> főnév [UK: baɪts] [US: ˈbaɪts]

## Metadata

- Tags: `PNG`, `file formats`
- Points: `250`
- Number of solvers: `76`
- Filename: [`Fornsics`](files/Fornsics)

## Solution

The `Fornsics` file is identified as `data` by `file`:

```bash
$ file For\'n\ sics 
For'n sics: data
```

However, if we run `hexdump` we can see that it must be a `PNG` file, but the header seems to be wrong.

```
$ hexdump -C For\'n\ sics | head -n 10
00000000  89 50 4e 00 0d 00 1a 0a  00 00 00 0d 49 48 44 52  |.PN.........IHDR|
00000010  00 00 03 20 00 00 01 f9  08 02 00 00 00 f6 bc cd  |... ............|
00000020  f1 00 00 04 b5 69 54 58  74 58 4d 4c 3a 63 6f 6d  |.....iTXtXML:com|
00000030  2e 61 64 6f 62 65 2e 78  6d 70 00 00 00 00 00 3c  |.adobe.xmp.....<|
00000040  3f 78 70 61 63 6b 65 74  20 62 65 67 69 6e 3d 22  |?xpacket begin="|
00000050  ef bb bf 22 20 69 64 3d  22 57 35 4d 30 4d 70 43  |..." id="W5M0MpC|
00000060  65 68 69 48 7a 72 65 53  7a 4e 54 63 7a 6b 63 39  |ehiHzreSzNTczkc9|
00000070  64 22 3f 3e 0a 3c 78 3a  78 6d 70 6d 65 74 61 20  |d"?>.<x:xmpmeta |
00000080  78 6d 6c 6e 73 3a 78 3d  22 61 64 6f 62 65 3a 6e  |xmlns:x="adobe:n|
00000090  73 3a 6d 65 74 61 2f 22  20 78 3a 78 6d 70 74 6b  |s:meta/" x:xmptk|
```

In our case the header it `89 50 4e 00 0d 00 1a 0a`, but it should be `89 50 4e 47 0d 0a 1a 0a`:

```
89 50 4e 00 0d 00 1a 0a
vs
89 50 4e 47 0d 0a 1a 0a
```

We can fix the header with a hex editor or using Python etc. If we open the image, the flag is in the bottom right corner.

![Fixed PNG](files/solution.png)

Flag: `HCSC24{He4dAch3}`