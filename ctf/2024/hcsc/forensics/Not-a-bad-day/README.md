# HCSC 2024 - Not a bad day

## Description

Egyik nap borzasztó fejfájással ébredtem! Mi történt tegnap...? A fene tudja. Csak azt tudom, hogy felkeltem és eltűnt a flag a gépemről. Tudnál segíteni? Segíts, hogy legalább a mai napom legyen egy jobb nap. 😊

Készítői kommentek:
* a megoldáshoz szerver oldali brute-force nem szükséges
* VPN kapcsolat szükséges
* a challenge egyetlen porton fut

**Flag formátum**: `HCSC24{...}`

*By MJ*

> Hint 1 (cost 225): Hogy hol élek? 10.10.1-9.10:61370! Mi vagyok? Szólíts meg, jellegzetes a beköszönésem. Meow! Ja bocs, szeretem a macskás képeket.


## Metadata

- Tags: `nbd`, `ext4`, `undelete`
- Points: `450`
- Number of solvers: `15`
- Filename: -

## Solution

The challenge was running on `10.10.(1-9).10:61370`.

Nmap says that the service is `nbd` (network block device). We can use `nbd-client` and `dd` to copy the content of the remote disk

```bash
$ nbd-client  10.10.5.10 -p 61370
$ sudo dd if=/dev/nbd0 of=image  bs=1
$ file image      
disk: Linux rev 1.0 ext4 filesystem data, UUID=a95232e0-bdab-4c7e-840a-903aa52adc7c, volume name "notabadday" (extents) (64bit) (large files) (huge files)
```

It is an `ext4` filesystem, we can extract it with `binwalk`, however, we are only going to find a bunch of images of cats.

There might be some deleted files. We can use `extundelete` or `photorec` to recover deleted files:

```
$ photorec image
$ ls recup_dir.1
f0017094.elf  f0017556.elf  f0018078.elf  f0018466.elf  f0018910.elf  f0019292.elf  f0019686.elf  f0020080.elf  f0024578.elf  f0024944.elf  f0025330.elf  f0025702.elf  f0026120.elf  f0026508.elf  f0026898.elf  f0027266.elf
f0017216.elf  f0017658.elf  f0018164.elf  f0018580.elf  f0019010.elf  f0019388.elf  f0019794.elf  f0020188.elf  f0024668.elf  f0025032.elf  f0025414.elf  f0025822.elf  f0026204.elf  f0026600.elf  f0026972.elf  f0027358.elf
f0017316.elf  f0017788.elf  f0018282.elf  f0018712.elf  f0019100.elf  f0019478.elf  f0019874.elf  f0020270.elf  f0024766.elf  f0025154.elf  f0025510.elf  f0025932.elf  f0026310.elf  f0026690.elf  f0027078.elf  report.xml
f0017430.elf  f0017926.elf  f0018376.elf  f0018808.elf  f0019208.elf  f0019586.elf  f0019990.elf  f0020364.elf  f0024862.elf  f0025242.elf  f0025608.elf  f0026028.elf  f0026412.elf  f0026780.elf  f0027178.elf
```

We got a few ELF files. If we execute them, each of them prints a number and a character. If we order the numbers, we get the flag.

```
$ ./f0018466.elf
12: s
```

```
0: H
1: C
2: S
3: C
4: 2
5: 4
6: {
7: n
8: b
9: d
10: _
11: 1
12: s
13: _
14: 4
15: _
16: S
17: i
18: C
19: K
20: _
21: S
22: y
23: S
24: 4
25: d
26: m
27: 1
28: n
29: _
30: t
31: 0
32: 0
33: l
34: _
35: f
36: 0
37: r
38: _
39: r
40: 3
41: m
42: 0
43: t
44: 3
45: _
46: 0
47: s
48: _
49: 1
50: n
51: 5
52: 7
53: a
54: l
55: l
56: 4
57: t
58: 1
59: 0
60: n
61: }
```

During the competition I extracted the ELF files manually using `dd` because first I noticed the `ELF` header in the `hexdump` and luckily after each `ELF` file there was a JPG image with the `JFIF` header.

The official write-up by `MJ` is available at: <https://github.com/NIK-SOC/hcsc_2024_mj/tree/main/ctf-not_a_bad_day>

Flag: `HCSC24{nbd_1s_4_SiCK_SyS4dm1n_t00l_f0r_r3m0t3_0s_1n57all4t10n}`