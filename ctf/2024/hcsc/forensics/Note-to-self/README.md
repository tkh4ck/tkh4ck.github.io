# HCSC 2024 - Note to self

## Description

Flag formátum: `HCSC24{md5hash}`

## Metadata

- Tags: `strings`, `memory forensics`, `volatility`, `notepad`
- Points: `400`
- Number of solvers: `27`
- Filename: `hcsc24.dmp.tar.xz` (not uploaded, ~ 1GB)

## Solution

The file for the challenge could be downloaded from `10.10.(1-9).10:46901`. For example with `wget http://10.10.1.10:46901/hcsc24.dmp.tar.xz`.

The file is a `Virtual Box Core Dump` file: <https://github.com/volatilityfoundation/volatility/wiki/Virtual-Box-Core-Dump>

```
$ file hcsc24.dmp
hcsc24.dmp:        ELF 64-bit LSB core file, x86-64, version 1 (SYSV)
```

We can analyze it with `Volatility`, but first run `strings` and `strings -e l` (UTF-16 little endian encoding) on it:

```
$ strings -e l hcsc24.dmp | grep HCSC24
HCSC24{975055B22AA57458DD04B6580DC352B8}
HCSC24
HCSC24{975055B22AA57458DD04B6580D
HCSC24{975055B22AA57458DD04B65
HCSC24{975055B22AA57458DD04B6580
HCSC24{975055B22AA57458DD04B6580DC3
HCSC24{975055B22AA57458DD04B658
HCSC24{975055B22AA57458DD04B6
HCSC24{975055B22AA57458DD04B6580DC35
HCSC24{975055B22
HCSC24{975055B
HCSC24{975055
HCSC24{975055B22AA5
```

As far as I know this was know by the created. I made a similar mistake a 5-6 years ago when we organized the first SecChallenge. There are plenty workarounds like encoding / encrypting the flag or giving a specific task and removing the flag format.

There was a Notepad process running and the goal of the challenge was to get the contents of the Notepad windows.

We can use both `Volatility3` and `Volatility2` for this:

```
$ python2 ~/tools/volatility/vol.py -f hcsc24.dmp imageinfo 
Volatility Foundation Volatility Framework 2.6.1
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win10x64_19041
                     AS Layer1 : SkipDuplicatesAMD64PagedMemory (Kernel AS)
                     AS Layer2 : VirtualBoxCoreDumpElf64 (Unnamed AS)
                     AS Layer3 : FileAddressSpace (/data/hcsc24.dmp)
                      PAE type : No PAE
                           DTB : 0x1aa002L
                          KDBG : 0xf80370406b20L
          Number of Processors : 1
     Image Type (Service Pack) : 0
                KPCR for CPU 0 : 0xfffff8036ea0d000L
             KUSER_SHARED_DATA : 0xfffff78000000000L
           Image date and time : 2024-03-26 23:04:17 UTC+0000
     Image local date and time : 2024-03-26 16:04:17 -0700

$ python2 ~/tools/volatility/vol.py -f hcsc24.dmp --profile Win10x64_19041 pstree
Volatility Foundation Volatility Framework 2.6.1
Name                                                  Pid   PPid   Thds   Hnds Time
-------------------------------------------------- ------ ------ ------ ------ ----
 0xffffde012b875040:System                              4      0    114      0 2024-03-27 06:56:25 UTC+0000
[...]
 0xffffde0130c83340:winlogon.exe                     4068   1032      5      0 2024-03-26 23:00:32 UTC+0000
[...]
2024-03-26 23:00:32 UTC+0000
. 0xffffde0131f5b340:userinit.exe                    4348   4068      0 ------ 2024-03-26 23:00:34 UTC+0000
.. 0xffffde0131aad300:explorer.exe                   4456   4348     64      0 2024-03-26 23:00:34 UTC+0000
... 0xffffde01318e5080:SecurityHealth                6256   4456      7      0 2024-03-26 23:02:12 UTC+0000
... 0xffffde01318e7080:notepad.exe                   3800   4456      4      0
[...]
```

We can see that our target process is `3800`. However, the `notepad` plugin does not support this profile and the `screenshots` plugin does not find any window:

```
$ python2 ~/tools/volatility/vol.py -f hcsc24.dmp --profile Win10x64_19041 notepad          
Volatility Foundation Volatility Framework 2.6.1
ERROR   : volatility.debug    : This command does not support the profile Win10x64_19041

$ python2 ~/tools/volatility/vol.py -f hcsc24.dmp --profile Win10x64_19041 screenshot --dump-dir .
Volatility Foundation Volatility Framework 2.6.1
WARNING : volatility.debug    : 0\Service-0x0-3e7$\Default has no windows
WARNING : volatility.debug    : 0\Service-0x0-3e4$\Default has no windows
WARNING : volatility.debug    : 0\Service-0x0-3e5$\Default has no windows
WARNING : volatility.debug    : 0\msswindowstation\mssrestricteddesk has no windows
WARNING : volatility.debug    : 0\Service-0x0-1743b9$\Default has no windows
```

Let's try our luck with `Volatility3` with a [`notepad plugin from GitHub`](https://github.com/spitfirerxf/vol3-plugins/blob/main/notepad.py):

```
$ python3 ~/tools/volatility3/vol.py -f hcsc24.dmp windows.info
Volatility 3 Framework 2.7.0
Progress:  100.00               PDB scanning finished                                                                                              
Variable        Value

Kernel Base     0xf8036f806000
DTB     0x1aa000
Symbols file:///home/pentest/tools/volatility3/volatility3/symbols/windows/ntkrnlmp.pdb/68A17FAF3012B7846079AEECDBE0A583-1.json.xz
Is64Bit True
IsPAE   False
layer_name      0 WindowsIntel32e
memory_layer    1 Elf64Layer
base_layer      2 FileLayer
KdVersionBlock  0xf80370415398
Major/Minor     15.19041
MachineType     34404
KeNumberProcessors      1
SystemTime      2024-03-26 23:04:17
NtSystemRoot    C:\Windows
NtProductType   NtProductWinNt
NtMajorVersion  10
NtMinorVersion  0
PE MajorOperatingSystemVersion  10
PE MinorOperatingSystemVersion  0
PE Machine      34404
PE TimeDateStamp        Wed Jun 28 04:14:26 1995

$ wget https://raw.githubusercontent.com/spitfirerxf/vol3-plugins/main/notepad.py -O ~/tools/volatility3/volatility3/plugins/windows/notepad.py

$ python3 ~/tools/volatility3/vol.py -f hcsc24.dmp windows.notepad                                                                  
Volatility 3 Framework 2.7.0
Progress:  100.00               PDB scanning finished                          
PID     Image   Probable Strings

3800    notepad.exe     5 7 @ A [...]  3 WIN-7K87L3UMBRP 10.0.2.15 HCSC24{975055B22AA57458DD04B6580DC352B8} 3 WIN-7K87L3UMBRP 10.0.2.15  [...] Ln 1, Col 33 ( HCSC24{975055B22AA5     Ln 1, Col 38   Ln 1, Col 11       8 8 8 8 Consolas nsole ER\S 5089-1688557810-2092337098-1001 ` ` @ Security-SPP-GenuineLocalStatus H ` `   ` N @ I I   %     solas Regular Microsoft: Consolas Consolas q   ( V i 9
```

This plugin also finds the flag, but basically does `strings` on the memory of `notepad`.

Flag: `HCSC24{975055B22AA57458DD04B6580DC352B8}`