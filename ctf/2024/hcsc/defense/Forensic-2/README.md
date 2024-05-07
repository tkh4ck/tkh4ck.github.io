# HCSC 2024 - Forensic 2.

## Description

Jimmie Benjamin submitted 2 suspicious files found on his desktop before his machine died. The admin collected them and put on the DC’s desktop, in a password protected 7z file. The password is: suspected.

What is the original name of the exe file?

When the pfx file’s actual content was created by the attacker (days/month/year_hours:minutes:seconds)?

(example: `hcsc{origname.exe_dd/mm/yyyy_hh:mm:ss}`)

## Metadata

- Tags: `7z`, `strings`, `dnspy`
- Points: `100`
- Number of solvers: `29`
- Filename: -

## Solution

From the description of the challenge we can figure out where to find the `7z` file: `C:\Users\Administrator\Desktop\evidence.7z`

We can print the content of the file and some extra information using `7z l`. We can also get the timestamp from here, we just have to take the timezone into account:

```
7z l evidence.7z

7-Zip [64] 17.05 : Copyright (c) 1999-2021 Igor Pavlov : 2017-08-28
p7zip Version 17.05 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,16 CPUs x64)

Scanning the drive for archives:
1 file, 91459 bytes (90 KiB)

Listing archive: evidence.7z

--
Path = evidence.7z
Type = 7z
Physical Size = 91459
Headers Size = 291
Method = LZMA2:192k BCJ 7zAES
Solid = -
Blocks = 2

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2024-03-30 10:07:10 D....            0            0  evidence
2024-03-20 00:37:23 ....A         3489         3392  evidence/exported_pwp.pfx
2022-11-07 20:56:46 ....A       174080        87776  evidence/casmonitor.exe
------------------- ----- ------------ ------------  ------------------------
2024-03-30 10:07:10             177569        91168  2 files, 1 folders
```

We can also get the information using the `stat` command:

```
$ stat exported_pwp.pfx
  File: exported_pwp.pfx
  Size: 3489      	Blocks: 8          IO Block: 4096   regular file
Device: 259,3	Inode: 11544111    Links: 1
Access: (0644/-rw-r--r--)  Uid: ( 1000/  ktamas)   Gid: ( 1000/  ktamas)
Access: 2024-04-27 22:02:01.632162228 +0200
Modify: 2024-03-19 23:37:23.000000000 +0100
Change: 2024-04-27 22:13:15.104987660 +0200
 Birth: 2024-04-27 21:59:08.641791938 +0200
```

The timestamp of the `.pfx` file is: `19/03/2024 23:37:23`.

The original name of the executable can be found out by loading the `casmonitor.exe` binary to `DNSpy` (because it is a .NET executable) or just using `strings`:

```
$ strings -e l evidence/casmonitor.exe| head -n 20
'"6$;%>&D'G(I)S+V,Z-\/]0^1_2`4aCbDc
#"*).-5464748494:4;4<4=4>4?4@4A4_^a`b`cbedfdgfhdidjdonpnqnrnsntnunvnwnxnynzn
   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v{0}
  Find information about all registered CAs:

    Certify.exe cas [/ca:SERVER\ca-name
```

The original name of the binary is `Certify.exe`.

Flag: `hcsc{Certify.exe_19/03/2024_23:37:23}`