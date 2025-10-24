# CyberQuest 2025 - Drivetrain

## Description

Something ridiculous happened with this car. Examine the logs.

Challenge difficulity: `medium`

## Metadata

- Filename: [`candump.txt`](files/candump.txt)
- Tags: `can`

## Solution

I tried to find the known characters of the flag in hex in the dump (`C` - `43`, `Q` - `51`).

The messages with the id `000` are the important ones:

```
$ cat candump.txt | grep '000#' | cut -d' ' -f3 
000#DEADBEEFCAFE0043
000#123456789ABC0051
000#1240000812480032
000#F243522812480035
000#CAFEBABEDEAD007B
000#1248124812480064
000#0000000000000064
000#0102030405060030
000#56789ABCDEFA0073
000#BEADF00DFACE005F
000#FFFFFFFFFFFF0030
000#FEEDFACEBADC006E
000#BEADF00DFACE005F
000#B00000BADC0D0063
000#7E7E7E7E7E7E0034
000#112233445566006E
000#BAADBEEF0000007D
```

The last bytes give the flag: `435132357B646430735F306E5F63346E7D`

Flag: `CQ25{dd0s_0n_c4n}`