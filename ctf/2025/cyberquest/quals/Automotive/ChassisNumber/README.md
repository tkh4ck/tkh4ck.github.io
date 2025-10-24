# CyberQuest 2025 - ChassisNumber

## Description

We found an unknown vehicle in the junkyard without chassis number. Maybe it's stolen. Do you have any idea to find it somehow?

Challenge difficulity: `hard`

## Metadata

- Filename: [`candump.txt`](files/candump.txt)
- Tags: `can`

## Solution

I searched for the known parts of the flag in hex.

The message id `6B4` is the important one:

```
$ cat candump.txt | grep '6B4#' | cut -d' ' -f3 | sort -u
6B4#0000000000435132
6B4#01357B6334726964
6B4#02336E746974797D
```

The flag is: `435132357B6334726964336E746974797D`

Flag: `CQ25{c4rid3ntity}`