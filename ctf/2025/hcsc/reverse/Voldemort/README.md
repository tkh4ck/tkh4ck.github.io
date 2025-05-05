# HCSC 2025 - Voldemort

## Description

This challange invites you to channel your inner Hermione and uncover a hidden flag buried within layers of obfuscation. This isn't about the infamous Voldemort malware, but you might notice some similarities. Your mission is to uncover the right spells and cast them in the correct sequence to unlock the flag.

The password that gets you started: `dobbyHasNoMaster!`

**Note**: Might be malicious. If you plan to run this, we definitely recommend a throwaway VM.

Good luck! May your magic be powerful and your logic razor-sharp! Happy flag hunting!

## Metadata

- Filename: [`voldemort.zip`](files/voldemort.zip)
- Tags: `vm`, `registry`
- Points: 450
- Number of solvers: 5

## Solution

I understood the task and the goals, but I could not solve the challenge during the competition.

The binary reads a binary data from a hard coded registry key (`HKCU\SOFTWARE\6-2-4-4-2`) and value (`incantation`) and based on the content of the binary data (inserted by us) executed predefined functions (like instructions), so basically it is an internal virtual machine.

The following solutions are from `Deathbaron` and `baltazar`, I will explain it later, if I have the time (until then check `Deathbaron`'s blog).

```
reg add "HKCU\SOFTWARE\6-2-4-4-2" /v incantation /t REG_BINARY /d 1100000000010707070701070707070710ED0DDCBA /f
```

```
01 07 07 07 07           # push 0x07070707
07                       # register handler
08 03 72 65 67           # print "reg"
11 11 00 00 00           # subprogram, length 0x11
   08 02 69 6E           # print "in"
   10 ED 0d DC BA        # call handler again
   08 05 72 61 69 73 65  # print "raise"
   00                    # return
08 03 6F 75 74           # print "out"
00                       # return
```