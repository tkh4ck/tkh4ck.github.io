# HTB Business CTF 2022 - Breakout

## Challenge

> The CCSS suffered a ransomware attack that compromised the Unique Digital Medical File (EDUS) and the National Prescriptions System for the public pharmacies. They've reported that their infrastructure has been compromised, and they cannot regain access. The APT left their implant interface exposed, though, and you'll need to break into it and find out how it works. NOTE: This challenge is intended to be solved before 'Breakin'.

- [bkd](../breakin/files/bkd)

### Metadata

- Difficulty: `easy`
- Tags: `reverse`, `strings`
- Points: `300`
- Number of solvers: `tbd`

## Solution

### Getting the flag

We just simply have to run `strings` on the binary to get the flag.

```shell
$ strings bkd | grep HTB -A 8
HTB{th3_H
pr0c_f5_H
15_4_p53H
ud0_f1l3H
5y5t3m_wH
h1ch_pr0H
v1d35_4nH
_1nt3rf4H
c3.....}H
```

We just have to remove the `H` characters from the end.

Flag: `HTB{th3_pr0c_f5_15_4_p53ud0_f1l35y5t3m_wh1ch_pr0v1d35_4n_1nt3rf4c3.....}`

## Files

* - [breakin](../breakin/files/breakin): Challenge binary