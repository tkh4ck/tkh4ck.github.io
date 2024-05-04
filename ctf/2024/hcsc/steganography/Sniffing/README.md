# HCSC 2024 - Sniffing

## Description

Ez gáz! Vagy gaz? 

Csak a zip file letöltése szükséges.

A flag formátuma: 
`HCSC24{...}`

## Metadata

- Tags: `strings`
- Points: `200`
- Number of solvers: `152`
- Filename: [`Sniff.jpg`](files/Sniff.jpg)

## Solution

Let's run `strings` first:

```
$ strings Sniff.jpg
JFIF
;CREATOR: gd-jpeg v1.0 (using IJG JPEG v62), quality = 90
$3br
%&'()*456789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz
        #3R
&'()*56789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz
H.C.S.C.2.4{.t0T..a.1.-.s.Z..1...v.A.s .}
XHjd
QblW1
lPQp
[...]
```

There is the flag, we just need to remove the `.` characters (and a space character).

Flag: `HCSC24{t0Ta1-sZ1vAs}`