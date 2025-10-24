# CyberQuest 2025 - Glass Ink

## Description

**Glass Ink — Palimpsest Lab — Player Handout (EASY)** 

**Type**: Static‑site forensics / web OSINT

**TASK**

Investigate a “lab archive” static site where nothing important is linked. Operational crumbs across standard locations, logs, a backup archive, and a DNS zone ultimately reveal three tokens and an assembly rule. Combine them to form the final flag.

**RULES**

- No brute force; everything you need is on the site.
- Basic CLI tools (curl, tar, base64) and a browser are enough.
- Submit the flag in CQ25{TOKEN_TOKEN_TOKEN} format.

`cq25-challenge0[1-9]-b.cq.honeylab:8082`

## Metadata

- Filename: -
- Tags: `web`

## Solution

In the `/assets/css/site.css` there is a comment:

```
/* Ops: review /.well-known/security.txt */
```

The `` file contains the following:

```
Contact: mailto:ops@glassink.example
Acknowledgments: /logs/
Policy: /policy.html
Preferred-Languages: en
```

In the `/logs/` folder, there are two file:

```
# /logs/access-2025-08-21a.log
203.0.113.10 - - [21/Aug/2025:08:11:14 +0000] "GET / HTTP/1.1" 200 640 "-" "curl/8.1"
203.0.113.10 - - [21/Aug/2025:08:11:16 +0000] "GET /.well-known/security.txt HTTP/1.1" 200 210 "-" "curl/8.1"
203.0.113.10 - - [21/Aug/2025:08:11:17 +0000] "GET /backup/palimpsest-aug.tgz HTTP/1.1" 200 16384 "-" "curl/8.1"
```

```
# /logs/access-2025-08-21b.log
198.51.100.5 - - [21/Aug/2025:08:15:02 +0000] "GET /scripts/lab.min.js HTTP/1.1" 200 800 "-" "Mozilla/5.0"
198.51.100.5 - - [21/Aug/2025:08:15:07 +0000] "GET /L3DG3R/ HTTP/1.1" 404 120 "-" "Mozilla/5.0"
```

The `L3DG3R` seems to be one part of the flag.

The `/backup/palimpsest-aug.tgz` contains an image ([`plate.jpg](files/plate.jpg)) and a [`README.txt`](files/README.txt) file.

The `plate.jpg` file contains another part from the flag (`tkn_img: ghost`):

```
$ hexdump -C plate.jpg
[...]
00002390  05 14 51 40 05 14 51 40  05 14 51 40 05 14 51 40  |..Q@..Q@..Q@..Q@|
*
000026e0  05 14 51 40 05 14 51 40  05 14 51 40 1f ff d9 0a  |..Q@..Q@..Q@....|
000026f0  23 20 74 6b 6e 5f 69 6d  67 3a 20 67 68 6f 73 74  |# tkn_img: ghost|
00002700  0a                                                |.|
00002701
```

The `README.txt` file contains the following:

```
Palimpsest Lab - backup (Aug)
- plate archived
- DNS notes under /dns/
```

The `/dns/` directory has a `zone.txt` file:

```
;; zone fragment
palimpsest.example.  3600 IN TXT "seg=SU5fVEhF"
palimpsest.example.  3600 IN TXT "note=join TXT segs if more than one"
```

If we base64 decode `SU5fVEhF` the result is `IN_THE`.

Flag: `CQ25{GHOST_IN_THE_L3DG3R}`