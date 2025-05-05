# HCSC 2025 - Interlog

## Description

## Interlog

Has it ever happened to you that a company’s critical data vanished without a trace, leaving only cryptic logs behind? Our company was breached, and there is C2 traces in the logs. Can you uncover the C2 communication?

evidence.log  `SHA256 66648dfaf7206a2c87e6b32c555bcb61e4555690e8d2d29664d593b1a2a46eba`

Remarks from the creator:
* No VPN connection is required

**Flag format**: `HCSC{...}`

*By D3v*

## Metadata

- Filename: [`evidence.log`](files/evidence.log)
- Tags: `logs`, `dns`, `subdomain`, `http`, `a record`, `basic authentication`
- Points: 350
- Number of solvers: 3

## Solution

We got a text file with a bunch of HTTP and DNS requests in it.

First we have to identify the interesting lines, which are all the lines referring the `0x00.hu` domain.

```bash
$ cat evidence.log| grep "0x00.hu" | awk '{print $6}'
4843.0x00.hu
5343.0x00.hu
7b4c.0x00.hu
3374.0x00.hu
735f.0x00.hu
4330.0x00.hu
756e.0x00.hu
745f.0x00.hu
7468.0x00.hu
336d.0x00.hu
5f34.0x00.hu
3131.0x00.hu
7d.0x00.hu
```

If we concatenate the subdomains and hex decode them, we get a fake flag:

```
484353437b4c3374735f4330756e745f7468336d5f3431317d
HCSC{L3ts_C0unt_th3m_411}
```

However there is also a website, which also gives fake flags: <https://0.0x00.hu>

What if we get the `A` records for the referenced domains:

```bash
dig +short 4843.0x00.hu
dig +short 5343.0x00.hu
dig +short 7b4c.0x00.hu
dig +short 3374.0x00.hu
dig +short 735f.0x00.hu
dig +short 4330.0x00.hu
dig +short 756e.0x00.hu
dig +short 745f.0x00.hu
dig +short 7468.0x00.hu
dig +short 336d.0x00.hu
dig +short 5f34.0x00.hu
dig +short 3131.0x00.hu
dig +short 7d.0x00.hu
105.100.57.54
50.50.56.56
51.54.58.117
109.99.72.76
110.89.109.66
120.121.65.70
55.90.65.69
82.50.67.66
117.74.57.76
57.110.67.54
84.110.112.68
78.102.113.115
76.104.105.98
```

The IP octetts look like ASCII characters, let's decode them:

```
id96228836:umcHLnYmBxyAF7ZAER2CBuJ9L9nC6TnpDNfqsLhib
```

Here, we need an idea that the colon looks like these are some kind of credentials.

Let's try `Basic` authentication:

```
curl -H "Authorization: Basic aWQ5NjIyODgzNjp1bWNITG5ZbUJ4eUFGN1pBRVIyQ0J1SjlMOW5DNlRucEROZnFzTGhpYg==" https://0.0x00.hu
HCSC{Sz14_Ur4m_C2_C0mm4nd_3rd3k3l}
```

The flag is: `HCSC{Sz14_Ur4m_C2_C0mm4nd_3rd3k3l}`