# CyberQuest 2025 - Secret Packets

## Description

When the data sets out unprotected, the fragment of code you seek will emerge.

Challenge difficulity: `easy`

`cq25-challenge0[1-9]-c.cq.honeylab:46748`

## Metadata

- Filename: [`network_traffic.pcap`](files/network_traffic.pcap)
- Tags: `pcap`

## Solution

On port `46748` we get a login page which doesn't seem to be vulnerable to any common attacks.

In the network capture, the TCP stream 84 is the most interesting:

```
POST / HTTP/1.1
Host: 104.16.132.229
User-Agent: Scapy
Content-Type: application/x-www-form-urlencoded
Content-Length: 40

username=shepherd&password=.aV121oZS)3V-
```

Using these credentials (`shepherd` / `.aV121oZS)3V-`) we can login to the website and get the flag.

Flag: `CQ25{Un5af4_n3tw0rk_7r4ffic}`