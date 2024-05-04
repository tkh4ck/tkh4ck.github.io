# HCSC 2024 - Return of Jack

## Description

A sok utálat miatt, amit tavaly Jack kapott, a helyi hatóságok letartóztatták és bezárták egy elhagyatott sziget börtönébe. Sok-sok morális rágódás után végül úgy döntött, hogy végre kész élni a következményekkel és kész meglobogtatni a fehér zászlót, majd beismerni tettét. Azonban a szigeten igencsak limitált a kommunikációs hálózat. Gyakorlatilag az egész sziget egy speciális /64-es IPv6 tartományon osztozik. Először lépj vele kapcsolatba, aztán folytatjuk!

### Ezeket az adatokat tudjuk:
 - `2001:470:6d:d6::/64` a hálózat
 - `2001:470:6d:d6::1337` egy hintet tartalmaz, de ezen kívül nem használható semmi másra
 - minden más IP a tartományból használható a Jackkel való kommunikációra
 - Jack nem sokat tud a hálózatokról, illetve router firmware fejlesztésekről, így csupán egyetlen *hálózati réteg* protokollt implementált le sikeresen. Ezen a protokollon ha kérdezel (ID: 128), ő talán válaszol (ID: 129). De a következőt mindenképp vedd figyelembe! Ez az egyetlen esélye, hogy kommunikáljon a külvilággal lebukás nélkül. Nyilván nem lesz túl bőbeszédű. Csak a jó kérdésre fog válaszolni (kivéve a hint esetében, hiszen az nem Jack műve). :)

Nem megy az IP elérése a "clear weben"? Semmi gond! Az első feladatod egy kis network OSINT. :) _Who is_ on the other side?

#### Még mindig nem tiszta minden?
Itt egy pontokba szedett lépéssorozat. Nem árt, ha ezekre mind tudsz válaszolni:
 1. Találd ki, hogy milyen szolgáltatásra lehetett használva a megadott IPv6 tartomány. Valószínűleg még szükséged lehet erre az infóra.
 2. Milyen protokollt használ Jack? Felismered az azonosítókat? Valószínűleg ez is fog kelleni.
 3. Mi történik, ha azt az IPv6 címet szólítod meg, ami a hintben szerepel? Lehet, hogy ad egy tippet, hogy hogyan tovább...
 4. Profit!

**Megjegyzés**: A challenge megoldása során neked közvetlenül csak az alább megadott IPv4 cím felé kell adatot küldened.

**Megjegyzés**: A célcím (dst) csak akkor számít, amikor a hinttel beszélgetsz. Minden más esetben lehet a cél bármilyen IPv6 cím.

Készítői kommentek:
* VPN kapcsolat nem szükséges
* Ez a challenge a megszokott infrastruktúrán kívül van hosztolva és egy szerveren elérhető. Az IP-t lentebb találjátok.
* a challenge nem TCP és nem is UDP, más

 ### Hasznos lehet az utadon:
 - <https://wireshark.org>
 - <https://scapy.net/>
 - <https://datatracker.ietf.org/> linkek

 _Kinda funny. You are going to capture the flag, capture data and rescue the captured Jack at the same time. :D_
 
 **Flag formátum**: `HCSC24{...}`
 
 Köszönet Zaletnyik Péternek az IPv6-os kérdéseimmel kapcsolatban nyújtott válaszaiért!

*By MJ*

> Hint 1 (cost 0): A "whois 2001:470:6d:d6::1337 | grep broker" adjon neked ihletet utadon hajósinasom!

> Hint 2 (cost 275): Akkor a checklist...<br>
IPv4(IPv6(ICMPv6()))<br>
ICMPv6<br>
Hol a flag? Többet erővel, mint ésszel! Elvégre egy gonosztevőről van szó! ICMP-re nézz rá, hogy hol lehet benne flaget rejteni.

## Metadata

- Tags: `IPv6`, `tunneling`, `ICMPv6`
- Points: `550`
- Number of solvers: `1`
- Filename: -

## Solution

**I did not have time for this challenge. I suggest reading the official write-up by MJ: <https://github.com/NIK-SOC/hcsc_2024_mj/tree/main/ctf-return_of_jack>**

The challenge was basically about creating ICMPv6 Echo Request packets inside an IPv6 packet targeting one of the addresses in the range. This IPv6 packet should be tunneled inside an IPv4 packet targetting the given IPv4 address.

`Deathbaron` (the winner, gg!) was the only solver of the challenge with the following Scapy script:

```python
$ sudo scapy
>>> for i in range(64):
    for j in range(128):
        sendp( Ether() / IP(dst="193.225.251.62", proto=41) / raw( IPv6(src="2001:470:6d:d6::1") / ICMPv6EchoRequest(id=i, seq=j) ), iface="eth0")
```

Flag: `HCSC24{JACK_KNOWS_JACKSHID_ABOUT_NETWORKING}`
