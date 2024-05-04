# HCSC 2024 - Válassz egy böngészőt

## Description

Nagyon népszerű a Chrome, a Safari meg még az Edge is.

De egy jó geek azért ismer mást is. PC-n, mobilon.
Közéjük tartozol? :)

Készítői kommentek:
- a megoldáshoz brute-force nem szükséges
- Kellékek a megoldáshoz: VPN hozzáférés
- a challenge egyetlen porton fut

**Flag formátum**: `HCSC24{...}` ahol a '...' helyén szerepel a flag.

*By [TheAdam](https://github.com/adns44)*

> Hint 1 (cost 0): Édesszájú vagyok, fejlesztés közben is ez voltam. A fejléc pedig mindig értékesebb, mint a lábléc

## Metadata

- Tags: `web`, `header`, `user-agent`
- Points: `250`
- Number of solvers: `0`
- Filename: -

## Solution

The challenge was available at `10.10.(1-9).11:5028`, for example: <http://10.10.1.11:5028>

No one was able to solve this challenge. Seemed a little bit guessing. I've heard rumors we should have visited the site with the latest Chrome, Safari and Edge and a mobile browser, then it would have given us the flag.

The only progress if we send an empty `User-Agent`, the response is a PHP error message:

```
$ curl -A '' http://10.10.1.11:5028
<br />
<b>Warning</b>:  Undefined array key "HTTP_USER_AGENT" in <b>/var/www/html/index.php</b> on line <b>9</b><br />
<br />
<b>Deprecated</b>:  strpos(): Passing null to parameter #1 ($haystack) of type string is deprecated in <b>/var/www/html/index.php</b> on line <b>12</b><br />
<br />
<b>Deprecated</b>:  strpos(): Passing null to parameter #1 ($haystack) of type string is deprecated in <b>/var/www/html/index.php</b> on line <b>12</b><br />
<br />
<b>Deprecated</b>:  strpos(): Passing null to parameter #1 ($haystack) of type string is deprecated in <b>/var/www/html/index.php</b> on line <b>12</b><br />
<br />
<b>Deprecated</b>:  strpos(): Passing null to parameter #1 ($haystack) of type string is deprecated in <b>/var/www/html/index.php</b> on line <b>12</b><br />
<br />
<b>Deprecated</b>:  strpos(): Passing null to parameter #1 ($haystack) of type string is deprecated in <b>/var/www/html/index.php</b> on line <b>12</b><br />
<br />
<b>Deprecated</b>:  strpos(): Passing null to parameter #1 ($haystack) of type string is deprecated in <b>/var/www/html/index.php</b> on line <b>12</b><br />
Have you been ever tried the most popular browsers from an user and a developer aspect?
```

> **Update**: Based on `MJ`s hints on Discord `Deathbaron` created a script to solve the challenge:

```bash
printf "" > ua.txt
for browser in firefox chrome edge safari internet-explorer opera vivaldi yandex-browser; do curl -s https://www.whatismybrowser.com/guides/the-latest-user-agent/$browser | grep -oP '(?<=<span class="code">).*(?=</span>)' >> ua.txt; done
echo curl/8.5.0 >> ua.txt
curl -v -A "$( (head -n 1 ua.txt; cat ua.txt | grep -oP '[^\)]*$' | tr ' ' '\n' | grep "\S" | sort -u ) | tr '\n' ' ')" http://10.10.2.11:5028/
```

The shortest accepted payload is (event works without the spaces, I left them there because of readability):

```bash
$ curl -v -A 'User-Agent: Firefox/12 Chrome/12 CriOS/12 curl/ FxiOS/12 Safari/60' http://10.10.1.11:5028
 
*   Trying 10.10.1.11:5028...
* Connected to 10.10.1.11 (10.10.1.11) port 5028
> GET / HTTP/1.1
> Host: 10.10.1.11:5028
> User-Agent: User-Agent: Firefox/12 Chrome/12 CriOS/12 curl/ FxiOS/12 Safari/60
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 200 OK
< Server: nginx/1.25.5
< Date: Fri, 03 May 2024 17:06:21 GMT
< Content-Type: text/html; charset=UTF-8
< Transfer-Encoding: chunked
< Connection: keep-alive
< X-Powered-By: PHP/8.3.6
< Set-Cookie: PHPSESSID=14c3b5cb0656ab1be2c39294947f5d9c; path=/
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate
< Pragma: no-cache
< 
* Connection #0 to host 10.10.1.11 left intact
HCSC24{CHOOSE-YOUR-FIGHTER-BROWSER}
```

The solution also works if we send latest `User-Agent` headers of the browsers above with a fix cookie value.

Flag: `HCSC24{CHOOSE-YOUR-FIGHTER-BROWSER}`