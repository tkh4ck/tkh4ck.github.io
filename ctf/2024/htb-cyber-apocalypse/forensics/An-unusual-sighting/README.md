# HTB Cyber Apocalypse 2024: Hacker Royale - An unusual sighting

## Challenge

> As the preparations come to an end, and The Fray draws near each day, our newly established team has started work on refactoring the new CMS application for the competition. However, after some time we noticed that a lot of our work mysteriously has been disappearing! We managed to extract the SSH Logs and the Bash History from our dev server in question. The faction that manages to uncover the perpetrator will have a massive bonus come competition!

## Metadata

- Difficulty: very easy
- Creator: `c4n0pus`
- Files: [`.bash_history`](files/bash_history.txt), [`sshd.log`](files/sshd.log)
- Docker: yes
- Tags: `log forensics`, `ssh`, `.bash_history`
- Points: `300`
- Number of solvers: 

## Solution

We have a `.bash_history` files and an `sshd.log` file from the same machine.

Upon connecting to the remote server we get a series of questions which we have to answer based on the evidences we got to get the flag.

```
Note 2: All timestamps are in the format they appear in the logs
```

### Question 1

```
What is the IP Address and Port of the SSH Server (IP:PORT)
```

We can get the answer from the `sshd.log` file from the `[2024-01-28 15:24:23] Connection from 100.72.1.95 port 47721 on 100.107.36.130 port 2221 rdomain ""` lines.
```
> 100.107.36.130:2221
[+] Correct!
```

### Question 2

```
What time is the first successful Login
```

Again we should use the `sshd.log` file and search for the first `Accepted password` or `Accepted publickey` line: `[2024-02-13 11:29:50] Accepted password for root from 100.81.51.199 port 63172 ssh2`

```
> 2024-02-13 11:29:50
[+] Correct!
```

### Question 3

```
What is the time of the unusual Login
```

The first suspicious command in the `.bash_history.txt` is `[2024-02-19 04:00:18] whoami`, because of the timestamp (4 AM) and it is typical that after initial access, the attacker tries to find out the user they've compromised. We should find the closest login time before this event from `sshd.log`: `[2024-02-19 04:00:14] Accepted password for root from 2.67.182.119 port 60071 ssh2`
```
> 2024-02-19 04:00:14
[+] Correct!
```

### Question 4

```
What is the Fingerprint of the attacker's public key
```

Before the previous `Accepted password` line, as the SSH clients automatically try to sign in using a key by default, if key-based authentication is enabled on the server. If a key is found on the cliend side, we can get the hash from the logs: `[2024-02-19 04:00:14] Failed publickey for root from 2.67.182.119 port 60071 ssh2: ECDSA SHA256:OPkBSs6okUKraq8pYo4XwwBg55QSo210F09FCe1-yj4`
```
> OPkBSs6okUKraq8pYo4XwwBg55QSo210F09FCe1-yj4
[+] Correct!
```

### Question 5

```
What is the first command the attacker executed after logging in
```

We have perviously identified this:
```
> whoami
[+] Correct!
```

### Question 6

```
What is the final command the attacker executed before logging out
```

Tracing `.bash_history` from the `whoami` command, we can see that the last command executed arount `4 AM` is `./setup`:
```
> ./setup
[+] Correct!
```

### Flag

This was the final question so we earned the flag:
```
[+] Here is the flag: HTB{B3sT_0f_luck_1n_th3_Fr4y!!}
```

Flag: `HTB{B3sT_0f_luck_1n_th3_Fr4y!!}`