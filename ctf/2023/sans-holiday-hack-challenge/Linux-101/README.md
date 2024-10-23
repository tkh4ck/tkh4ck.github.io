# SANS Holiday Hack Challenge 2023 - Linux 101

## Description

> Visit Ginger Breddie in Santa's Shack on Christmas Island to help him with some basic Linux tasks. It's in the southwest corner of Frosty's Beach.

> **Ginger Breddie (Santa's Surf Shack)**:
*Hey, welcome to Santa's Surf Shack on tropical Christmas Island! I'm just hanging ten here, taking it easy while brushing up on my Linux skills.
You ever tried getting into Linux? It's a super cool way to play around with computers.
Can you believe ChatNPT suggested this trip to the Geese Islands this year? I'm so thrilled!
Kudos to ChatNPT, eh? The sunshine, the waves, and my surfboard – simply loving it!
So, what do you have planned? Care to join me in a Linux session?*

### Metadata

- Difficulty: 1/5
- Tags: `linux`, `cli`, `trolls`

## Solution

### Video

<iframe width="1280" height="720" src="https://www.youtube-nocookie.com/embed/LtHHYrNxOEw?start=226" title="SANS Holiday Hack Challenge 2023 - Linux 101" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

### Write-up

We are presented with a virtual terminal, we have to execute some Linux commands to find some "trolls".

> The North Pole 🎁 Present Maker: All the presents on this system have been stolen by trolls. Capture trolls by following instructions here and 🎁's will appear in the green bar below. Run the command "hintme" to receive a hint.

```
Type "yes" to begin: yes
```

> Perform a directory listing of your home directory to find a troll and retrieve a present!

```bash
elf@4df81742b692:~$ ls
HELP  troll_19315479765589239  workshop
```

> Now find the troll inside the troll.

```bash
elf@4df81742b692:~$ cat troll_19315479765589239 
troll_24187022596776786
```

> Great, now remove the troll in your home directory.

```bash
elf@4df81742b692:~$ rm troll_19315479765589239
```

> Print the present working directory using a command.

```bash
elf@4df81742b692:~$ pwd
/home/elf
```

> Good job but it looks like another troll hid itself in your home directory. Find the hidden troll!

```bash
elf@4df81742b692:~$ ls -la
total 64
drwxr-xr-x 1 elf  elf   4096 Jan  2 20:47 .
drwxr-xr-x 1 root root  4096 Dec  2 22:19 ..
-rw-r--r-- 1 elf  elf     28 Dec  2 22:19 .bash_history
-rw-r--r-- 1 elf  elf    220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 elf  elf   3105 Nov 20 18:04 .bashrc
-rw-r--r-- 1 elf  elf    807 Feb 25  2020 .profile
-rw-r--r-- 1 elf  elf      0 Jan  2 20:47 .troll_5074624024543078
-rw-r--r-- 1 elf  elf    168 Nov 20 18:04 HELP
drwxr-xr-x 1 elf  elf  24576 Dec  2 22:19 workshop
```

> Excellent, now find the troll in your command history.

```bash
elf@4df81742b692:~$ history
    1  echo troll_9394554126440791
    2  ls
    3  cat troll_19315479765589239 
    4  rm troll_19315479765589239 
    5  pwd
    6  ls -la
    7  history
```

> Find the troll in your environment variables.

```bash
elf@4df81742b692:~$ env
SHELL=/bin/bash
TMUX=/tmp/tmux-1050/default,17,0
HOSTNAME=4df81742b692
RESOURCE_ID=cb91b7c2-a438-4a66-8d6c-6fa9a18b6a59
GREENSTATUSPREFIX=presents
PWD=/home/elf
LOGNAME=elf
SESSNAME=Troll Wrangler
z_TROLL=troll_20249649541603754
HOME=/home/elf
LANG=C.UTF-8
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:
HHCUSERNAME=tkh4ck
AREA=cisantassurfshack
BPUSERHOME=/home/elf
LESSCLOSE=/usr/bin/lesspipe %s %s
TERM=screen
LESSOPEN=| /usr/bin/lesspipe %s
USER=elf
TOKENS=linux101
TMUX_PANE=%2
BPUSER=elf
SHLVL=3
LC_ALL=C.UTF-8
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
MAIL=/var/mail/elf
LOCATION=7,7
_=/usr/bin/env
```

> Next, head into the workshop.

```bash
elf@4df81742b692:~$ cd workshop/
```

> A troll is hiding in one of the workshop toolboxes. Use "grep" while ignoring case to find which toolbox the troll is in.

```bash
elf@4b4969377281:~/workshop$ grep -ir troll
toolbox_191.txt:tRoLl.4056180441832623
```

> A troll is blocking the present_engine from starting. Run the present_engine binary to retrieve this troll.

```bash
elf@4b4969377281:~/workshop$ ls -la present_engine 
-r--r--r-- 1 elf elf 4990336 Dec  2 22:19 present_engine
elf@4b4969377281:~/workshop$ chmod +x present_engine 
elf@4b4969377281:~/workshop$ ./present_engine 
troll.898906189498077
```

> Trolls have blown the fuses in /home/elf/workshop/electrical. cd into electrical and rename blown_fuse0 to fuse0.

```bash
elf@4b4969377281:~/workshop$ cd electrical/
elf@4b4969377281:~/workshop/electrical$ mv blown_fuse0 fuse0
```

> Now, make a symbolic link (symlink) named fuse1 that points to fuse0

```bash
elf@4b4969377281:~/workshop/electrical$ ln -s fuse0 fuse1
```

> Make a copy of fuse1 named fuse2.

```bash
elf@4b4969377281:~/workshop/electrical$ cp fuse1 fuse2
```

> We need to make sure trolls don't come back. Add the characters "TROLL_REPELLENT" into the file fuse2. 

```bash
elf@4b4969377281:~/workshop/electrical$ echo "TROLL_REPELLENT" > fuse2
```

> Find the troll somewhere in /opt/troll_den.

Here we can "cheat" a little bit. `/opt/troll_den` is a Git repository we can check the new / modified files and find 3 trolls immediatelly.

```bash
elf@4b4969377281:~/workshop/electrical$ cd /opt/troll_den/
elf@4b4969377281:/opt/troll_den$ find . -iregex ".*troll.*"
./plugins/embeddedjsp/src/main/java/org/apache/struts2/jasper/compiler/ParserController.java
./apps/showcase/src/main/resources/tRoLl.6253159819943018
./apps/rest-showcase/src/main/java/org/demo/rest/example/IndexController.java
./apps/rest-showcase/src/main/java/org/demo/rest/example/OrdersController.java
```

> Find the file somewhere in /opt/troll_den that is owned by the user troll.

```bash
elf@4b4969377281:/opt/troll_den$ find . -user troll
./apps/showcase/src/main/resources/template/ajaxErrorContainers/tr0LL_9528909612014411
```

> Find the file created by trolls that is greater than 108 kilobytes and less than 110 kilobytes located somewhere in /opt/troll_den.

```bash
elf@4b4969377281:/opt/troll_den$ find . -size +108k -size -110k
./plugins/portlet-mocks/src/test/java/org/apache/t_r_o_l_l_2579728047101724
```

We can "cheat" in the last 3 tasks using `git`:

```bash
elf@4b4969377281:~/workshop/electrical$ cd /opt/troll_den/
elf@4b4969377281:/opt/troll_den$ ls 
CODEOWNERS  Jenkinsfile  LICENSE  SECURITY.md  apps  assembly  bom  bundles  core  mvnw  mvnw.cmd  plugins  pom.xml  src
elf@4b4969377281:/opt/troll_den$ ls -la
total 168
drwxr-xr-x 1 root root  4096 Dec  2 22:19 .
drwxr-xr-x 1 root root  4096 Dec  2 22:19 ..
-rw-r--r-- 1 root root   624 Dec  2 22:19 .asf.yaml
drwxr-xr-x 8 root root  4096 Dec  2 22:19 .git
drwxr-xr-x 3 root root  4096 Dec  2 22:19 .github
-rw-r--r-- 1 root root   515 Dec  2 22:19 .gitignore
drwxr-xr-x 3 root root  4096 Dec  2 22:19 .mvn
-rw-r--r-- 1 root root    81 Dec  2 22:19 CODEOWNERS
-rw-r--r-- 1 root root  6821 Dec  2 22:19 Jenkinsfile
-rw-r--r-- 1 root root 11357 Dec  2 22:19 LICENSE
-rw-r--r-- 1 root root  1727 Dec  2 22:19 SECURITY.md
drwxr-xr-x 1 root root  4096 Dec  2 22:19 apps
drwxr-xr-x 3 root root  4096 Dec  2 22:19 assembly
drwxr-xr-x 2 root root  4096 Dec  2 22:19 bom
drwxr-xr-x 4 root root  4096 Dec  2 22:19 bundles
drwxr-xr-x 3 root root  4096 Dec  2 22:19 core
-rwxr-xr-x 1 root root 10283 Dec  2 22:19 mvnw
-rw-r--r-- 1 root root  6733 Dec  2 22:19 mvnw.cmd
drwxr-xr-x 1 root root  4096 Dec  2 22:19 plugins
-rw-r--r-- 1 root root 45729 Dec  2 22:19 pom.xml
drwxr-xr-x 5 root root  4096 Dec  2 22:19 src
elf@4b4969377281:/opt/troll_den$ git status
fatal: detected dubious ownership in repository at '/opt/troll_den'
To add an exception for this directory, call:

        git config --global --add safe.directory /opt/troll_den
elf@4b4969377281:/opt/troll_den$ git config --global --add safe.directory /opt/troll_den
elf@4b4969377281:/opt/troll_den$ git status
On branch master
Your branch is up to date with 'origin/master'.

Changes not staged for commit:
  (use "git add/rm <file>..." to update what will be committed)
  (use "git restore <file>..." to discard changes in working directory)
        deleted:    README.md

Untracked files:
  (use "git add <file>..." to include in what will be committed)
        apps/showcase/src/main/resources/tRoLl.6253159819943018
        apps/showcase/src/main/resources/template/ajaxErrorContainers/tr0LL_9528909612014411
        plugins/portlet-mocks/src/test/java/org/apache/t_r_o_l_l_2579728047101724

no changes added to commit (use "git add" and/or "git commit -a")
```

> List running processes to find another troll.

```bash
elf@4b4969377281:/opt/troll_den$ ps aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
init           1  0.0  0.0  20112 16548 pts/0    Ss+  22:11   0:00 /usr/bin/python3 /usr/local/bin/tmuxp load ./mysession.yaml
elf        12208  0.2  0.0  31520 26936 pts/2    S+   22:31   0:00 /usr/bin/python3 /14516_troll
elf        12902  0.0  0.0   7672  3312 pts/3    R+   22:33   0:00 ps aux
```

> The 14516_troll process is listening on a TCP port. Use a command to have the only listening port display to the screen.

```bash
elf@4b4969377281:/opt/troll_den$ netstat -tlpn
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:54321           0.0.0.0:*               LISTEN      12208/python3
```

> The service listening on port 54321 is an HTTP server. Interact with this server to retrieve the last troll.

```bash
elf@4b4969377281:/opt/troll_den$ curl localhost:54321
troll.73180338045875 
```

> Your final task is to stop the 14516_troll process to collect the remaining presents.

```bash
elf@4b4969377281:/opt/troll_den$ kill -9 12208
```

> Congratulations, you caught all the trolls and retrieved all the presents!
Type "exit" to close...

```bash
elf@4b4969377281:/opt/troll_den$ exit
```

> **Ginger Breddie (Santa's Surf Shack)**:
*Wow, if your surfing skills are as good as your Linux skills, you could be winning competitions!*