# Hexordia Weekly CTF - iOS - Week 1 - Crewmates are Sus

> What is Chad's user ID for the multiplayer social game?

- Points: `15`

## Solution

- We can find out - for example with iLEAPP - that Among Us (`com.innersloth.amongus`) is installed on the device (the name of the challenge is also a hint (`crewmates`))
- The application home folder can be extracted from `/private/var/mobile/Library/FrontBoard/applicationState.db` in our case it is `/private/var/mobile/Containers/Data/Application/AE23352D-C47B-43D9-87A7-6141653955A2`
- The `userid` can be found in the `Library/Preferences/com.innersloth.amongus.plist` file

```bash
$ cd private/var/mobile/Containers/Data/Application/AE23352D-C47B-43D9-87A7-6141653955A2/Library/Preferences
$ plistutil -i com.innersloth.amongus.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>unity.player_sessionid</key>
	<string>3112481729882798963</string>
	<key>userid</key>
	<string>001381.5ced44f175f640fb9264ce19cc43683f.2043</string>
	<key>Unreal Engine/Identifiers/MachineId</key>
	<string>550951250C432C887ACAB9805D90E03C</string>
	<key>token</key>
	<string>eyJraWQiOiJmaDZCczhDIiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoiY29tLmlubmVyc2xvdGguYW1vbmd1cyIsImV4cCI6MTcwMzgwMTY1MiwiaWF0IjoxNzAzNzE1MjUyLCJzdWIiOiIwMDEzODEuNWNlZDQ0ZjE3NWY2NDBmYjkyNjRjZTE5Y2M0MzY4M2YuMjA0MyIsImNfaGFzaCI6IlhyNTJnV1ZlY2F4dGJzRWlrRnVKenciLCJhdXRoX3RpbWUiOjE3MDM3MTUyNTIsIm5vbmNlX3N1cHBvcnRlZCI6dHJ1ZX0.Va5tJxuUMbA-48vnxu150GjkeCum9KmehGmWT-mQ7ybLBMJHgrYhw28JhI8ielQVdnm6C-iqfKyi8WASKu_Lgrwtp0zduXxMoTI87vWBi3pSR18iwNNQOj-3UxxCw07akWzKQkR_G6ERbrcBazV19oH2WyzVvKvUyMdXVg-HDB7xYtEKY-l761B-cDcDRgy0HOziZyxJXR8_Ru9AdRXB6uD-fbUG2nd2l5RJlp6Qk4FhHncC1J1J-bc20omEHWDi8sQ86YnChPFuiQiNTgUkus6x39KViZ8Rkfn4niacU-U5Zk_j9g31RA0HTp40deO6_OdKiiO2A_-msSEEd61odg</string>
	<key>unity.player_session_count</key>
	<string>2</string>
</dict>
</plist>
```

- We can create a Python script which solves the challenge ([crewmates-are-sus.py](files/crewmates-are-sus.py)):

```python
import sqlite3
import plistlib
import sys
import pathlib

root = pathlib.Path(sys.argv[1])
applicationState = root / 'private/var/mobile/Library/FrontBoard/applicationState.db'
assert(applicationState.exists())

connection = sqlite3.connect(applicationState)

app = 'com.innersloth.amongus'
sql = f"select value from kvs left join application_identifier_tab on kvs.application_identifier=application_identifier_tab.id where kvs.key=1 and application_identifier_tab.application_identifier='{app}'"

cursor = connection.cursor()
rows = cursor.execute(sql).fetchall()
assert(len(rows) == 1)

plist = plistlib.loads(plistlib.loads(rows[0][0]))
app_path = ''
for o in plist['$objects']:
    if '/private/var/mobile/Containers/Data/Application/' in o:
        app_path = pathlib.Path(o)
		break

print(f'{app} - {app_path}')

preferences = root / app_path.relative_to(app_path.anchor) / 'Library' / 'Preferences' / f'{app}.plist'
assert(preferences.exists())

plist = plistlib.loads(open(preferences, 'rb').read())
print(f'userid - {plist["userid"]}')
```

```bash
$ python solve.py /path-to-extracted-image
com.innersloth.amongus - /private/var/mobile/Containers/Data/Application/AE23352D-C47B-43D9-87A7-6141653955A2
userid - 001381.5ced44f175f640fb9264ce19cc43683f.2043
```

Flag: `001381.5ced44f175f640fb9264ce19cc43683f.2043`