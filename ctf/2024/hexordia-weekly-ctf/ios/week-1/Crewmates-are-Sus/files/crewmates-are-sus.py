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