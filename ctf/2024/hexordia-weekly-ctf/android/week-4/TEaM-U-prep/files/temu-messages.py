import sqlite3
import sys
import pathlib
import re

root = pathlib.Path(sys.argv[1])
app = 'com.einnovation.temu'
databases_folder = root / f'data/data/{app}/databases/'

databases = []
for db in databases_folder.iterdir():
    m = re.search('ChatDB_.*_msgbox_2\.db',str(db))
    if m is not None:
        databases.append(m.group())
assert(len(databases) == 1)

database = databases_folder / databases[0]
assert(database.exists())

connection = sqlite3.connect(database)
sql = "select summary from message"

cursor = connection.cursor()
rows = cursor.execute(sql).fetchall()
assert(len(rows) >= 1)

for row in rows:
    print(row[0])