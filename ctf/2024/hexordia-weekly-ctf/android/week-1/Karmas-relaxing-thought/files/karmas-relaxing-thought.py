import sqlite3
import sys
import pathlib
from datetime import datetime

root = pathlib.Path(sys.argv[1])
app = 'com.reddit.frontpage'
databases = root / f'data/data/{app}/databases'
assert(databases.exists())

database = None
for db in databases.glob('reddit_db_*'):
    if 'anonymous' not in str(db):
        database = db
        break

assert(database is not None)
connection = sqlite3.connect(database)

sql = f"select timestamp from karma_statistics"

cursor = connection.cursor()
rows = cursor.execute(sql).fetchall()
assert(len(rows) >= 1)

ts = rows[0][0] / 1000
print(datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S'))