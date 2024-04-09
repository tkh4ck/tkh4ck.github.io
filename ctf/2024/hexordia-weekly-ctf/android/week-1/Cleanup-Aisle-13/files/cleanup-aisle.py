import sqlite3
import sys
import pathlib

root = pathlib.Path(sys.argv[1])
app = 'com.thehomedepotca'
database = root / f'data/data/{app}/databases/HD_DATA_BASE'
assert(database.exists())

connection = sqlite3.connect(database)

sql = f"select average_rating from recently_viewed_items"

cursor = connection.cursor()
rows = cursor.execute(sql).fetchall()
assert(len(rows) >= 1)

print(rows[0][0])