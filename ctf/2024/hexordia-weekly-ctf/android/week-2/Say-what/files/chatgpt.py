import sqlite3
import sys
import pathlib

root = pathlib.Path(sys.argv[1])
answer = sys.argv[2]
app = 'com.smartwidgetlabs.chatgpt'
database = root / f'data/data/{app}/databases/chat_gpt_database'
assert(database.exists())

connection = sqlite3.connect(database)
sql = "select yourText from conversations where statusMessage=? or answerText=?"

cursor = connection.cursor()
rows = cursor.execute(sql,(answer, answer)).fetchall()
assert(len(rows) >= 1)

for row in rows:
    print(row[0])