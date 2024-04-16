import sqlite3
import sys
import pathlib

root = pathlib.Path(sys.argv[1])
question = sys.argv[2]
app = 'com.smartwidgetlabs.chatgpt'
database = root / f'data/data/{app}/databases/chat_gpt_database'
assert(database.exists())

connection = sqlite3.connect(database)
sql = "select answerText, statusMessage from conversations where yourText LIKE ?"

cursor = connection.cursor()
rows = cursor.execute(sql, (f'%{question}%',)).fetchall()
assert(len(rows) >= 1)

for row in rows:
    print('Answer: ', row[0])
    print('Status: ', row[1])