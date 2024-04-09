# Hexordia Weekly CTF - Android - Week 1 - Karma's relaxing thought

> When was the user upvoted?

- Points: `25`

## Solution

- The description (`upvote`) and the challenge name `karma` hints that we have to look around the Reddit application
- The home folder of the app is at `/data/data/com.reddit.frontpage`
- The main database storing the user related information is `databases/reddit_db_NarrowEcho136`
- The user gets karma points if their posts / comments are upvoted
- Luckily for us the user has only 1 karma and the `karma_statistics` table stores the timestamp of each karma score change
```
$ sqlite3 data/data/com.reddit.frontpage/databases/reddit_db_NarrowEcho136
SQLite version 3.45.1 2024-01-30 16:01:20
Enter ".help" for usage hints.
sqlite> .tables
account                        room_master_table
account_mutations              skipped_geo_tagging
android_metadata               subreddit
announcement                   subreddit_channels
chat_goal                      subreddit_chats_availability
comment_mutations              subreddit_extra
comments                       subreddit_forking
crowdsource_tagging_questions  subreddit_leaderboard
experiments                    subreddit_mutations
karma_statistics               subreddit_pinned_posts
link                           subreddit_topic
link_mutations                 subreddit_triggered_invite
listing                        survey_local_demo
listing_discovery_unit         survey_status
live_chats                     unsubmitted_pixels
moderatorsresponse             userMyReddits
query                          userSocialLink
recent_subreddits              user_subreddit

sqlite> .schema karma_statistics
CREATE TABLE `karma_statistics` (`id` INTEGER PRIMARY KEY AUTOINCREMENT, `timestamp` INTEGER NOT NULL, `karma` INTEGER NOT NULL);
CREATE INDEX `index_karma_statistics_timestamp` ON `karma_statistics` (`timestamp`);

sqlite> select * from karma_statistics;
1|1703627653479|1
```

- We can also create a small Python script to solve the challenge ([karmas-relaxing-thought.py](files/karmas-relaxing-thought.py)):

```python
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
```

```bash
$ python solve.py /path-to-extracted-image
2023-12-26 21:54:13
```

Flag: `2023-12-26 21:54:13`