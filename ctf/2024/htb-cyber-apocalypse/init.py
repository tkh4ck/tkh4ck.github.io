import json
import os

categories = {
    2 : 'web', 
    3 : 'pwn', 
    4 : 'crypto', 
    5 : 'reverse', 
    7 : 'forensics', 
    8 : 'misc',
    14 : 'blockchain', 
    15 : 'hardware'
}

ctf = ''

challenges = json.load(open('challenges.json'))

for category in categories.values():
    try:
        os.mkdir(category)
    except:
        pass

for challenge in challenges['challenges']:
    category = categories[challenge['challenge_category_id']]
    name = challenge['name']
    print(category, name)
    try:
        os.mkdir(f'{category}/{name.replace(" ", "-")}')
    except:
        pass
    readme = open(f'{category}/{name.replace(" ", "-")}/README.md', 'w')
    readme.write(f'# {ctf} - {name}\n')
    readme.write('\n')
    readme.write('## Challenge\n')
    readme.write('\n')
    readme.write(f'> {challenge["description"]}\n')
    readme.write('\n')
    readme.write('## Metadata\n')
    readme.write('\n')
    readme.write(f'- Difficulty: {challenge["difficulty"]}\n')
    readme.write(f'- Creator: {challenge["creator"]}\n')
    readme.write(f'- Filename: {challenge["filename"]}\n')
    readme.write(f'- Docker: {"yes" if challenge["hasDocker"]==1 else "no"}\n')
    readme.write('- Tags: \n')
    readme.write('- Points: \n')
    readme.write('- Number of solvers: \n')
    readme.write('\n')
    readme.write('## Solution\n')
    readme.write('\n')
    readme.close()
