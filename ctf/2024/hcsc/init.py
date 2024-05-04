import json
import os
import requests
import string
import urllib.request
from pathlib import Path

BASE_URL = 'https://ctfd.nki.gov.hu'
API_URL = f'{BASE_URL}/api/v1'
API_KEY = '[API_KEY]'

s = requests.Session()
s.headers.update({ 'Authorization': f'Token {API_KEY}'})
s.headers.update({ 'Content-Type': 'application/json'})

challenges = s.get(f'{API_URL}/challenges').json()
categories = {}
ctf = 'HCSC 2024'

translate_dict = {}
for c in string.punctuation:
    translate_dict[c] = ''
translate_dict[' '] = '-'
translate_obj = str.maketrans(translate_dict)

for challenge in challenges['data']:
    category = challenge['category']
    category_sanitized = challenge['category'].translate(translate_obj)
    Path(category_sanitized).mkdir(parents=True, exist_ok=True)

    id = challenge['id']
    name = challenge['name']
    name_sanitized = challenge['name'].translate(translate_obj)
    value = challenge['value']
    solves = challenge['solves']
    print(category, name)
    Path(f'{category_sanitized}/{name_sanitized}').mkdir(parents=True, exist_ok=True)

    chall = s.get(f'{API_URL}/challenges/{id}').json()
    description = chall['data']['description']
    if len(chall['data']['files']) > 0:
        Path(f'{category_sanitized}/{name_sanitized}/files').mkdir(parents=True, exist_ok=True)
        for file_url in chall['data']['files']:
            req = s.get(f'{BASE_URL}{file_url}')
            filename = file_url.split('?')[0].split('/')[-1]
            with open(f'{category_sanitized}/{name_sanitized}/files/{filename}', 'wb') as f:
                f.write(req.content)
    with open(f'{category_sanitized}/{name_sanitized}/README.md', 'w') as readme:
        readme.write(f'# {ctf} - {name}\n')
        readme.write('\n')
        readme.write('## Description\n')
        readme.write('\n')
        readme.write(f'{description}\n')
        readme.write('\n')
        if len(chall['data']['hints']) > 0:
            for hint in chall['data']['hints']:
                readme.write(f'> Hint 1 (cost {hint["cost"]}): {hint["content"]}\n\n')
        readme.write('## Metadata\n')
        readme.write('\n')
        readme.write(f'- Filename: \n')
        readme.write('- Tags: \n')
        readme.write(f'- Points: {value}\n')
        readme.write(f'- Number of solvers: {solves}\n')
        readme.write('\n')
        readme.write('## Solution\n')
        readme.write('\n')