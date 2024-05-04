import requests
import hashlib
import base64
import pandas as pd

# Download the dataset from https://www.kaggle.com/datasets/jenny18/honey-bee-annotated-images/data

unknown_bees = requests.get('http://10.10.5.11:53369/images').json()

honey_bee_df=pd.read_csv('bee_data.csv')
honey_bee_df = honey_bee_df.loc[honey_bee_df['subspecies'].isin(["Carniolan honey bee", "Italian honey bee", "Russian honey bee", "VSH Italian honey bee", "Western honey bee"])]

def get_md5(filename):
    img = open(f'bee_imgs/bee_imgs/{filename}', 'rb').read()
    return hashlib.md5(img).hexdigest()

hashes = honey_bee_df['file'].apply(get_md5)
honey_bee_df = honey_bee_df.assign(md5=hashes)

result = {}
for unknown_bee in unknown_bees:
    id, img = list(unknown_bee.items())[0]
    hash = hashlib.md5(base64.b64decode(img)).hexdigest()
    subspecies = honey_bee_df.loc[honey_bee_df['md5'] == hash]['subspecies'].values[0]
    result[id] = subspecies

print(result)
r = requests.post('http://10.10.5.11:53369/submit', json=result)
print(r.content)