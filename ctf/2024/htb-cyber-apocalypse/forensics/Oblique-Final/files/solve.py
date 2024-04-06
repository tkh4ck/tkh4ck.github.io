payload = bytes.fromhex('4e8ef433206f58a04932c6a142f669740ad087b6a2151f9dda3acb65231b05171dd1b05b5b4e03cb6b08c1f507e87c3744d0b9efa95c218788309163284c050b1d8dcf753f7e27f64f64ede645b1626275d1d7b5f3545fcec4728d70221c511554c3b6352f621df6073bdde256e96b7445c296fba65c1386d73bd165341905555f90b0746e611daf4625d1e95ef169655e9ad6e9e7171f8bdd7000')
key = bytes.fromhex('2de390130f0c78822757b28137850c062ab7e6dbc7387eefb952a2114678713a')

def decrypt(payload, key):
    result = ''
    for i in range(len(payload)):
        j = i >> 0x1f & 0x1f
        result += chr(payload[i] ^ key[((i + j & 0x1f) - j)])
    return result
    
result = decrypt(payload, key)
print(result)