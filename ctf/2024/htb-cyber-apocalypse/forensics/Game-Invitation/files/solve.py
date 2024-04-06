def decrypt(encrypted, xor_key=45):
    decrypted = []
    for i in range(0, len(encrypted)):
        decrypted.append(encrypted[i] ^ xor_key)
        xor_key = ((xor_key ^ 99) ^ (i % 254))
    return decrypted

s = b'sWcDWp36x5oIe2hJGnRy1iC92AcdQgO8RLioVZWlhCKJXHRSqO450AiqLZyLFeXYilCtorg0p3RdaoPa'

image = open('image1.jpg', 'rb').read()
index = image.index(s)
encrypted = image[index+len(s):]
print(len(encrypted))
print(bytes(decrypt(encrypted)))
