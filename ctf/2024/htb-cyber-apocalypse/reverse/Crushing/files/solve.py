dump = open('message.txt.cz', 'rb').read()
entries = []
length = 0

for i in range(0, len(dump), 8):
    value = int.from_bytes(dump[i:i+8], "little")
    entries.append(value)
    if value > length:
        length = value

text = ['*'] * (length+1)

size = 0
character = 0
i = 0
while i < len(entries):
    if i == 0:
        while i == 0:
            i += 1
        size = entries[i]
        character = i
        for j in range(i+1, i+1+size):
            text[entries[j]] = chr(character)
    else:
        size = entries[i]
        character = character + 1
        for j in range(i+1, i+1+size):
            text[entries[j]] = chr(character)
    i = i + 1 + size
print(''.join(text))