from Crypto.Cipher import AES

def decrypt(key, iv, enc):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(enc)

def _unpad(s):
    return s[:-ord(s[len(s)-1:])]

key = bytes.fromhex("16edb3aca07e08f1ec7d95877a362ecfdeaa1a336ce719f0d16ea4f8aee61930")
iv = bytes.fromhex("e09d4da3162dc5209bef781c27aca70e")
encrypted = open('Applicants_info.xlsx.korp', 'rb').read()

decrypted = decrypt(key, iv, encrypted)
open('Applicants_info.xlsx', 'wb').write(decrypted)