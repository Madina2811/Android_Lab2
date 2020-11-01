import sys
from base64 import b64decode

from Crypto.Cipher import AES

from pkcs7 import PKCS7Encoder

#
def encrypt(plaintext, key, iv):
    global encoder

    aes = AES.new(key, AES.MODE_CBC, iv)
    pad_text = encoder.encode(plaintext)
    return aes.encrypt(pad_text)


def decrypt(ciphertext, key, iv):
    global encoder
    aes = AES.new(key.encode("utf8"), AES.MODE_CBC, iv.encode("utf8"))
    pad_text = aes.decrypt(ciphertext)
    return pad_text


if __name__ == '__main__':
    encoder = PKCS7Encoder()

    chipertext = b64decode("ojDcwKqyZdCPMX1KNLBlsg==")
    key = 'fqIhyykbTjNQ2QdQlBOISw=='
    iv = '8119745113154120'

    print("chipertext: '%s'" % chipertext)
    print("key: '%s'" % key)
    print("IV: '%s'" % iv)

    decrypted = decrypt(chipertext, key, iv)

    print("encrypted: '%s'" % decrypted)
