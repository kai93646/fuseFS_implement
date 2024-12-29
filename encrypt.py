from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

class AESCipher:
    def encrypt(data: bytes, key: bytes, iv: str='This is an IV123'):
        cipher = AES.new(key, AES.MODE_CBC, iv.encode('utf-8'))
        encrypted = cipher.encrypt(pad(data, AES.block_size))
        return encrypted
    
    def decrypt(data: bytes, key: bytes, iv: str='This is an IV123'):
        cipher = AES.new(key, AES.MODE_CBC, iv.encode('utf-8'))
        decrypted = unpad(cipher.decrypt(data), AES.block_size)
        return decrypted

    def add_key():
        key = get_random_bytes(16)
        return key
        

if __name__ == "__main__":
    key = get_random_bytes(16)


#aes needed variables: key, target file, iv
#aes needed functions: encrypt, decrypt
#aes needed vars in decrypt: key, target file, iv