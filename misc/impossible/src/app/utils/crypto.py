from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii

FLAG_ENC='ed4e0cc3a8d5d267bc4f1924c552676291a20c681acd8d97c6cdb4b091c705b375e104714d69647541957f82b70cc54705f47c03a5a3b7e95fcb0eb8097d2c0b209c9e60508c0379500c8bb94ad588540bb11c75bff4b44887398b608e3323e17fb3f31b3c8a7a46cae69563014962cc92440c92021d79b17f12e329a371a97f'
KEY='f122df4b445b2c383ace204f1571e410d7c5061c8852ed0b1f1a5e696aab0bea'
IV='b9e3fb697dba55f8753921b88acb8509'

def gen_key(passphrase: str) -> bytes:
    salt = get_random_bytes(16)
    return PBKDF2(passphrase, salt, 32, count=1000000, hmac_hash_module=SHA512)

def encrypt_print(flag: str, key: bytes):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ct = cipher.encrypt(pad(flag.encode(), 32))
    print(f"FLAG_ENC='{ct.hex()}'")
    print(f"KEY='{key.hex()}'")
    print(f"IV='{iv.hex()}'")

def decrypt(key_hex: str) -> str:
    if key_hex != KEY:
        return "Lol we told you this is impossible to solve!"
    key = binascii.unhexlify(key_hex)
    flag_enc = binascii.unhexlify(FLAG_ENC)
    iv = binascii.unhexlify(IV)

    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    pt = unpad(cipher.decrypt(flag_enc), 32)

    try:
        return pt.decode()
    except:
        return "Cannot decode plaintext!"
    
if __name__ == "__main__":
    flag = input("flag: ")
    passphrase = input("passphrase: ")
    key = gen_key(passphrase)
    encrypt_print(flag, key)