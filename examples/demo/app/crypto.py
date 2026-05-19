import hashlib
from Crypto.PublicKey import RSA, DSA
from Crypto.Cipher import DES, AES

# legacy MD5 fingerprint
def fingerprint(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()

def sha1_digest(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()

# weak RSA key generation
def gen_rsa_1024():
    return RSA.generate(1024)

def gen_rsa_2048():
    return RSA.generate(2048)

# DSA, deprecated
def gen_dsa():
    return DSA.generate(2048)

def des_encrypt(key, data):
    return DES.new(key, DES.MODE_ECB).encrypt(data)

def aes_encrypt(key, data):
    return AES.new(key, AES.MODE_GCM).encrypt(data)
