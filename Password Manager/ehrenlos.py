from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import SHA256
from base64 import urlsafe_b64decode, urlsafe_b64encode
from cryptography.hazmat.primitives import padding
from base64 import b64decode
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pickle
import os

CONFIG_FILE = "config.enc"

def ehrenlos(mpList):
     ehrenlos_write(mpList)

def ehrenlos_write(encrypted_mpList):
    with open(CONFIG_FILE, "wb") as file:
        pickle.dump(encrypted_mpList[0], file)
        pickle.dump(encrypted_mpList[1], file)

    del encrypted_mpList

def check(raw_master_password):
    with open(CONFIG_FILE, "rb") as file:
        obj1 = pickle.load(file)
        obj2 = pickle.load(file)

    mpList_enc = [raw_master_password, obj1, obj2]
    return mpList_enc
