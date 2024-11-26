import sqlite3
from contextlib import contextmanager
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import SHA256
from base64 import urlsafe_b64decode, urlsafe_b64encode
from cryptography.hazmat.primitives import padding
from base64 import b64decode
from base64 import b64encode
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import logging
import os
import ehrenlos
import random
import string

# Configure logging for database errors
logging.basicConfig(filename='database_errors.log', level=logging.ERROR, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

class Database:
    def __init__(self, db_path):
        self.db_path = db_path
        self.connection = None
        self.cursor = None

    def encrypt_data(self, plaintext: str, random=False, key:bytes=None, iv:bytes=None) -> bytes:
        """
        Encrypts the given plaintext using AES with the provided key and IV.

        Args:
            plaintext (bytes): The data to encrypt.
            key (bytes): The AES encryption key.
            iv (bytes): The initialization vector (IV).

        Returns:
            bytes: The encrypted ciphertext.
        """
        # Convert the plaintext string to bytes
        plaintext_bytes = plaintext.encode('utf-8')
        del plaintext

        if random:
            # Generate random key and IV
            key = os.urandom(32)  # 256-bit key
            iv = os.urandom(16)   # 16 bytes for AES IV

        # Pad the plaintext to make it a multiple of the block size
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext_bytes) + padder.finalize()

        # Create a Cipher object and encrypt the data
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return [ciphertext, key, iv]

    def decrypt_data(self, ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        """
        Decrypts the given ciphertext using AES with the provided key and IV.

        Args:
            ciphertext (bytes): The encrypted data.
            key (bytes): The AES decryption key.
            iv (bytes): The initialization vector (IV).

        Returns:
            bytes: The decrypted plaintext.
        """
        # Create a Cipher object and decrypt the data
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove padding from the decrypted data
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(decrypted_padded_data) + unpadder.finalize()

        return plaintext

    def connect(self):
        """Establish a connection to the database."""
        try:
            self.connection = sqlite3.connect(self.db_path, check_same_thread=False)
            self.cursor = self.connection.cursor()
            print("Database connection established.")
        except Exception as e:
            print(f"Error connecting to the database: {e}")
            raise

    def disconnect(self):
        """Close the database connection."""
        if self.connection:
            self.connection.close()
            print("Database connection closed.")

    def execute_query(self, query, params=None):
        """Execute a query with optional parameters."""
        if not self.connection or not self.cursor:
            raise ValueError("Database connection is not initialized. Call `connect` first.")
        try:
            if params:
                self.cursor.execute(query, params)
            else:
                self.cursor.execute(query)
            self.connection.commit()
        except Exception as e:
            print(f"Error executing query: {e}")
            raise


    def create_tables(self):
        try:
            self.execute_query("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    password BLOB NOT NULL,
                    website TEXT NOT NULL,
                    encryption_key BLOB NOT NULL,
                    iv_env BLOB NOT NULL
                )
            """)
            self.execute_query("""
                CREATE TABLE IF NOT EXISTS master (
                    id INTEGER PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    encrypted_master_password BLOB NOT NULL
                )
            """)
            print("Tables created successfully.")
        except Exception as e:
            print(f"Error creating tables: {e}")
            raise

    def add_pass(self, username, password, website):

        # encrypt password
        mpList = self.encrypt_data(plaintext=password, random=True)

        encrypted_password = mpList[0]
        encryption_key = mpList[1]
        iv_env = mpList[2]

        try:
            self.execute_query(
                """
                INSERT INTO users (username, password, website, encryption_key, iv_env) 
                VALUES (?, ?, ?, ?)
                """,
                (username, encrypted_password, website, encryption_key, iv_env)
            )
            print(f"User {username} added successfully.")
        except Exception as e:
            print(f"Error adding user: {e}")
            raise

    def log_in(self, raw_userID, raw_masterPass):
        # verify user id
        userID = self.get_user_id()
        
        # verify master password
        mpList_enc = ehrenlos.check(raw_masterPass)
        encrypted_raw_masterPass_bytes_list = self.encrypt_data(raw_masterPass, key=mpList_enc[1], iv=mpList_enc[2])
        encrypted_raw_masterPass_bytes = encrypted_raw_masterPass_bytes_list[0]
        encrypted_master_password = self.get_encrypted_master_password()

        # Convert bytes to a Base64 string
        encrypted_raw_master_password = b64encode(encrypted_raw_masterPass_bytes).decode('utf-8')

        # moment of truth
        if raw_userID == userID and encrypted_raw_master_password == encrypted_master_password:
            return True
        else:
            return False

    def get_user_id(self):
        query = "SELECT user_id FROM master WHERE id = 1"
        try:
            self.cursor.execute(query)  # Execute the query
            result = self.cursor.fetchone()  # Fetch the first result
            if result:  # Check if result is not None
                return result[0]  # Extract the user_id value from the tuple
            return None
        except Exception as e:
            print(f"Error fetching user ID: {e}")
            raise
    
    def get_encrypted_master_password(self):
        query = "SELECT encrypted_master_password FROM master WHERE id = 1"
        try:
            self.cursor.execute(query)
            result = self.cursor.fetchone()
            if result:
                return result[0]
            return None
        except Exception as e:
            print(f"Error fetching encrypted master password: {e}")
            raise

    def sign_up(self, raw_master_password):
        userID = self.create_user_id()
        mpList = self.encrypt_data(plaintext=raw_master_password, random=True)
        del raw_master_password

        # Save the encrypted version
        encrypted_master_password_bytes = mpList[0]
        mpList.pop(0)

        # Convert bytes to a Base64 string
        encrypted_master_password = b64encode(encrypted_master_password_bytes).decode('utf-8')

        # ???
        ehrenlos.ehrenlos(mpList=mpList)
        del mpList

        # Save to database
        try:
            self.execute_query(
                """
                INSERT INTO master (user_id, encrypted_master_password)
                VALUES (?, ?)
                """,
                (userID, encrypted_master_password)
            )
        except Exception as e:
            print("Error signing up")
            print("Please try again later")
            raise


    def log_out(self):
        self.disconnect()
        exit()

    def create_user_id(self):
        length = 7
        # Define the pool of characters (letters and digits)
        characters = string.ascii_letters + string.digits
        # Use random.choices to pick characters
        random_string = ''.join(random.choices(characters, k=length))
        return random_string
        