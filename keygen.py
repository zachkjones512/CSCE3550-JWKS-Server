"""
Zachary Jones
ZKJ0007
CSCE 3055
Project 2: JWKS Server SQLite integration
keygen.py: Generate keys to a SQLite database that are encoded for JWKS implementation
"""

from base64 import b64encode, b64decode
import time
import sqlite3
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes #used for decryption
from cryptography.hazmat.backends import default_backend #used in cipher
import os

sqlDB = "totally_not_my_privateKeys.db"

if 'NOT_MY_KEY' not in os.environ: #create temporary env variable
    temp_key = os.urandom(16)
    os.environ['NOT_MY_KEY'] = b64encode(temp_key).decode('utf-8')
    print("--temp key set")


class RSAKey:
    def __init__(self, key_id=None, expire_time=1):
        #constructor for the RSAKey, sets an expire time of 1 hour 
        self.priv_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.expire = int(time.time()) + (expire_time * 3600) #set expire time
        self.save_to_db() 

    def grab_key(): #grabs key from environment variable
        env_key = os.environ.get('NOT_MY_KEY')
        if not env_key:
            print("ERROR: no NOT_MY_KEY env variable")
        return b64decode(env_key) #decodes key

    #aes decryption and encryption functions for the private key
    def encrypt_data(self, data):

        aes_key = RSAKey.grab_key()
        cipher = Cipher(algorithms.AES(aes_key), modes.ECB(), backend=default_backend()) #ecb because no iv
        encryptor = cipher.encryptor()


        #create padding to ensure its a multiple of 16 bytes
        if len(data) % 16 != 0:
            data = data + b'\0' * (16 - len(data) % 16)

        ciphertext = encryptor.update(data) + encryptor.finalize()
        return ciphertext

    def decrypt_data(encrypted): #can decrypt the key from the aes format if necessary
        aes_key = RSAKey.grab_key()
        cipher = Cipher(algorithms.AES(aes_key), modes.ECB(), backend=default_backend())  # Use ECB mode
        decryptor = cipher.decryptor()

        decrypted_data = decryptor.update(encrypted) + decryptor.finalize()

        #remove padding
        decrypted_data = decrypted_data.rstrip(b'\0')
        
        return decrypted_data #returns decrypted aes key


    #serialize the private key in PEM for db storage, decodes later.
    def serialize_private_key(self):
        return self.priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    
    #serializes public key for DB storage, just like above
    def serialize_public_key(self):
        public_key = self.priv_key.public_key()
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo            
        ).decode('utf-8')
    
    #save the generated private key and its public key to the db
    def save_to_db(self):
        with sqlite3.connect(sqlDB) as conn: #This is used to close the transaction block and ensure save
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS keys(
                    kid INTEGER PRIMARY KEY AUTOINCREMENT,
                    key BLOB NOT NULL,                                       
                    exp INTEGER NOT NULL
                )    
           """)
            conn.commit()
            
        serialized_key = self.serialize_private_key() 
        encrypted_key = self.encrypt_data(serialized_key)
        if not encrypted_key:
            print("error: encrypted private key is empty or non generated")

        with sqlite3.connect(sqlDB) as key_conn:
            key_cursor = key_conn.cursor()
            key_cursor.execute("""
                INSERT INTO keys (key, exp) VALUES (?, ?)""", (encrypted_key, int(self.expire)))
            key_conn.commit()


    def expired(self):
        #checks if the key has expired yet using the time
        is_expired = time.time() > self.expire
        return is_expired

    @staticmethod
    def serialize_jwks(kid, key, exp):
        #converts the key into the JWKS format

        #grabs the public key modulus and public exponent
        pub_key = key.public_key()
        pub_numbers = pub_key.public_numbers()

        #converts those numbers into the base64 format
        n = b64encode(pub_numbers.n.to_bytes(256, byteorder='big')).rstrip(b'=').decode('utf-8')
        e = b64encode(pub_numbers.e.to_bytes(3, byteorder='big')).rstrip(b'=').decode('utf-8')

        #generate json
        jwks = {
            "kid": kid,
            "alg": "RS256",
            "typ": "JWT",         
            "kty": "RSA",           
            "use": "sig",           
            "n": n,                 
            "e": e,                 
            "exp": exp
        }
        return jwks        