"""
Zachary Jones
ZKJ0007
CSCE 3055
Project 2: JWKS Server SQLite integration
keygen.py: Generate keys to a SQLite database that are encoded for JWKS implementation
"""

import base64
import time
import sqlite3
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

sqlDB = "totally_not_my_privateKeys.db"

class RSAKey:
    def __init__(self, key_id=None, expire_time=1):
        #constructor for the RSAKey, sets an expire time of 1 hour 
        self.priv_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.expire = int(time.time()) + (expire_time * 3600) #set expire time
        self.save_to_db() 
    
    #serialize the private key in PEM for db storage, decodes later.
    def serialize_private_key(self):
        return self.priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ) #decoding to utf8 ensures storage
    
    #save the generated private key to the db
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
            cursor.execute("""
                INSERT INTO keys (key, exp) VALUES (?, ?)""", (self.serialize_private_key(), int(self.expire)))
            conn.commit()


    def expired(self):
        #checks if the key has expired yet using the time
        is_expired = time.time() > self.expire
        return is_expired


    def serialize_jwks(kid, key, exp):
        #converts the key into the JWKS format

        #grabs the public key modulus and public exponent
        pub_key = key.public_key()
        pub_numbers = pub_key.public_numbers()

        #converts those numbers into the base64 format
        n = base64.urlsafe_b64encode(pub_numbers.n.to_bytes(256, byteorder='big')).rstrip(b'=').decode('utf-8')
        e = base64.urlsafe_b64encode(pub_numbers.e.to_bytes(3, byteorder='big')).rstrip(b'=').decode('utf-8')

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