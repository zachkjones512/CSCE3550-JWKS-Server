"""
Zachary Jones
ZKJ0007
CSCE 3055
Project 1: JWKS Server
keygen.py: Generate keys in JWKS format
"""

import base64
import datetime
import uuid
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

class RSAKey:
    def __init__(self, key_id=None, expire_time=1):
        #constructor for the RSAKey, sets an expire time of 1 hour 
        self.priv_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.pub_key = self.priv_key.public_key() #generate public key from the private
        self.kid = str(uuid.uuid4()) #set kid to initialized key id or a unique key id
        self.expire = datetime.datetime.utcnow() + datetime.timedelta(hours=expire_time) #set expire time 
    
    #serialize the private key to decode the jwt later
    def serialize_private_key(self):
        return self.priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    
    def expired(self):
        #checks if the key has expired yet using the time
        is_expired = datetime.datetime.utcnow() > self.expire
        if is_expired:
            print(f"Key {self.kid} has expired.")
        return is_expired

    def encode_base64(self, data):
        #encodes in base64 for JWKS
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

    def serialize_jwks(self):
        #converts the key into the JWKS format

        #grabs the public key modulus and public exponent
        pub_numbers = self.pub_key.public_numbers()

        #converts those numbers into the base64 format
        n = self.encode_base64(pub_numbers.n.to_bytes(256, byteorder='big')) 
        e = self.encode_base64(pub_numbers.e.to_bytes(3, byteorder='big'))

        #generate json
        jwks = {
            "kid": self.kid,
            "alg": "RS256",
            "typ": "JWT",         
            "kty": "RSA",           
            "use": "sig",           
            "n": n,                 
            "e": e,                 
            "exp": int(self.expire.timestamp())  
        }
        return jwks        