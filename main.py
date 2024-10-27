"""
Zachary Jones
ZKJ0007
CSCE 3055
Project 2: JWKS Server
main.py: Host web server using flask and authenticate JWTs
"""

from flask import Flask, jsonify, request #using flask for webserver
from cryptography.hazmat.primitives import serialization
import time
import jwt
import sqlite3
from keygen import RSAKey, sqlDB #imports RSAKey class from keygen.py

app = Flask(__name__) #creates flask application

#route to grab jwks
@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks(): #returns the JWKS with the public key

    jwks_keys = [] #list that holds the keys

    with sqlite3.connect(sqlDB) as conn: #Read all the entries in the database
        cursor = conn.cursor()
        cursor.execute("SELECT kid,key,exp FROM keys WHERE exp >= ?",  (int(time.time()),))
        rows = cursor.fetchall()
        for row in rows:
            kid, key_en, exp = row #creates a tuple of each row with the kid, the key, and the exp
            key = serialization.load_pem_private_key(key_en, password=None) #loads the private key
            jwks_keys.append(RSAKey.serialize_jwks(str(kid), key, exp)) #use the serialize_jwks method to get the JWKS format
    
    jwks_output = {
        "keys": jwks_keys
    }

    return jsonify(jwks_output) #returns as a json

#authentication and JWT issue route
@app.route('/auth', methods=['POST'])
def auth():
    use_expired = request.args.get('expired', default=False, type=bool) #checks if expired flag is set

    with sqlite3.connect(sqlDB) as conn: #Read all the entries in the database
        cursor = conn.cursor()

    #if expired flag is set select expired key, otherwise select non-expired keys
    if use_expired:
        cursor.execute("SELECT kid,key,exp FROM keys WHERE exp < ?",  (int(time.time()),))
        row = cursor.fetchone() #grabs first matching row
        if row is None:
            print("Expired key not in database! ERROR!")
        else:
            print("Expired key added to database")
    else: 
        cursor.execute("SELECT kid,key,exp FROM keys WHERE exp >= ?",  (int(time.time()),))
        row = cursor.fetchone() #grabs first matching row
        if row is None: #if no row found
            return jsonify({"error": "No valid keys available"}), 400 
    
    kid, key_en, exp = row #creates a tuple of the row with the kid, the key, and the exp
    key = serialization.load_pem_private_key(key_en, password=None) #loads the private key  

    payload = {
        "sub": "12345678910",
        "name": "Test Name",
        "iat": int(time.time()),
        "exp": int(exp)  #set to a valid expire time
    }

    #encode jwt with private key
    token = jwt.encode(payload, key, algorithm='RS256', headers={"kid": str(kid)})
    return jsonify({"token": token})

if __name__ == '__main__':
    for i in range(5): #initializes a list of 5 RSA key pairs and saves them in DB
        expire_time = -1 if i==4 else 1 #makes the last one expired
        key = RSAKey(expire_time=expire_time) 

    app.run(port=8080) #listens on port 8080
