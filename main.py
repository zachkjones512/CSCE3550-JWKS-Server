"""
Zachary Jones
ZKJ0007
CSCE 3055
Project 1: JWKS Server
main.py: Host web server using flask and authenticate JWTs
"""

from flask import Flask, jsonify, request #using flask for webserver
import time
from keygen import RSAKey #imports RSAKey class from keygen.py
import jwt
import datetime

app = Flask(__name__) #creates flask application

key_pairs = [RSAKey() for _ in range(5)] #initializes a list of 5 RSA key pairs

#route to grab jwks
@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks(): #returns the JWKS with the public key
    jwks_data = {
        "keys": [key.serialize_jwks() for key in key_pairs if not key.expired()] #use the serialize_jwks method to get the JWKS format
    }
    return jsonify(jwks_data) #returns as a json

#authentication and JWT issue route
@app.route('/auth', methods=['POST'])
def auth():
    use_expired = request.args.get('expired', default=False, type=bool) #checks if expired flag is set

    #if expired flag is set
    if use_expired:
        key = key_pairs[-1]  #make the last key expired
        key_pairs[-1].expire = datetime.datetime.utcnow() - datetime.timedelta(hours=2) #makes sure the key expires
        payload = {
            "sub": "12345678910",
            "name": "Test Name",
            "iat": int(time.time()),
            "exp": int(time.time() - 7200)  #set an expired time two hours before
        }
    else:
        key = next((key for key in key_pairs if not key.expired()), None)
        if key is None:
            return jsonify({"error": "No valid keys available"}), 400
        
        payload = {
            "sub": "12345678910",
            "name": "Test Name",
            "iat": int(time.time()),
            "exp": int(key.expire.timestamp())  #set to a valid expire time
        }

    #encode jwt with private key
    token = jwt.encode(payload, key.serialize_private_key(), algorithm='RS256', headers={"kid": key.kid})
    return jsonify({"token": token})

if __name__ == '__main__':
    app.run(port=8080) #listens on port 8080