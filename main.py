"""
Zachary Jones
ZKJ0007
CSCE 3055
Project 2: JWKS Server
main.py: Host web server using flask and authenticate JWTs
"""

from flask import Flask, jsonify, request #using flask for webserver
from cryptography.hazmat.primitives import serialization
from argon2 import PasswordHasher
import time
import jwt
import sqlite3
import uuid
from keygen import RSAKey, sqlDB #imports RSAKey class from keygen.py


app = Flask(__name__) #creates flask application

#token bucket class for rate-limiting the auth route
class token_bucket:
    def __init__(self, rate: int, capacity: int):
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.last_refill = time.time()
    
    def refill(self):
        #refill tokens after the time has passed
        now = time.time()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.last_refill = now

    def consume(self, count: int = 1) -> bool:
        #returns true if tokens are avaialble and consumes token, count = tokens to consume
        self.refill()
        if self.tokens >= count:
            self.tokens -= count
            return True
        return False

#route to grab jwks
@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks(): #returns the JWKS with the public key

    jwks_keys = [] #list that holds the keys

    with sqlite3.connect(sqlDB) as conn: #Read all the entries in the database
        cursor = conn.cursor()
        cursor.execute("SELECT kid,key,exp FROM keys WHERE exp >= ?",  (int(time.time()),))
        rows = cursor.fetchall()
        for row in rows:
            kid, public_key, exp = row #creates a tuple of each row with the kid, the key, and the exp
            key = serialization.load_pem_public_key(public_key.encode('utf-8')) #loads the private key
            jwks_keys.append(RSAKey.serialize_jwks(str(kid), key, exp)) #use the serialize_jwks method to get the JWKS format
    
    jwks_output = {
        "keys": jwks_keys
    }

    return jsonify(jwks_output) #returns as a json

#registration route
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    username = data.get('username')
    email = data.get('email')

    if not username or not email:
        return jsonify({"error: Username and email required"}), 400
    
    #generates password
    password = str(uuid.uuid4())

    #hashes password
    hasher = PasswordHasher()
    hashed = hasher.hash(password)

    #store data and hashed password in users table
    with sqlite3.connect(sqlDB) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO users (username, password_hash, email)
            VALUES (?, ?, ?)
        """, (username, hashed, email))
        conn.commit()
        #return original to user
        return jsonify({"password": password}), 201

#authentication and JWT issue route
@app.route('/auth', methods=['POST'])
def auth():
    
    #initialize token bucket to rate limit to 10 requests per second
    rate_limiter = token_bucket(rate=10, capacity=10)

    if not rate_limiter.consume():
        return jsonify({"error": "Rate limit exceeded, try again later."}), 429

    data = request.get_json()

    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error: Username and password required"}), 400
    
    with sqlite3.connect(sqlDB) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.commit()
        if not user:
            return jsonify({"error": "No matching user or password"}), 401
        
        user_id, hash = user

        #verify password
        hasher = PasswordHasher()
        try:
            hasher.verify(hash, password)
        except:
                return jsonify("error: no matching user or password")

        user_ip = request.remote_addr
        
        with sqlite3.connect(sqlDB) as log_conn:
            log_cursor = log_conn.cursor()
            log_cursor.execute("""
                INSERT INTO auth_logs (request_ip, user_id)
                VALUES (?, ?)
            """, (user_ip, user_id))
            log_conn.commit()

        with sqlite3.connect(sqlDB) as key_conn:
            key_cursor = key_conn.cursor()
            key_cursor.execute("SELECT kid, key, exp FROM keys WHERE exp >= ?", (int(time.time()),))
            row = key_cursor.fetchone()
            key_conn.commit()
            if row is None:
                return jsonify({"error": "No valid keys available"}), 400
            
    kid, key_en, exp = row  #creates a tuple of the row with the kid, the encrypted key, and the exp
    #decrypt private key to sign
    private_key_pem = RSAKey.decrypt_data(key_en) 
    private_key_obj = serialization.load_pem_private_key(private_key_pem, password=None)

    #SEND PRIV KEY WITH JWT
    payload = {
        "sub": "12345678910",
        "name": "Test Name",
        "iat": int(time.time()),
        "exp": int(exp),  #set to a valid expire time
    }

    #encode jwt with private key
    token = jwt.encode(payload, private_key_obj, algorithm='RS256', headers={"kid": str(kid)})
    return jsonify({"token": token}, 200)

if __name__ == '__main__':
    for i in range(5): #initializes a list of 5 RSA key pairs and saves them in DB
        expire_time = 1
        key = RSAKey(expire_time=expire_time) 

    with sqlite3.connect(sqlDB) as conn: #create users and auth_logs table
        cursor = conn.cursor()
        cursor.execute("""
                        CREATE TABLE IF NOT EXISTS users(
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL UNIQUE,
                        password_hash TEXT NOT NULL,
                        email TEXT UNIQUE,
                        date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_login TIMESTAMP      
            )   
        """)
        cursor.execute("""
                       
                        CREATE TABLE IF NOT EXISTS auth_logs(
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        request_ip TEXT NOT NULL,
                        request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        user_id INTEGER,  
                        FOREIGN KEY(user_id) REFERENCES users(id)
            );
        """) 
    app.run(port=8080) #listens on port 8080
