# JWKS Server - CSCE 3055 Project 1

### Code by Zachary Jones

#### Keygen.py

Generate keys in JWKS format

#### Main.py

Creates a flask webserver that has the following endpoints:
`/jwks` which returns public RSA keys 
`/auth` which returns a signed JWT. Using `expired=true` you can get a JWT signed with an expired key

### How to Run
For the requirements you can use pip to install them with the requirements.txt file using the following command:
`pip install -r requirements.txt`

In the terminal type:
`python main.py`

This will start the Flask server on localhost:8080
