# JWKS Server - CSCE 3055 Project 2

### Code by Zachary Jones

#### Keygen.py

Generate keys in JWKS format and places them in a SQLite database

#### Main.py

Creates a flask webserver that has the following endpoints:
`/.well-known/jwks.json` which returns a json demonstrating the database holding encrypted private RSA keys
`/register` which generates a password for a user after their username and email are sent in the request. This password is returned to the user and necessary for a JWT
`/auth` which returns a signed JWT. This endpoint first checks for whether the user has registered. Each request is logged separately in the sqldb

#### Tests.py

Sends get and post requests to the webserver in main.py
Tests if get and post requests are successful and the tables exist and are being logged 

### How to Run
For the requirements you can use pip to install them with the requirements.txt file using the following command:
`pip install -r requirements.txt`

In the terminal type:
`python main.py`

This will start the Flask server on localhost:8080

You can run the test suite after by typing:
`python tests.py`
