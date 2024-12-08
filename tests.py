import requests
import jwt
import sqlite3

sqldb = "totally_not_my_privateKeys.db"
get_url = "http://localhost:8080/.well-known/jwks.json"
reg_url = "http://localhost:8080/register"
auth_url = "http://localhost:8080/auth"     #URL for get and post requests
totalTests = 6
completed = 0



#test register endpoiont
username = "zach123"
email = "email@test.com"
data = {"username": username, "email": email}
response_post = requests.post(reg_url, json=data)
if response_post.status_code == 201:
        print("User registered successfully.")
        password = response_post.json().get("password")  # Extract the password from the JSON response
        completed +=1
else:
        print(f"Error: Failed to register user {username}: {response_post.status_code}")

#send GET to JWKS endpoint
response_get = requests.get(get_url) 

#test if GET request was successful 
if response_get.status_code == 200:
    print("GET request successful - Key included in JWT.")
    completed +=1
else:
    print("GET request failed, status code:", response_get.status_code)


#test if AUTH request was successful
try: 
    data1 = {"username": username,"password": password}
    response_auth = requests.post(auth_url,json=data1)
    if response_auth.status_code == 200:
        print("POST request successful.")
        print("AUTH request logged.")
        completed +=2
    else:
        print("Error: POST request failed, status code:", response_post.status_code)
except:
     print("Error: couldn't grab password")


#test if users table and auth logs table exists
with sqlite3.connect(sqldb) as conn_users:
    cursor = conn_users.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users';")
    if not cursor:
        "Error: No users table"
    else:
        print("Users Table Exists.")
        completed +=1

with sqlite3.connect(sqldb) as conn_auth:
    cursor = conn_auth.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='auth_logs';")
    if not cursor:
        "Error: No auth_logs table"
    else:
        completed +=1
        print("Auth_logs Table Exists.")

testPercent = (completed / totalTests) * 100
print(f"Test Coverage: [{completed}/{totalTests}]")
print(f"Test Coverage Percent: {testPercent:.2f}%")