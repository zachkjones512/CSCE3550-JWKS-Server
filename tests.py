import requests
import jwt

get_url = "http://localhost:8080/.well-known/jwks.json"
post_url = "http://localhost:8080/auth"     #URL for get and post requests
totalTests = 7
completed = 0

#send GET to JWKS endpoint
response_get = requests.get(get_url) 

#test if GET request was successful 
if response_get.status_code == 200:
    print("GET request successful.")
    completed +=1
else:
    print("GET request failed, status code:", response_get.status_code)

##NON-EXPIRED KEY POST
response_post = requests.post(post_url)

#test if POST request was successful
if response_post.status_code == 200:
    print("POST request successful.")
    completed +=1
else:
    print("POST request failed, status code:", response_post.status_code)

#Extract KID from token
try:
    header = jwt.get_unverified_header(response_post.json().get('token'))
    key_id = header['kid']
    print("Received UNEXPIRED kid from JWT:", key_id)
    completed +=1
except:
    print("Failed to decode key_id")

#look for KID in list from JWKS endpoint
found_key = None
for key in response_get.json()['keys']:
    if key['kid'] == key_id:
        found_key = key
        break

#if expired kid in JWKS endpoint then return error
if found_key:
    print("Valid key found in JWKS")
    completed +=1
else:
    print("Valid Key not found in JWKS, ERROR")

##EXPIRED KEY
#send POST to auth endpoint for expired key
response_post = requests.post(post_url, params={'expired': 'true'})

#test if POST request was successful
if response_post.status_code == 200:
    print("POST request successful.")
    completed +=1
else:
    print("POST request failed, status code:", response_post.status_code)

#Extract KID from token
try:
    header = jwt.get_unverified_header(response_post.json().get('token'))
    key_id = header['kid']
    print("Received EXPIRED kid from JWT:", key_id)
    completed +=1
except:
    print("Failed to decode key_id")

#look for KID in list from JWKS endpoint
found_key = None
for key in response_get.json()['keys']:
    if key['kid'] == key_id:
        found_key = key
        break

#if expired kid in JWKS endpoint then return error
if found_key:
    print("Expired key found in JWKS, ERROR")
else:
    print("Expired Key not found in JWKS")
    completed +=1

testPercent = (totalTests / completed) * 100
print(f"Test Coverage Percent: {testPercent:.2f}%")