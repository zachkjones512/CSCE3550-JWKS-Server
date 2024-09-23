import requests
import jwt

get_url = "http://localhost:8080/.well-known/jwks.json"
post_url = "http://localhost:8080/auth"     #URL for get and post requests

#send GET to JWKS endpoint
response_get = requests.get(get_url) 

#test if POST request was successful 
if response_get.status_code == 200:
    print("GET request successful.")
else:
    print("GET request failed, status code:", response_get.status_code)

#send POST to auth endpoint
response_post = requests.post(post_url, params={'expired': 'true'})

#test if POST request was successful
if response_post.status_code == 200:
    print("POST request successful.")
else:
    print("POST request failed, status code:", response_post.status_code)

#Extract KID from token
try:
    header = jwt.get_unverified_header(response_post.json().get('token'))
    key_id = header['kid']
    print("Received EXPIRED kid from JWT:", key_id)
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