# CS361 Key Generation Service

A microservice that generates Ed25519 key pairs, signs data, and verifies digital signatures via REST API.

## Team
- Kairon Johnson
- Thao Nguyen


## Usage / Testing Instructions
# Key Generation Service (CS361)

FastAPI microservice providing Ed25519 key generation, signing, and verification.

## Setup

1. Create and activate a Python virtual environment:

`
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
`

2. Install dependencies

`
pip install -r requirements.txt
`

## Running the Server

`
fastapi dev main.py
`

## Requesting and recieving data
After spinning up the server as described above, to be able to interact with the service, your program most be able to send REST API requests containing JSON. The service will then respond by sending a json object containing the specific data requested.
Here is an example of a service sending a request for a key pair, and printing out the keys from the returned json object.

### 1) Generate an Ed25519 Key Pair
```
import requests

url = "http://127.0.0.1:8000/generateKeyPair"
payload = {"algorithm": "Ed25519"}

response = requests.post(url, json=payload)
data = response.json

print("Public key:", data["public_key"])
print("Private key:", data["Private_key"])
```

### Expectecd Response
`
{
  "public_key": "Base64EncodedPublicKeyString",
  "private_key": "Base64EncodedPrivateKeyString"
}
`
### 2) Sign data using a private key
```
import requests

url = "http://127.0.0.1:8000/signData"
payload = {
    "private_key": "<Base64 private key>",
    "message": "Hello, this is a test message!"
}

response = requests.post(url, json=payload)
data = response.json()

print("Generated Signature:", data["signature"])
```

### Expected Response
`
{
  "signature": "Base64EncodedSignatureString"
}
`

### 3) Verify digital signature
```
import requests

url = "http://127.0.0.1:8000/verifySignature"
payload = {
    "public_key": "<Base64 public key>",
    "message": "Hello, this is a test message!",
    "signature": "<Base64 signature>"
}

response = requests.post(url, json=payload)
data = response.json()

print("Is the signature valid?", data["valid"])
```

### Expected Response
`
{
  "valid": true
}
`


## UML Diagram

<img width="462" height="538" alt="image" src="https://github.com/user-attachments/assets/e1e9566b-511d-42c7-b26f-9ae06359aeba" />
