import requests
import json
import time

BASE_URL = "http://127.0.0.1:8000"

# -----------------------------
# 1. Test: Generate Key Pair
# -----------------------------
def test_generate_keypair():
    print("=== Testing /generateKeyPair ===")

    payload = {"algorithm": "Ed25519"}

    response = requests.post(
        f"{BASE_URL}/generateKeyPair",
        json=payload
    )

    print("Status Code:", response.status_code)

    try:
        data = response.json()
        print("Response JSON:", json.dumps(data, indent=2))
    except Exception as e:
        print("Failed to parse JSON:", e)

    return data


# -----------------------------
# 2. Test: Sign Data
# -----------------------------
def test_sign_data(private_key, message):
    print("\n=== Testing /signData ===")

    payload = {
        "private_key": private_key,
        "message": message
    }

    response = requests.post(
        f"{BASE_URL}/signData",
        json=payload
    )

    print("Status Code:", response.status_code)

    try:
        data = response.json()
        print("Response JSON:", json.dumps(data, indent=2))
    except:
        print("Response could not be parsed as JSON.")
        return None

    return data


# -----------------------------
# 3. Test: Verify Signature
# -----------------------------
def test_verify_signature(public_key, message, signature):
    print("\n=== Testing /verifySignature ===")

    payload = {
        "public_key": public_key,
        "message": message,
        "signature": signature
    }

    response = requests.post(
        f"{BASE_URL}/verifySignature",
        json=payload
    )

    print("Status Code:", response.status_code)

    try:
        data = response.json()
        print("Response JSON:", json.dumps(data, indent=2))
    except:
        print("Response could not be parsed as JSON.")
        data = None

    return data


def test_verify_incorrect_signature(public_key, message):
    print("\n=== Testing /verifySignature with INCORRECT signature ===")

    other_keys = test_generate_keypair()
    wrong_private = other_keys["private_key"]

    wrong_signature_result = test_sign_data(wrong_private, message)
    wrong_signature = wrong_signature_result["signature"]

    payload = {
        "public_key": public_key,
        "message": message,
        "signature": wrong_signature
    }

    response = requests.post(
        f"{BASE_URL}/verifySignature",
        json=payload
    )

    print("Status Code:", response.status_code)

    try:
        data = response.json()
        print("Response JSON:", json.dumps(data, indent=2))
    except:
        print("Could not parse JSON.")
        return {}

    return data




# -----------------------------
# Orchestrate Full Workflow
# -----------------------------
if __name__ == "__main__":
    print("\n========== RUNNING FULL MICROSERVICE TEST ==========\n")

    # Step 1: Generate keys
    keys = test_generate_keypair()
    public_key = keys["public_key"]
    private_key = keys["private_key"]

    time.sleep(1)

    # Step 2: Sign a message
    message = "Hello from the test program!"
    sign_result = test_sign_data(private_key, message)
    signature = sign_result["signature"]
    
    time.sleep(1)

    # Step 3: Verify the signature
    verify_result = test_verify_signature(public_key, message, signature)

    time.sleep(1)

    print("\n========== SUMMARY ==========")
    print("Message:", message)
    print("Signature valid?:", verify_result.get("valid"))

    print("\nDone.\n")
