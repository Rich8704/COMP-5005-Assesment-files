import json
import base64
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.exceptions import InvalidTag
psk = Path("shared_key.bin").read_bytes()
aesccm = AESCCM(psk, tag_length=16)
print("BOB - AES-256-CCM DECRYPTION")
print("--------------------------------")
with open("encrypted_message.json", "r") as file:
    packet = json.load(file)
nonce = base64.b64decode(packet["nonce"])
ciphertext = base64.b64decode(packet["ciphertext"])
tag = base64.b64decode(packet["tag"])
encrypted_data = ciphertext + tag
print("Encrypted packet received.")
print("Nonce              :", packet["nonce"])
print("Ciphertext         :", packet["ciphertext"])
print("Authentication tag :", packet["tag"])
try:
    
    plaintext = aesccm.decrypt(
        nonce,
        encrypted_data,
        None
    )

    print("\nDECRYPTION SUCCESSFUL")
    print("Authentication     : PASSED")
    print("Recovered message  :")
    print(plaintext.decode("utf-8"))

except InvalidTag:
    print("\nDECRYPTION FAILED")
    print("Authentication     : FAILED")
    print("Message rejected.")