import json
import base64
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.exceptions import InvalidTag


psk = Path("shared_key.bin").read_bytes()


aesccm = AESCCM(psk, tag_length=16)


with open("encrypted_message.json", "r") as file:
    packet = json.load(file)


nonce = base64.b64decode(packet["nonce"])
ciphertext = bytearray(base64.b64decode(packet["ciphertext"]))
tag = base64.b64decode(packet["tag"])

print("AES-256-CCM INTEGRITY TEST")
print("---------------------------")


ciphertext[0] ^= 1

print("Original encrypted message captured.")
print("Attacker modified the ciphertext.")

try:
    
    aesccm.decrypt(
        nonce,
        bytes(ciphertext) + tag,
        None
    )

    print("WARNING: Modified message accepted.")

except InvalidTag:
    print("\nAUTHENTICATION FAILED")
    print("Modified message rejected.")
    print("Integrity protection is working.")