import os
import json
import base64
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
psk = Path("shared_key.bin").read_bytes()
aesccm = AESCCM(psk, tag_length=16)
print("ALICE - AES-256-CCM ENCRYPTION")
print("--------------------------------")
plaintext = input("Enter confidential message: ")
nonce = os.urandom(12)
encrypted_data = aesccm.encrypt(
    nonce,
    plaintext.encode("utf-8"),
    None
)
ciphertext = encrypted_data[:-16]
tag = encrypted_data[-16:]
packet = {
    "nonce": base64.b64encode(nonce).decode("utf-8"),
    "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
    "tag": base64.b64encode(tag).decode("utf-8")
}
with open("encrypted_message.json", "w") as file:
    json.dump(packet, file, indent=4)

print("\nENCRYPTION SUCCESSFUL")
print("Algorithm          : AES-256-CCM")
print("Key size           : 256 bits")
print("Nonce              :", packet["nonce"])
print("Ciphertext         :", packet["ciphertext"])
print("Authentication tag :", packet["tag"])
print("Output file        : encrypted_message.json")