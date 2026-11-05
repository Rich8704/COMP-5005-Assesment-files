import os
import json
import base64
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
key = Path("shared_key.bin").read_bytes()
aesccm = AESCCM(key, tag_length=16)
plaintext = input("Alice - Enter secret message: ")
sequence_number = 1
aad = sequence_number.to_bytes(8, "big")
nonce = os.urandom(12)
encrypted = aesccm.encrypt(
    nonce,
    plaintext.encode("utf-8"),
    aad
)
ciphertext = encrypted[:-16]
tag = encrypted[-16:]
packet = {
    "sequence_number": sequence_number,
    "nonce": base64.b64encode(nonce).decode(),
    "ciphertext": base64.b64encode(ciphertext).decode(),
    "tag": base64.b64encode(tag).decode()
}
with open("encrypted_after.json", "w") as file:
    json.dump(packet, file, indent=4)
print("\nALICE: ENCRYPTION SUCCESSFUL")
print("Sequence number:", sequence_number)
print("AAD:", aad.hex())
print("Ciphertext:", packet["ciphertext"])
print("Authentication tag:", packet["tag"])
