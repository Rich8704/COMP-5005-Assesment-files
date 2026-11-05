
import json
import base64
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESCCM


key = Path("shared_key.bin").read_bytes()
aesccm = AESCCM(key, tag_length=16)


with open("encrypted_message.json", "r") as file:
    packet = json.load(file)

nonce = base64.b64decode(packet["nonce"])
ciphertext = base64.b64decode(packet["ciphertext"])
tag = base64.b64decode(packet["tag"])


for attempt in range(1, 3):
    print(f"\n--- Transmission {attempt} ---")

    try:
        plaintext = aesccm.decrypt(
            nonce,
            ciphertext + tag,
            None
        )

        print("Authentication: PASSED")
        print("Message accepted by Bob")
        print("Recovered message:", plaintext.decode())

    except Exception:
        print("Message rejected")
