import json
import base64
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.exceptions import InvalidTag
key = Path("shared_key.bin").read_bytes()
aesccm = AESCCM(key, tag_length=16)
state_file = Path("received_sequences.json")
if state_file.exists():
    received = json.loads(state_file.read_text())
else:
    received = []
packet = json.loads(
    Path("encrypted_after.json").read_text()
)
sequence_number = packet["sequence_number"]
nonce = base64.b64decode(packet["nonce"])
ciphertext = base64.b64decode(packet["ciphertext"])
tag = base64.b64decode(packet["tag"])
aad = sequence_number.to_bytes(8, "big")
print("\nBOB: RECEIVING MESSAGE")
print("Sequence number:", sequence_number)
try:
    plaintext = aesccm.decrypt(
        nonce,
        ciphertext + tag,
        aad
    )
    if sequence_number in received:
        print("REPLAY ATTACK DETECTED")
        print("Message rejected: duplicate sequence number.")
    else:
        received.append(sequence_number)

        state_file.write_text(
            json.dumps(received, indent=4)
        )
        print("Authentication: PASSED")
        print("Message accepted.")
        print("Recovered message:")
        print(plaintext.decode("utf-8"))
except InvalidTag:
    print("AUTHENTICATION FAILED")
    print("Message rejected.")
