import secrets
from pathlib import Path


psk = secrets.token_bytes(32)


key_file = Path("shared_key.bin")
key_file.write_bytes(psk)


try:
    key_file.chmod(0o600)
except OSError:
    pass

print("PRE-SHARED KEY GENERATION")
print("-------------------------")
print("Algorithm       : AES-256")
print("Key size        : 256 bits")
print("Key length      : 32 bytes")
print("Generation      : Cryptographically secure")
print("Key saved as    : shared_key.bin")
print("Status          : SUCCESS")