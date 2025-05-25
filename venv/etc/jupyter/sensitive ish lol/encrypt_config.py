import json
from cryptography.fernet import Fernet

# Load the existing config
with open("config.json", "r") as f:
    config = json.load(f)

# Load the key
with open("secret.key", "rb") as key_file:
    key = key_file.read()

fernet = Fernet(key)

# Encrypt the config
encrypted = fernet.encrypt(json.dumps(config).encode())

# Overwrite the config.json with encrypted content
with open("config.json", "wb") as wf:
    wf.write(encrypted)

print("Config encrypted successfully.")
