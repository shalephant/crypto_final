from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import hashlib

# Step 1: Read Bob's public key
with open("public.pem", "rb") as f:
    pubkey = RSA.import_key(f.read())

# Step 2: Generate AES key and IV
aes_key = get_random_bytes(32)
iv = get_random_bytes(16)
cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)

# Step 3: Read and pad message
message = open("alice_message.txt", "rb").read()
padding = 16 - (len(message) % 16)
message += bytes([padding]) * padding  # PKCS7 padding

ciphertext = cipher_aes.encrypt(message)

# Step 4: Encrypt AES key with RSA
cipher_rsa = PKCS1_OAEP.new(pubkey)
encrypted_key = cipher_rsa.encrypt(aes_key)

# Save files
with open("encrypted_file.bin", "wb") as f:
    f.write(iv + ciphertext)

with open("aes_key_encrypted.bin", "wb") as f:
    f.write(encrypted_key)

print("File encrypted and key encrypted with RSA.")
