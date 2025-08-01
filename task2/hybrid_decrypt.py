from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import hashlib

# Step 1: Load private key
with open("private.pem", "rb") as f:
    privkey = RSA.import_key(f.read())

# Step 2: Load and decrypt AES key
with open("aes_key_encrypted.bin", "rb") as f:
    encrypted_key = f.read()

cipher_rsa = PKCS1_OAEP.new(privkey)
aes_key = cipher_rsa.decrypt(encrypted_key)

# Step 3: Load encrypted file
with open("encrypted_file.bin", "rb") as f:
    iv = f.read(16)
    ciphertext = f.read()

cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
padded_message = cipher_aes.decrypt(ciphertext)

# Remove padding
padding = padded_message[-1]
message = padded_message[:-padding]

# Save decrypted message
with open("decrypted_message.txt", "wb") as f:
    f.write(message)

# Integrity check
original_hash = hashlib.sha256(open("alice_message.txt", "rb").read()).hexdigest()
new_hash = hashlib.sha256(message).hexdigest()

print("Original hash:", original_hash)
print("Decrypted hash:", new_hash)
print("Integrity OK:", original_hash == new_hash)
