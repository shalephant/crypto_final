from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64

# Read public key
with open("rsa_key_public.pem", "rb") as f:
    public_key = RSA.import_key(f.read())

# Generate AES key
aes_key = get_random_bytes(32)  # 256-bit key
cipher_aes = AES.new(aes_key, AES.MODE_EAX)
message = open("message.txt", "r").read().encode()

# Encrypt message
ciphertext, tag = cipher_aes.encrypt_and_digest(message)

# Encrypt AES key with RSA
cipher_rsa = PKCS1_OAEP.new(public_key)
encrypted_aes_key = cipher_rsa.encrypt(aes_key)

# Save encrypted data
with open("encrypted_message.bin", "wb") as f:
    for x in (cipher_aes.nonce, tag, ciphertext):
        f.write(x)

with open("aes_key_encrypted.bin", "wb") as f:
    f.write(encrypted_aes_key)

print("Encryption complete.")
