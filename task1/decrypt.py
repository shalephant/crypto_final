from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

# Load private key
with open("rsa_key_private.pem", "rb") as f:
    private_key = RSA.import_key(f.read())

# Load encrypted AES key
with open("aes_key_encrypted.bin", "rb") as f:
    encrypted_aes_key = f.read()

# Decrypt AES key
cipher_rsa = PKCS1_OAEP.new(private_key)
aes_key = cipher_rsa.decrypt(encrypted_aes_key)

# Load encrypted message
with open("encrypted_message.bin", "rb") as f:
    nonce = f.read(16)
    tag = f.read(16)
    ciphertext = f.read()

# Decrypt message
cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce)
message = cipher_aes.decrypt_and_verify(ciphertext, tag)

# Save result
with open("decrypted_message.txt", "w") as f:
    f.write(message.decode())

print("Decryption successful:", message.decode())
