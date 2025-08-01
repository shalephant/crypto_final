# Hybrid Encryption: RSA + AES

## Flow
1. Bob generates an RSA key pair.
2. Alice:
   - Creates `alice_message.txt`.
   - Generates a random AES-256 key and IV.
   - Encrypts the file using AES-CBC.
   - Encrypts the AES key using Bob's RSA public key.
3. Bob:
   - Decrypts the AES key with his private key.
   - Uses the key and IV to decrypt the file.
4. SHA-256 hash of original and decrypted file are compared for integrity.

## AES vs RSA

| Feature         | AES                              | RSA                                  |
|----------------|----------------------------------|--------------------------------------|
| Type           | Symmetric                        | Asymmetric                           |
| Speed          | Very fast (bulk encryption)      | Slower (key operations only)         |
| Use Case       | Encrypting large data            | Key exchange, digital signatures     |
| Key Size       | 128, 192, 256 bits                | 2048+ bits (slow with larger)        |
| Security       | Resistant to quantum (for now)   | Broken by quantum computers (Shor's) |
| Best Practice  | Use in hybrid systems            | Never encrypt large data directly    |

Hybrid encryption combines the speed of AES with the secure key exchange of RSA.
