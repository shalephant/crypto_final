# Encryption Flow

1. **User A** generates an RSA key pair (private + public).
2. **User B**:
   - Reads the public key.
   - Generates a random 256-bit AES key.
   - Encrypts the message using AES-256 in EAX mode (provides authenticity).
   - Encrypts the AES key using RSA-OAEP with User A's public key.
   - Saves encrypted message and encrypted AES key.
3. **User A**:
   - Uses their private key to decrypt the AES key.
   - Uses the decrypted AES key to decrypt and verify the message.

This is hybrid encryption: fast AES for bulk data, RSA for secure key exchange.
