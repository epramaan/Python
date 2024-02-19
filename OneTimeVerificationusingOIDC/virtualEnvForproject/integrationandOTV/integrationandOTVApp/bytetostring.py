from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os

def encrypt(plaintext, key, nonce):
    # Generate a ChaCha20-Poly1305 cipher object
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())

    # Encrypt the plaintext
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Generate a Poly1305 tag
    tag = encryptor.tag

    # Combine ciphertext and tag
    encrypted_data_with_tag = ciphertext + tag

    # URL-safe base64 encoding
    encoded_ciphertext = urlsafe_b64encode(encrypted_data_with_tag).decode('utf-8')

    return encoded_ciphertext

def decrypt(encoded_ciphertext, key, nonce):
    # URL-safe base64 decoding
    encrypted_data_with_tag = urlsafe_b64decode(encoded_ciphertext)

    # Extract ciphertext and tag
    ciphertext = encrypted_data_with_tag[:-16]
    tag = encrypted_data_with_tag[-16:]

    # Generate a ChaCha20-Poly1305 cipher object
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())

    # Decrypt the ciphertext
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    return decrypted_data

# Example usage:
key = os.urandom(32)
nonce = os.urandom(16)
plaintext = b'Hello, ChaCha-Poly!'

# Encrypt
encrypted_text = encrypt(plaintext, key, nonce)
print("Encrypted:", encrypted_text)

# Decrypt
decrypted_text = decrypt(encrypted_text, key, nonce)
print("Decrypted:", decrypted_text.decode('utf-8'))