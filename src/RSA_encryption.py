import os
import rsa

def RSA_encrypt_file(file, public_key):
    # Read the f data
    with open(file, "rb") as f:
        plaintext = f.read()

    # Encrypt the data using the public key
    ciphertext = rsa.encrypt(plaintext, public_key)

    # Return the encrypted data so it can be written in the main function
    return ciphertext

def RSA_decrypt_file(file, private_key):
    # Read the encrypted f data
    with open(file, "rb") as f:
        ciphertext = f.read()

    # Decrypt the data using the private key
    plaintext = rsa.decrypt(ciphertext, private_key)

    # Return the decrypted data so it can be written in the main function
    return plaintext
