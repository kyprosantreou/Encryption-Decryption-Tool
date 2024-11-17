import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# AES encryption function using ECB mode
def AES_encryption(file, key):
    """
    Encrypts a binary file using AES encryption in ECB mode.

    Args:
    - file: Path to the input file to encrypt.
    - key: The AES encryption key (should be 16, 24, or 32 bytes long).

    Returns:
    - ciphertext: The encrypted file content (in bytes).
    """
    # Open the file in binary read mode and read its content
    with open(file, "rb") as f:
        plaintext = f.read()

    # Create a new AES cipher object using the provided key and ECB mode
    cipher = AES.new(key, AES.MODE_ECB)

    # Encrypt the plaintext using the AES cipher, padding it to match the block size
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    # Return the encrypted data (ciphertext)
    return ciphertext  

# AES decryption function using ECB mode
def AES_decryption(file, key):
    """
    Decrypts a binary file using AES decryption in ECB mode.

    Args:
    - file: Path to the encrypted file to decrypt.
    - key: The AES decryption key (should be the same as the encryption key).

    Returns:
    - plaintext: The decrypted file content (in bytes).
    """
    # Open the encrypted file in binary read mode and read its content
    with open(file, "rb") as f:
        ciphertext = f.read()

    # Create a new AES cipher object using the provided key and ECB mode
    cipher = AES.new(key, AES.MODE_ECB)

    # Decrypt the ciphertext and remove the padding to restore the original data
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

    # Return the decrypted data
    return plaintext  
