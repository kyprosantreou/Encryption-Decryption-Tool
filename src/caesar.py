import os

# Caesar cipher encryption function for binary files
def caesar_cipher_binary(file, shift):
    """
    Encrypts a binary file using the Caesar cipher algorithm.

    Args:
    - file: Path to the input binary file.
    - shift: The number of positions to shift each byte for encryption.

    Returns:
    - ciphertext: The encrypted file content (in bytes).
    """
    # Open the file in binary read mode and read its content
    with open(file, "rb") as f:
        plaintext = f.read()

    # Apply the Caesar cipher shift to each byte in the file plaintext
    # (byte + shift) % 256 ensures the result stays within byte size range (0-255)
    ciphertext = bytes((byte + shift) % 256 for byte in plaintext)

    # Return the encrypted plaintext
    return ciphertext

# Caesar cipher decryption function for binary files
def caesar_cipher_decrypt_binary(file, shift):
    """
    Decrypts a binary file encrypted with the Caesar cipher.

    Args:
    - file: Path to the encrypted binary file.
    - shift: The number of positions to shift each byte for decryption.

    Returns:
    - plaintext: The decrypted file content (in bytes).
    """
    # Open the encrypted file in binary read mode and read its content
    with open(file, "rb") as f:
        ciphertext = f.read()

    # Apply the reverse Caesar cipher shift to each byte in the encrypted plaintext
    # (byte - shift) % 256 ensures the result stays within byte size range (0-255)
    plaintext = bytes((byte - shift) % 256 for byte in ciphertext)

    # Return the decrypted plaintext
    return plaintext
