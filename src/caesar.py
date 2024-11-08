import os

# Caesar cipher encryption function for binary files
def caesar_cipher_binary(file_path, shift):
    """
    Encrypts a binary file using the Caesar cipher algorithm.

    Args:
    - file_path: Path to the input binary file.
    - shift: The number of positions to shift each byte for encryption.

    Returns:
    - encrypted_data: The encrypted file content (in bytes).
    """
    # Open the file in binary read mode and read its content
    with open(file_path, 'rb') as file:
        data = file.read()

    # Apply the Caesar cipher shift to each byte in the file data
    # (byte + shift) % 256 ensures the result stays within byte size range (0-255)
    encrypted_data = bytes((byte + shift) % 256 for byte in data)

    # Return the encrypted data
    return encrypted_data

# Caesar cipher decryption function for binary files
def caesar_cipher_decrypt_binary(file_path, shift):
    """
    Decrypts a binary file encrypted with the Caesar cipher.

    Args:
    - file_path: Path to the encrypted binary file.
    - shift: The number of positions to shift each byte for decryption.

    Returns:
    - decrypted_data: The decrypted file content (in bytes).
    """
    # Open the encrypted file in binary read mode and read its content
    with open(file_path, 'rb') as file:
        encrypted_data = file.read()

    # Apply the reverse Caesar cipher shift to each byte in the encrypted data
    # (byte - shift) % 256 ensures the result stays within byte size range (0-255)
    decrypted_data = bytes((byte - shift) % 256 for byte in encrypted_data)

    # Return the decrypted data
    return decrypted_data
