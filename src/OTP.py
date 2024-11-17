import os

# OTP encryption function
def OTP_encryption(file, key):
    """
    Encrypts a file using the OTP (One-Time Pad) algorithm.
    
    Args:
    - file: The file content to encrypt (in bytes).
    - key: The OTP key used for encryption (in bytes).
    
    Returns:
    - ciphertext: The encrypted file content (in bytes).
    - key: The OTP key used for encryption (returned for future decryption).
    """
    # Perform XOR encryption between the file and the key
    ciphertext = bytes([c ^ k for c, k in zip(file, key)])

    # Return the encrypted file and the used key
    return ciphertext, key

# OTP decryption function
def OTP_decryption(ciphertext, key):
    """
    Decrypts a file encrypted using the OTP (One-Time Pad) algorithm.
    
    Args:
    - ciphertext: The encrypted file content (in bytes).
    - key: The OTP key used for decryption (in bytes).
    
    Returns:
    - plaintext: The decrypted file content (in bytes).
    """
    # Perform XOR decryption using the same key as encryption
    plaintext = bytes([c ^ k for c, k in zip(ciphertext, key)])
    
    # Return the decrypted file
    return plaintext
