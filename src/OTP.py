import os

# OTP encryption function
def OTP_encryption(file, key):
    """
    Encrypts a file using the OTP (One-Time Pad) algorithm.
    
    Args:
    - file: The file content to encrypt (in bytes).
    - key: The OTP key used for encryption (in bytes).
    
    Returns:
    - encrypted_file: The encrypted file content (in bytes).
    - key: The OTP key used for encryption (returned for future decryption).
    """
    # Perform XOR encryption between the file and the key
    encrypted_file = bytes([c ^ k for c, k in zip(file, key)])

    # Return the encrypted file and the used key
    return encrypted_file, key

# OTP decryption function
def OTP_decryption(encrypted_file, key):
    """
    Decrypts a file encrypted using the OTP (One-Time Pad) algorithm.
    
    Args:
    - encrypted_file: The encrypted file content (in bytes).
    - key: The OTP key used for decryption (in bytes).
    
    Returns:
    - decrypted_file: The decrypted file content (in bytes).
    """
    # Perform XOR decryption using the same key as encryption
    decrypted_file = bytes([c ^ k for c, k in zip(encrypted_file, key)])
    
    # Return the decrypted file
    return decrypted_file
