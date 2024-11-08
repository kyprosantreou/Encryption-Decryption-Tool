import rsa

def RSA_encrypt_file(file_path, public_key):
    # Read the file data
    with open(file_path, "rb") as file:
        file_data = file.read()

    # Encrypt the data using the public key
    encrypted_data = rsa.encrypt(file_data, public_key)

    # Return the encrypted data so it can be written in the main function
    return encrypted_data

def RSA_decrypt_file(encrypted_file_path, private_key):
    # Read the encrypted file data
    with open(encrypted_file_path, "rb") as enc_file:
        encrypted_data = enc_file.read()

    # Decrypt the data using the private key
    decrypted_data = rsa.decrypt(encrypted_data, private_key)

    # Return the decrypted data so it can be written in the main function
    return decrypted_data
