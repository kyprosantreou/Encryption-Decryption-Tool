import os
import rsa
import argparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from OTP import OTP_encryption, OTP_decryption
from AES import AES_encryption, AES_decryption
from RSA_encryption import RSA_encrypt_file, RSA_decrypt_file
from caesar import caesar_cipher_binary, caesar_cipher_decrypt_binary

# Function to generate encryption keys based on the algorithm
def generate_keys(algorithm, key_file=None, content=None):
    # AES key generation or loading
    if algorithm == "aes":
        if key_file:
            # If a key file is provided, read the key from the file
            with open(key_file, "rb") as keyfile:
                return keyfile.read()
        else:
            # Otherwise, generate a random 16-byte AES key and save it to a file
            key = get_random_bytes(16)
            with open("aes_key.key", "wb") as keyfile:
                keyfile.write(key)
            return key

    # RSA key generation or loading
    elif algorithm == "rsa":
        if key_file:
            # Check whether the key is public or private based on its content
            with open(key_file, "rb") as f:
                key_data = f.read()
                try:
                    public_key = rsa.PublicKey.load_pkcs1(key_data)  # Try loading as public key
                    return public_key, None
                except ValueError:
                    private_key = rsa.PrivateKey.load_pkcs1(key_data)  # Try loading as private key
                    return None, private_key
        else:
            # Generate a new RSA key pair (1024-bit keys) if no key is provided
            public_key, private_key = rsa.newkeys(1024)

            # Save the public and private keys to files
            with open("public.pem", "wb") as f:
                f.write(public_key.save_pkcs1("PEM"))

            with open("private.pem", "wb") as f:
                f.write(private_key.save_pkcs1("PEM"))

            return public_key, private_key


    # OTP key generation
    elif algorithm == "otp":
        key = os.urandom(len(content))  # Generate a random key of the same length as the content
        otp_key_filename = "otp_key.key"

        # Save the OTP key to a file
        with open(otp_key_filename, "wb") as key_file:
            key_file.write(key)
        return key  # Return the generated key
    else:
        return None

# Main function to handle encryption and decryption processes
def main():
    # Argument parser setup
    parser = argparse.ArgumentParser(description="Encryption and Decryption Tool")
    parser.add_argument("--encrypt", action="store_true", help="Choose encryption mode")
    parser.add_argument("--decrypt", action="store_true", help="Choose decryption mode")
    parser.add_argument("--algorithm", choices=["caesar", "aes", "otp", "rsa"], required=True, help="Encryption algorithm to use")
    parser.add_argument("--key", type=str, help="Path to key file (for algorithms that require a key)")
    parser.add_argument("--input", type=str, required=True, help="Input file path")
    parser.add_argument("--output", type=str, required=True, help="Output file path")
    
    args = parser.parse_args()  # Parse the command-line arguments

    # Encryption process
    if args.encrypt:
        # Caesar cipher encryption
        if args.algorithm == "caesar":
            try:
                ciphertext = caesar_cipher_binary(args.input, 10)  # Encrypt with Caesar cipher (shift 10)
                with open(args.output, "wb") as f:
                    f.write(ciphertext)
                
                print(f"Encryption complete. Encrypted file saved to {args.output}")

            except Exception as e:
                print(f"Error: {e}")

        # AES encryption
        elif args.algorithm == "aes":
            try:
                key = generate_keys("aes", args.key)  # Generate or load the AES key
                ciphertext = AES_encryption(args.input, key)  # Encrypt using AES encryption

                with open(args.output, "wb") as f:
                    f.write(ciphertext)
                
                print(f"Encryption complete. Encrypted file saved to {args.output}")

            except Exception as e:
                print(f"Error: {e}")

        # OTP encryption
        elif args.algorithm == "otp":
            try:
                with open(args.input, "rb") as file:
                    plaintext = file.read()  # Read the content of the file

                key = generate_keys("otp", content=plaintext)  # Generate OTP key
                encrypted_data, otp_key = OTP_encryption(plaintext, key)  # Encrypt using OTP

                with open(args.output, "wb") as ciphertext:
                    ciphertext.write(encrypted_data)
                
                print(f"Encryption complete. Encrypted file saved to {args.output}")

            except Exception as e:
                print(f"Error: {e}")

        # RSA encryption
        elif args.algorithm == "rsa":
            try:
                public_key, private_key = generate_keys("rsa", args.key)  # Load the public RSA key
                ciphertext = RSA_encrypt_file(args.input, public_key)  # Encrypt using RSA encryption

                with open(args.output, "wb") as f:
                    f.write(ciphertext)

                print(f"Encryption complete. Encrypted file saved to {args.output}")

            except Exception as e:
                print(f"Error: {e}")

    # Decryption process
    elif args.decrypt:
        # Caesar cipher decryption
        if args.algorithm == "caesar":
            try:
                decrypted_file = caesar_cipher_decrypt_binary(args.input, 10)  # Decrypt with Caesar cipher (shift 10)

                with open(args.output, "wb") as f:
                    f.write(decrypted_file)
            
                print(f"Decryption complete. Decrypted file saved to {args.output}")

            except Exception as e:
                print(f"Error: {e}")

        # AES decryption
        elif args.algorithm == "aes":
            try:
                key = generate_keys("aes", args.key)  # Load the AES key

                decrypted_file = AES_decryption(args.input, key)  # Decrypt using AES decryption

                with open(args.output, "wb") as f:
                    f.write(decrypted_file)
                
                print(f"Decryption complete. Decrypted file saved to {args.output}")

            except Exception as e:
                print(f"Error: {e}")

        # OTP decryption
        elif args.algorithm == "otp":
            try:
                with open(args.input, "rb") as ciphertext:
                    encrypted_data = ciphertext.read()  # Read the encrypted file

                with open(args.key, "rb") as key_file:
                    otp_key = key_file.read()  # Read the OTP key from the file

                decrypted_data = OTP_decryption(encrypted_data, otp_key)  # Decrypt using OTP

                with open(args.output, "wb") as decrypted_file:
                    decrypted_file.write(decrypted_data)

                print(f"Decryption complete. Decrypted file saved to {args.output}")

            except Exception as e:
                print(f"Error: {e}")

        # RSA decryption
        elif args.algorithm == "rsa":
            try:
                public_key, private_key = generate_keys("rsa", args.key)  # Load the private RSA key
                decrypted_file = RSA_decrypt_file(args.input, private_key)  # Decrypt using RSA decryption

                with open(args.output, "wb") as f:
                    f.write(decrypted_file)
                
                print(f"Decryption complete. Decrypted file saved to {args.output}")

            except Exception as e:
                print(f"Error: {e}")

    else:
        print("Invalid option. Please specify either --encrypt or --decrypt.")  # If neither encrypt nor decrypt is specified

# Entry point for the script
if __name__ == "__main__":
    main()
