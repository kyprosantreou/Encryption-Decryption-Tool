# 🔒 File Encryption and Decryption Tool 🔓

This tool provides multiple methods for encrypting and decrypting files, including **AES**, **RSA**, **OTP (One-Time Pad)**, and **Caesar Cipher**. It supports both encryption and decryption modes, making it a versatile tool for secure file handling.

## ✨ Features Features

- **AES (Advanced Encryption Standard)**: Symmetric encryption for securely encrypting files using a randomly generated key.
- **RSA (Rivest-Shamir-Adleman)**: Asymmetric encryption suitable for securely sharing encrypted files with a public/private key pair.
- **OTP (One-Time Pad)**: Symmetric encryption method for high-security use, where the key must be as long as the data.
- **Caesar Cipher**: A simple encryption technique for learning purposes, using a shift of 10.

## 📋 Requirements

This tool requires Python 3 and several libraries. Install the required libraries by running the following command:

```bash
pip install -r requirements.txt
```

## 📥 Installation
```bash
https://github.com/kyprosantreou/Encryption-Decryption-Tool.git
```

```bash
cd Encryption-Decryption-Tool
```

## ⚡ Usage

The encryption tool provides various options for encrypting and decrypting files using the command line. You can specify the mode (`--encrypt` or `--decrypt`), the algorithm to use (`--algorithm`), and the paths for the input, output, and key files as needed.

### 🛠️ Command-Line Options

- `--encrypt` or `--decrypt`: Specifies the mode of operation (encryption or decryption).
- `--algorithm`: Specifies the encryption algorithm to use. Options include:
  - `aes` (Advanced Encryption Standard)
  - `rsa` (Rivest-Shamir-Adleman)
  - `otp` (One-Time Pad)
  - `caesar` (Caesar Cipher)
- `--key`: Path to the key file (required for AES, RSA, and OTP).
- `--input`: Path to the input file (required).
- `--output`: Path to the output file (required).

# 🚀 Example Commands for Encryption and Decryption for each algorithm

### 🔒 Encrypt a File

Make sure to replace `path/to/inputfile`, `path/to/outputfile`, and key paths with actual paths.

#### AES Encryption
```bash
python main.py --encrypt --algorithm aes --input path/to/inputfile --output path/to/outputfile --key path/to/aes_key.key
```

#### RSA Encryption
```bash
python encryption_tool.py --encrypt --algorithm rsa --input path/to/inputfile --output path/to/outputfile --key path/to/public.pem
```

#### OTP Encryption
```bash
python encryption_tool.py --encrypt --algorithm otp --input path/to/inputfile --output path/to/outputfile --key path/to/otp_key.key
```

#### Caesar Cipher Encryption (with a shift of 10 by default)
```bash
python encryption_tool.py --encrypt --algorithm caesar --input path/to/inputfile --output path/to/outputfile
```

### 🔓 Decrypt a File

#### AES Decryption
```bash
python encryption_tool.py --decrypt --algorithm aes --input path/to/encryptedfile --output path/to/decryptedfile --key path/to/aes_key.key
```

#### RSA Decryption
```bash
python encryption_tool.py --decrypt --algorithm rsa --input path/to/encryptedfile --output path/to/decryptedfile --key path/to/private.pem
```

#### OTP Decryption
```bash
python encryption_tool.py --decrypt --algorithm otp --input path/to/encryptedfile --output path/to/decryptedfile --key path/to/otp_key.key
```

#### Caesar Cipher Decryption (shift of 10 by default)
```bash
python encryption_tool.py --decrypt --algorithm caesar --input path/to/encryptedfile --output path/to/decryptedfile
```

# 👨‍💻 Author
Created by Kypros Andreou
