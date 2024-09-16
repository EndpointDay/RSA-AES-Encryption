# Encryption Tool

A simple yet powerful encryption tool that demonstrates **symmetric (AES)** and **asymmetric (RSA)** encryption techniques in Java. This tool allows you to encrypt and decrypt data using both AES and RSA, and supports key generation, saving, and loading from files. Additionally, it features hybrid encryption by securing an AES key with RSA.

## Features
- **AES (Symmetric Encryption)**:
  - Generate a new AES key or load an existing one from a file.
  - Encrypt and decrypt text using AES.
  - Export the AES key to a file.
  
- **RSA (Asymmetric Encryption)**:
  - Generate a new RSA key pair or load keys from files (both public and private keys).
  - Encrypt and decrypt text using RSA.
  - Export RSA keys (public and private) to files.

- **Hybrid Encryption**:
  - Securely encrypt the AES key with RSA.
  - Recover the AES key by decrypting it with the RSA private key.

## How It Works

### AES Encryption/Decryption
- AES (Advanced Encryption Standard) is a symmetric encryption algorithm that uses the same key for encryption and decryption.
- You can either generate a new AES key or load one from a file.

### RSA Encryption/Decryption
- RSA (Rivest–Shamir–Adleman) is an asymmetric encryption algorithm where the public key is used to encrypt data, and the private key is used to decrypt it.
- You can generate new RSA keys or load existing keys from files.

### Hybrid Encryption
- AES keys are encrypted using RSA's public key. This demonstrates a hybrid encryption model where the RSA algorithm secures the AES key, enabling the secure exchange of symmetric keys over insecure channels.

## How to Use

### Prerequisites
- Java 8 or later installed on your system.
- A Java development environment for compiling and running the code.

### Compile the Code
```bash
javac Main.java
```

### Run the Program
```bash
java Main
```

### Program Flow
1. **AES Key Setup**: Choose whether to generate a new AES key or load an existing key from a file.
2. **AES Encryption**: Input some text to encrypt using AES, view the encrypted and decrypted results.
3. **RSA Key Setup**: Choose whether to generate a new RSA key pair or load existing keys from files.
4. **RSA Encryption**: Input text to encrypt using RSA, view the encrypted and decrypted results.
5. **Hybrid Encryption**: Encrypt the AES key using RSA and then decrypt it back to retrieve the original AES key.

### Exporting and Importing Keys
- The tool gives you the option to export and save the AES and RSA keys to files for future use.
- You can later import these keys back into the tool for encryption/decryption tasks.

## Example Usage
1. **Generate a new AES key** and **export it to a file**:
   - Choose option `1` to generate the AES key.
   - When prompted, enter a filename to save the key.

2. **Encrypt some text using AES**:
   - Provide the plaintext to be encrypted.
   - The tool will display the encrypted and decrypted data.

3. **Generate RSA key pair** or **load from files**:
   - Choose option `1` to generate new keys or option `2` to load existing keys from files.

4. **Encrypt AES key using RSA**:
   - The tool will encrypt the AES key with the RSA public key and show the encrypted key.
   - It will then decrypt it back using the RSA private key and show the recovered AES key.

## Key Methods
- **AES**:
  - `encryptAES(String data, SecretKey secretKey)`: Encrypts data using the AES key.
  - `decryptAES(String encryptedData, SecretKey secretKey)`: Decrypts AES-encrypted data.
  - `exportAESKey(SecretKey secretKey, String fileName)`: Exports the AES key to a file.
  - `importAESKey(String fileName)`: Loads an AES key from a file.

- **RSA**:
  - `encryptRSA(String data, PublicKey publicKey)`: Encrypts data using RSA public key.
  - `decryptRSA(String encryptedData, PrivateKey privateKey)`: Decrypts RSA-encrypted data.
  - `exportRSAKey(Key key, String fileName)`: Exports RSA keys (public/private) to files.
  - `importRSAPublicKey(String fileName)`: Loads an RSA public key from a file.
  - `importRSAPrivateKey(String fileName)`: Loads an RSA private key from a file.
