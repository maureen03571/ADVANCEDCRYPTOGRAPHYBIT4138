# week1_test_encrypt.py
# Simple AES encryption test to confirm cryptography library is functional

from cryptography.fernet import Fernet

def main():
    # Generate a key
    key = Fernet.generate_key()
    cipher = Fernet(key)
    
    # Original message
    plaintext = b"Hello, this is a test encryption message."
    print(f"Original: {plaintext}")
    
    # Encrypt
    ciphertext = cipher.encrypt(plaintext)
    print(f"Encrypted: {ciphertext}")
    
    # Decrypt to verify
    decrypted = cipher.decrypt(ciphertext)
    print(f"Decrypted: {decrypted}")
    
    print("\nEncryption successful: ciphertext generated.")

if __name__ == "__main__":
    main()