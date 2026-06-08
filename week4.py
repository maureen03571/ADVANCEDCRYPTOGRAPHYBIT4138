# week4_aes.py
# AES-256-CBC file encryption/decryption with PBKDF2 key derivation

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import time
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

def derive_key(password: str, salt: bytes, iterations=100000):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,          # 256-bit key
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(input_file, output_file, password):
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = derive_key(password, salt)
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    with open(input_file, 'rb') as f:
        plaintext = f.read()
    
    # PKCS7 padding
    pad_len = 16 - (len(plaintext) % 16)
    plaintext += bytes([pad_len]) * pad_len
    
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    with open(output_file, 'wb') as f:
        f.write(salt + iv + ciphertext)
    print(f"Encrypted {input_file} -> {output_file}")

def decrypt_file(input_file, output_file, password):
    with open(input_file, 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        ciphertext = f.read()
    
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove PKCS7 padding
    pad_len = plaintext_padded[-1]
    if pad_len > 16:
        raise ValueError("Invalid padding")
    plaintext = plaintext_padded[:-pad_len]
    
    with open(output_file, 'wb') as f:
        f.write(plaintext)
    print(f"Decrypted {input_file} -> {output_file}")

def benchmark(modes_list, data_size=10*1024*1024):  # 10 MB
    data = os.urandom(data_size)
    key = os.urandom(32)
    results = {}
    for mode_name, mode_class in modes_list:
        if mode_class == modes.ECB:
            cipher = Cipher(algorithms.AES(key), mode_class(), backend=default_backend())
        else:
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), mode_class(iv), backend=default_backend())
        
        encryptor = cipher.encryptor()
        start = time.time()
        ct = encryptor.update(data) + encryptor.finalize()
        enc_time = time.time() - start
        
        decryptor = cipher.decryptor()
        start = time.time()
        pt = decryptor.update(ct) + decryptor.finalize()
        dec_time = time.time() - start
        
        results[mode_name] = (enc_time, dec_time)
    return results

def main():
    print("=== AES-256-CBC File Encryption Demo ===")
    # Create a test file
    with open("secret.txt", "w") as f:
        f.write("This is confidential content.\nIt should be encrypted.")
    password = os.getenv("SECRET_KEY", "MyStrongP@ssw0rd")  # Load from .env
    
    encrypt_file("secret.txt", "secret.txt.enc", password)
    decrypt_file("secret.txt.enc", "secret_decrypted.txt", password)
    
    # Verify
    with open("secret.txt", "r") as f1, open("secret_decrypted.txt", "r") as f2:
        if f1.read() == f2.read():
            print("Verification: Original and decrypted files match.")
    
    print("\n=== Performance Testing (AES modes on 10 MB) ===")
    modes_to_test = [("ECB", modes.ECB), ("CBC", modes.CBC), ("GCM", modes.GCM)]
    res = benchmark(modes_to_test, 10*1024*1024)
    print(f"{'Mode':<6} {'Encrypt (s)':<12} {'Decrypt (s)':<12}")
    for mode, (enc, dec) in res.items():
        print(f"{mode:<6} {enc:<12.4f} {dec:<12.4f}")

if __name__ == "__main__":
    main()