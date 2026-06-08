#!/usr/bin/env python3
"""
Hybrid Encryption System with Digital Envelope
Creative Task for BIT4138 Advanced Cryptography

Features:
- Generate RSA key pair (2048-bit)
- Load existing RSA keys (PEM format)
- Encrypt any file using hybrid encryption:
    * Random AES-256-GCM key encrypts the file
    * RSA public key encrypts the AES key (digital envelope)
    * SHA-256 hash of original file for verification
- Decrypt the hybrid file using RSA private key
- GUI built with Tkinter
"""

import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import os
import threading
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidTag

# ----------------------------- Helper Functions -----------------------------

def generate_rsa_keys(priv_path="private_key.pem", pub_path="public_key.pem"):
    """Generate RSA key pair and save to PEM files."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    # Save private key
    with open(priv_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    # Save public key
    with open(pub_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    return priv_path, pub_path

def load_rsa_private_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_rsa_public_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def sha256_file(filepath):
    """Return SHA-256 hash of file as hex string."""
    sha = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha.update(chunk)
    return sha.hexdigest()

def hybrid_encrypt(input_file, output_file, public_key_path, progress_callback=None):
    """
    Hybrid encryption:
    1. Generate random AES-256 key and nonce (12 bytes for GCM)
    2. Encrypt file with AES-GCM (ciphertext + tag)
    3. Encrypt AES key with RSA public key (OAEP)
    4. Write: [len_enc_aes_key(2 bytes)] [encrypted_aes_key] [nonce(12)] [tag(16)] [ciphertext]
    5. Also compute SHA-256 of original file and append at the end (optional integrity)
    """
    # Load public key
    public_key = load_rsa_public_key(public_key_path)

    # Generate random AES key and nonce
    aes_key = os.urandom(32)      # 256-bit
    nonce = os.urandom(12)        # GCM recommended

    # Encrypt file with AES-GCM
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    with open(input_file, "rb") as f:
        plaintext = f.read()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag

    # Encrypt AES key with RSA
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Compute original file hash for integrity
    file_hash = sha256_file(input_file).encode()

    # Write hybrid file
    with open(output_file, "wb") as f:
        # 2 bytes: length of encrypted AES key
        f.write(len(encrypted_aes_key).to_bytes(2, "big"))
        f.write(encrypted_aes_key)
        f.write(nonce)
        f.write(tag)
        f.write(ciphertext)
        f.write(file_hash)   # 64 bytes (hex digest as ascii)

    if progress_callback:
        progress_callback(100)

    return True

def hybrid_decrypt(input_file, output_file, private_key_path, progress_callback=None):
    """
    Decrypt a hybrid file:
    1. Read encrypted AES key length
    2. Extract encrypted AES key, nonce, tag, ciphertext, and stored hash
    3. Decrypt AES key using RSA private key
    4. Decrypt ciphertext with AES-GCM (verifies tag)
    5. Verify integrity by comparing SHA-256 of decrypted file with stored hash
    """
    private_key = load_rsa_private_key(private_key_path)

    with open(input_file, "rb") as f:
        # Read encrypted AES key length
        key_len_bytes = f.read(2)
        if len(key_len_bytes) < 2:
            raise ValueError("Corrupted hybrid file: missing key length")
        key_len = int.from_bytes(key_len_bytes, "big")
        encrypted_aes_key = f.read(key_len)
        if len(encrypted_aes_key) < key_len:
            raise ValueError("Corrupted hybrid file: incomplete encrypted key")
        nonce = f.read(12)
        if len(nonce) < 12:
            raise ValueError("Corrupted hybrid file: missing nonce")
        tag = f.read(16)
        if len(tag) < 16:
            raise ValueError("Corrupted hybrid file: missing authentication tag")
        ciphertext = f.read()
        # Last 64 bytes are the original file hash (hex)
        if len(ciphertext) < 64:
            raise ValueError("Corrupted hybrid file: missing hash")
        stored_hash = ciphertext[-64:].decode()
        ciphertext = ciphertext[:-64]

    # Decrypt AES key using RSA private key
    try:
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        raise ValueError("RSA decryption failed. Wrong private key?") from e

    # Decrypt file content with AES-GCM (automatically verifies tag)
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Write decrypted file
    with open(output_file, "wb") as f:
        f.write(plaintext)

    # Integrity verification
    actual_hash = sha256_file(output_file)
    if actual_hash != stored_hash:
        os.remove(output_file)  # delete corrupted file
        raise ValueError(f"Integrity check failed! File may have been tampered. Expected {stored_hash}, got {actual_hash}")

    if progress_callback:
        progress_callback(100)

    return True

# ----------------------------- GUI Class -----------------------------

class HybridCryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Hybrid Crypto System - AES+RSA Digital Envelope")
        self.root.geometry("700x650")
        self.root.resizable(True, True)

        # Variables
        self.input_file = tk.StringVar()
        self.output_file = tk.StringVar()
        self.pub_key_file = tk.StringVar(value="public_key.pem")
        self.priv_key_file = tk.StringVar(value="private_key.pem")
        self.mode = tk.StringVar(value="encrypt")
        self.progress_var = tk.IntVar()

        # Create GUI elements
        self.create_widgets()

    def create_widgets(self):
        # Title
        title = tk.Label(self.root, text="Hybrid Encryption System (Digital Envelope)",
                         font=("Arial", 14, "bold"), fg="darkblue")
        title.pack(pady=10)

        # Mode selection
        mode_frame = tk.LabelFrame(self.root, text="Operation Mode", padx=10, pady=5)
        mode_frame.pack(fill="x", padx=10, pady=5)
        tk.Radiobutton(mode_frame, text="Encrypt", variable=self.mode, value="encrypt").pack(side="left", padx=20)
        tk.Radiobutton(mode_frame, text="Decrypt", variable=self.mode, value="decrypt").pack(side="left", padx=20)

        # Input file
        file_frame = tk.LabelFrame(self.root, text="File Selection", padx=10, pady=5)
        file_frame.pack(fill="x", padx=10, pady=5)
        tk.Label(file_frame, text="Input File:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        tk.Entry(file_frame, textvariable=self.input_file, width=50).grid(row=0, column=1, padx=5, pady=5)
        tk.Button(file_frame, text="Browse", command=self.browse_input).grid(row=0, column=2, padx=5)

        tk.Label(file_frame, text="Output File:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        tk.Entry(file_frame, textvariable=self.output_file, width=50).grid(row=1, column=1, padx=5, pady=5)
        tk.Button(file_frame, text="Browse", command=self.browse_output).grid(row=1, column=2, padx=5)

        # RSA Keys
        key_frame = tk.LabelFrame(self.root, text="RSA Keys (PEM format)", padx=10, pady=5)
        key_frame.pack(fill="x", padx=10, pady=5)
        tk.Label(key_frame, text="Public Key (encrypt only):").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        tk.Entry(key_frame, textvariable=self.pub_key_file, width=50).grid(row=0, column=1, padx=5, pady=2)
        tk.Button(key_frame, text="Browse", command=lambda: self.browse_key("pub")).grid(row=0, column=2, padx=5)

        tk.Label(key_frame, text="Private Key (decrypt only):").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        tk.Entry(key_frame, textvariable=self.priv_key_file, width=50).grid(row=1, column=1, padx=5, pady=2)
        tk.Button(key_frame, text="Browse", command=lambda: self.browse_key("priv")).grid(row=1, column=2, padx=5)

        # Key generation button
        gen_frame = tk.Frame(self.root)
        gen_frame.pack(pady=5)
        tk.Button(gen_frame, text="Generate New RSA Key Pair (2048-bit)", command=self.generate_keys,
                  bg="lightblue").pack()

        # Progress bar
        progress_frame = tk.LabelFrame(self.root, text="Progress", padx=10, pady=5)
        progress_frame.pack(fill="x", padx=10, pady=5)
        self.progress = ttk.Progressbar(progress_frame, variable=self.progress_var, maximum=100)
        self.progress.pack(fill="x", padx=5, pady=5)
        self.status_label = tk.Label(progress_frame, text="Ready", fg="gray")
        self.status_label.pack()

        # Log area
        log_frame = tk.LabelFrame(self.root, text="Log / Output", padx=10, pady=5)
        log_frame.pack(fill="both", expand=True, padx=10, pady=5)
        self.log_area = scrolledtext.ScrolledText(log_frame, height=12, state="normal")
        self.log_area.pack(fill="both", expand=True)
        self.log_area.config(font=("Courier", 9))

        # Action button
        self.action_btn = tk.Button(self.root, text="START", command=self.start_operation,
                                    bg="darkgreen", fg="white", font=("Arial", 12, "bold"))
        self.action_btn.pack(pady=15)

    def browse_input(self):
        filetypes = [("All files", "*.*")]
        fname = filedialog.askopenfilename(title="Select input file", filetypes=filetypes)
        if fname:
            self.input_file.set(fname)
            if not self.output_file.get():
                # Auto suggest output file name
                base = os.path.splitext(fname)[0]
                if self.mode.get() == "encrypt":
                    self.output_file.set(base + ".hybrid")
                else:
                    self.output_file.set(base + "_decrypted" + os.path.splitext(fname)[1].replace(".hybrid", ""))

    def browse_output(self):
        if self.mode.get() == "encrypt":
            def_ext = ".hybrid"
            filetypes = [("Hybrid encrypted", "*.hybrid"), ("All files", "*.*")]
        else:
            def_ext = ""
            filetypes = [("All files", "*.*")]
        fname = filedialog.asksaveasfilename(title="Save as...", defaultextension=def_ext, filetypes=filetypes)
        if fname:
            self.output_file.set(fname)

    def browse_key(self, key_type):
        if key_type == "pub":
            fname = filedialog.askopenfilename(title="Select public key (PEM)", filetypes=[("PEM files", "*.pem")])
            if fname:
                self.pub_key_file.set(fname)
        else:
            fname = filedialog.askopenfilename(title="Select private key (PEM)", filetypes=[("PEM files", "*.pem")])
            if fname:
                self.priv_key_file.set(fname)

    def generate_keys(self):
        try:
            priv, pub = generate_rsa_keys()
            self.pub_key_file.set(pub)
            self.priv_key_file.set(priv)
            self.log("✅ RSA key pair generated successfully!")
            self.log(f"   Private key: {priv}")
            self.log(f"   Public key:  {pub}")
            messagebox.showinfo("Success", f"Keys generated:\nPrivate: {priv}\nPublic: {pub}")
        except Exception as e:
            messagebox.showerror("Error", f"Key generation failed: {e}")

    def log(self, msg):
        self.log_area.insert(tk.END, msg + "\n")
        self.log_area.see(tk.END)
        self.root.update_idletasks()

    def update_progress(self, value):
        self.progress_var.set(value)
        self.root.update_idletasks()

    def start_operation(self):
        # Validate inputs
        inp = self.input_file.get()
        outp = self.output_file.get()
        if not inp or not os.path.isfile(inp):
            messagebox.showerror("Error", "Please select a valid input file.")
            return
        if not outp:
            messagebox.showerror("Error", "Please specify output file.")
            return

        mode = self.mode.get()
        if mode == "encrypt":
            pub_path = self.pub_key_file.get()
            if not pub_path or not os.path.isfile(pub_path):
                messagebox.showerror("Error", "Please select a valid RSA public key (PEM file).")
                return
        else:  # decrypt
            priv_path = self.priv_key_file.get()
            if not priv_path or not os.path.isfile(priv_path):
                messagebox.showerror("Error", "Please select a valid RSA private key (PEM file).")
                return

        # Disable button during operation
        self.action_btn.config(state="disabled", text="WORKING...")
        self.log("\n" + "="*60)
        self.log(f"Starting {mode.upper()} operation...")
        self.log(f"Input: {inp}")
        self.log(f"Output: {outp}")
        self.progress_var.set(0)

        # Run in thread to keep GUI responsive
        thread = threading.Thread(target=self.run_operation, args=(mode, inp, outp), daemon=True)
        thread.start()

    def run_operation(self, mode, inp, outp):
        try:
            if mode == "encrypt":
                hybrid_encrypt(inp, outp, self.pub_key_file.get(),
                               progress_callback=self.update_progress)
                self.log("✅ Encryption completed successfully!")
                self.log(f"   Encrypted file saved as: {outp}")
                self.log(f"   Original file SHA-256: {sha256_file(inp)}")
            else:
                hybrid_decrypt(inp, outp, self.priv_key_file.get(),
                               progress_callback=self.update_progress)
                self.log("✅ Decryption completed successfully!")
                self.log(f"   Decrypted file saved as: {outp}")
                self.log(f"   Integrity verified. Hash matches original.")
            self.update_progress(100)
        except Exception as e:
            self.log(f"❌ ERROR: {e}")
            messagebox.showerror("Operation Failed", str(e))
        finally:
            self.action_btn.config(state="normal", text="START")
            self.log("="*60 + "\n")

# ----------------------------- Main -----------------------------
if __name__ == "__main__":
    root = tk.Tk()
    app = HybridCryptoApp(root)
    root.mainloop()