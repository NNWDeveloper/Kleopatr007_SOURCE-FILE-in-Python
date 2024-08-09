import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Function to generate RSA keys
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,  # Strong encryption with 4096-bit key
        backend=default_backend()
    )
    
    public_key = private_key.public_key()
    
    with open("privateKey.txt", "wb") as priv_file:
        priv_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    
    with open("publicKey.txt", "wb") as pub_file:
        pub_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
    
    print("Keys generated successfully!")

# Function to load a private key from file
def load_private_key(file_name):
    with open(file_name, "rb") as key_file:
        key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return key

# Function to encrypt a file
def encrypt_file(input_file, public_key_file):
    with open(public_key_file, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    
    symmetric_key = os.urandom(32)  # AES-256 key
    
    encrypted_symmetric_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    with open(input_file, "rb") as f:
        data = f.read()
    
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    
    with open(input_file + ".enc", "wb") as f:
        f.write(encrypted_symmetric_key + iv + encrypted_data)
    
    print(f"File {input_file} encrypted successfully!")

# Function to decrypt a file
def decrypt_file(encrypted_file, private_key_file):
    private_key = load_private_key(private_key_file)
    
    with open(encrypted_file, "rb") as f:
        encrypted_symmetric_key = f.read(512)
        iv = f.read(16)
        encrypted_data = f.read()
    
    symmetric_key = private_key.decrypt(
        encrypted_symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    
    output_file = encrypted_file.replace(".enc", ".dec")
    with open(output_file, "wb") as f:
        f.write(decrypted_data)
    
    print(f"File {encrypted_file} decrypted successfully!")

# GUI Functions
def generate_keys_gui():
    try:
        generate_keys()
        messagebox.showinfo("Success", "Keys generated successfully!")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def encrypt_file_gui():
    try:
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
        
        public_key_path = filedialog.askopenfilename(title="Select Public Key")
        if not public_key_path:
            return
        
        encrypt_file(file_path, public_key_path)
        messagebox.showinfo("Success", "File encrypted successfully!")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def decrypt_file_gui():
    try:
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
        
        private_key_path = filedialog.askopenfilename(title="Select Private Key")
        if not private_key_path:
            return
        
        decrypt_file(file_path, private_key_path)
        messagebox.showinfo("Success", "File decrypted successfully!")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# GUI setup
root = tk.Tk()
root.title("RSA Encryption Software")
root.geometry("400x300")

btn_generate_keys = tk.Button(root, text="Generate New Keys", command=generate_keys_gui)
btn_generate_keys.pack(pady=20)

btn_encrypt = tk.Button(root, text="Encrypt", command=encrypt_file_gui)
btn_encrypt.pack(pady=20)

btn_decrypt = tk.Button(root, text="Decrypt", command=decrypt_file_gui)
btn_decrypt.pack(pady=20)

root.mainloop()
