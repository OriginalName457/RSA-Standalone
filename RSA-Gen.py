import tkinter as tk
from tkinter import Listbox, END, messagebox
import os
import subprocess
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import base64

# Key generation function
def generate_key_pair():
    key = RSA.generate(2048)  # Generate a new RSA key pair
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    # Save the private key to 'private_key.pem'
    with open('private_key.pem', 'wb') as private_file:
        private_file.write(private_key)

    # Save the public key to 'public_key.pem'
    with open('public_key.pem', 'wb') as public_file:
        public_file.write(public_key)

    messagebox.showinfo("Success", "New RSA key pair generated successfully.")
    
    # Reload keys
    global public_key_loaded, private_key_loaded
    public_key_loaded = load_key('public_key.pem')
    private_key_loaded = load_key('private_key.pem')

def load_key(filename):
    with open(filename, 'r') as file:
        key = RSA.import_key(file.read())
    return key

def check_and_generate_keys():
    # Check if public and private key files exist, generate if not present
    if not os.path.exists('public_key.pem') or not os.path.exists('private_key.pem'):
        messagebox.showinfo("Info", "Key files not found. Generating new RSA key pair.")
        generate_key_pair()

def encrypt_message(message, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_message = cipher.encrypt(message.encode())
    return base64.b64encode(encrypted_message).decode()

def decrypt_message(encrypted_message, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher.decrypt(base64.b64decode(encrypted_message))
    return decrypted_message.decode()

def encrypt_file(file_name, public_key):
    with open(file_name, 'r') as file:
        content = file.read()
    encrypted_content = encrypt_message(content, public_key)
    encrypted_file_name = file_name.replace('.txt', '_encrypted.txt')
    with open(encrypted_file_name, 'w') as file:
        file.write(encrypted_content)
    return encrypted_file_name

def decrypt_file(file_name, private_key):
    with open(file_name, 'r') as file:
        encrypted_content = file.read()
    decrypted_content = decrypt_message(encrypted_content, private_key)
    decrypted_file_name = file_name.replace('_encrypted.txt', '_decrypted.txt')
    with open(decrypted_file_name, 'w') as file:
        file.write(decrypted_content)
    return decrypted_file_name

def open_file(event):
    selected_file = file_list.get(tk.ANCHOR)
    if selected_file:
        try:
            # Open the file with the system's default text editor
            subprocess.run(['notepad', selected_file], check=True)
        except Exception as e:
            messagebox.showerror("Error", f"Could not open the file: {e}")

def refresh_file_list():
    file_list.delete(0, END)
    for file in os.listdir('.'):
        if file.endswith('.txt'):
            file_list.insert(END, file)

def encrypt_action():
    selected_file = file_list.get(tk.ANCHOR)
    if selected_file:
        encrypted_file = encrypt_file(selected_file, public_key_loaded)
        messagebox.showinfo("Success", f"File '{selected_file}' encrypted successfully as '{encrypted_file}'.")
        refresh_file_list()

def decrypt_action():
    selected_file = file_list.get(tk.ANCHOR)
    if selected_file:
        decrypted_file = decrypt_file(selected_file, private_key_loaded)
        messagebox.showinfo("Success", f"File '{selected_file}' decrypted successfully as '{decrypted_file}'.")
        refresh_file_list()

# Initialize the application and check for key files
check_and_generate_keys()

# Load the keys after checking or generating them
public_key_loaded = load_key('public_key.pem')
private_key_loaded = load_key('private_key.pem')

root = tk.Tk()
root.title("RSA Encryption/Decryption Demo")

file_list = Listbox(root)
file_list.pack(pady=10)
file_list.bind('<Double-1>', open_file)  # Bind double-click event to open_file function

encrypt_button = tk.Button(root, text="Encrypt", command=encrypt_action)
encrypt_button.pack(pady=10)

decrypt_button = tk.Button(root, text="Decrypt", command=decrypt_action)
decrypt_button.pack(pady=10)

# Add new button to generate RSA key pair
generate_key_button = tk.Button(root, text="Generate RSA Key Pair", command=generate_key_pair)
generate_key_button.pack(pady=10)

refresh_button = tk.Button(root, text="Refresh List", command=refresh_file_list)
refresh_button.pack(pady=10)

refresh_file_list()

root.mainloop()
