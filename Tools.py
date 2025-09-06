import tkinter as tk
from tkinter import filedialog, messagebox
from ttkbootstrap import Style
from ttkbootstrap.constants import *
from ttkbootstrap.widgets import *

import base64
import hashlib
import urllib.parse
import html
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# ----------------------
# Main GUI
# ----------------------
root = tk.Tk()
root.title("Universal Encoder/Decoder with Crypto")
root.geometry("1000x820")

# Modern Style (choose "flatly", "darkly", "cyborg", etc.)
style = Style("cyborg")  

# Notebook (tabs)
notebook = Notebook(root, bootstyle="primary")
notebook.pack(fill="both", expand=True, padx=10, pady=10)

# ----------------------
# Tabs
# ----------------------
tab_main = Frame(notebook, padding=15)
notebook.add(tab_main, text="Encoder / Decoder")

tab_keys = Frame(notebook, padding=15)
notebook.add(tab_keys, text="Key Management")

# ----------------------
# Methods
# ----------------------
methods = [
    "ASCII", "UTF-8", "UTF-16", "UTF-32",
    "Base16 (Hex)", "Base32", "Base58", "Base64", "Base85",
    "URL Encode", "URL Decode",
    "HTML Encode", "HTML Decode",
    "MD5", "SHA-1", "SHA-256", "SHA-512",
    "AES Encrypt", "AES Decrypt",
    "RSA Encrypt", "RSA Decrypt"
]

hash_methods = ["MD5", "SHA-1", "SHA-256", "SHA-512"]
aes_methods = ["AES Encrypt", "AES Decrypt"]
rsa_methods = ["RSA Encrypt", "RSA Decrypt"]

rsa_key = None
rsa_pub = None
rsa_cipher_enc = None
rsa_cipher_dec = None

# ----------------------
# Input / Output (Main Tab)
# ----------------------
input_frame = Labelframe(tab_main, text="Input", bootstyle="info", padding=10)
input_frame.pack(fill="x", pady=10)

input_text = tk.Text(input_frame, height=6, wrap="word", font=("Consolas", 11))
input_text.pack(fill="both", expand=True)

method_frame = Labelframe(tab_main, text="Encoding / Decoding Method", bootstyle="primary", padding=10)
method_frame.pack(fill="x", pady=10)

method_var = tk.StringVar(value=methods[0])
method_menu = Combobox(method_frame, textvariable=method_var, values=methods, state="readonly")
method_menu.pack(fill="x", padx=5, pady=5)

# AES Key field
key_label = Label(method_frame, text="AES Key (16/24/32 bytes):")
key_entry = Entry(method_frame, bootstyle="secondary")

output_frame = Labelframe(tab_main, text="Output", bootstyle="success", padding=10)
output_frame.pack(fill="both", expand=True, pady=10)

output_text = tk.Text(output_frame, height=8, wrap="word", font=("Consolas", 11))
output_text.pack(fill="both", expand=True)

# ----------------------
# Utility
# ----------------------
def pad(s):
    return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)

def unpad(s):
    return s[:-ord(s[-1])]

# ----------------------
# Encode / Decode
# ----------------------
def encode_text():
    global rsa_cipher_enc
    text = input_text.get("1.0", tk.END).strip()
    method = method_var.get()
    try:
        if method in ["ASCII", "UTF-8", "UTF-16", "UTF-32"]:
            result = text.encode(method.lower())
        elif method == "Base16 (Hex)":
            result = base64.b16encode(text.encode()).decode()
        elif method == "Base32":
            result = base64.b32encode(text.encode()).decode()
        elif method == "Base58":
            alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
            num = int.from_bytes(text.encode(), "big")
            result = ""
            while num > 0:
                num, rem = divmod(num, 58)
                result = alphabet[rem] + result
        elif method == "Base64":
            result = base64.b64encode(text.encode()).decode()
        elif method == "Base85":
            result = base64.b85encode(text.encode()).decode()
        elif method == "URL Encode":
            result = urllib.parse.quote(text)
        elif method == "HTML Encode":
            result = html.escape(text)
        elif method == "MD5":
            result = hashlib.md5(text.encode()).hexdigest()
        elif method == "SHA-1":
            result = hashlib.sha1(text.encode()).hexdigest()
        elif method == "SHA-256":
            result = hashlib.sha256(text.encode()).hexdigest()
        elif method == "SHA-512":
            result = hashlib.sha512(text.encode()).hexdigest()
        elif method == "AES Encrypt":
            key = key_entry.get().encode()
            if len(key) not in [16, 24, 32]:
                raise ValueError("AES key must be 16/24/32 bytes long")
            cipher = AES.new(key, AES.MODE_ECB)
            ct_bytes = cipher.encrypt(pad(text).encode())
            result = base64.b64encode(ct_bytes).decode()
        elif method == "RSA Encrypt":
            if rsa_cipher_enc is None:
                raise ValueError("No RSA key loaded! Generate or import one first.")
            ct_bytes = rsa_cipher_enc.encrypt(text.encode())
            result = base64.b64encode(ct_bytes).decode()
        else:
            result = "This method supports only decoding!"
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, str(result))
    except Exception as e:
        messagebox.showerror("Error", str(e))

def decode_text():
    global rsa_cipher_dec
    text = input_text.get("1.0", tk.END).strip()
    method = method_var.get()
    try:
        if method == "Base16 (Hex)":
            result = base64.b16decode(text.encode()).decode()
        elif method == "Base32":
            result = base64.b32decode(text.encode()).decode()
        elif method == "Base58":
            alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
            num = 0
            for char in text:
                num = num * 58 + alphabet.index(char)
            result = num.to_bytes((num.bit_length() + 7) // 8, "big").decode()
        elif method == "Base64":
            result = base64.b64decode(text.encode()).decode()
        elif method == "Base85":
            result = base64.b85decode(text.encode()).decode()
        elif method == "URL Decode":
            result = urllib.parse.unquote(text)
        elif method == "HTML Decode":
            result = html.unescape(text)
        elif method == "AES Decrypt":
            key = key_entry.get().encode()
            if len(key) not in [16, 24, 32]:
                raise ValueError("AES key must be 16/24/32 bytes long")
            cipher = AES.new(key, AES.MODE_ECB)
            pt = cipher.decrypt(base64.b64decode(text.encode())).decode()
            result = unpad(pt)
        elif method == "RSA Decrypt":
            if rsa_cipher_dec is None:
                raise ValueError("No RSA key loaded! Generate or import one first.")
            ct_bytes = base64.b64decode(text.encode())
            result = rsa_cipher_dec.decrypt(ct_bytes).decode()
        elif method in hash_methods:
            result = "Decoding not possible for hashing!"
        else:
            result = text.encode().decode(method.lower())
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, result)
    except Exception as e:
        messagebox.showerror("Error", str(e))

# ----------------------
# Buttons
# ----------------------
btn_frame = Frame(tab_main)
btn_frame.pack(pady=15)

encode_button = Button(btn_frame, text="Encode", bootstyle="success-outline", command=encode_text)
encode_button.grid(row=0, column=0, padx=10)

decode_button = Button(btn_frame, text="Decode", bootstyle="danger-outline", command=decode_text)
decode_button.grid(row=0, column=1, padx=10)

def update_buttons(*args):
    method = method_var.get()
    if method in hash_methods:
        decode_button.grid_remove()
    else:
        decode_button.grid()
    if method in aes_methods:
        key_label.pack(anchor="w", padx=5, pady=5)
        key_entry.pack(fill="x", padx=5, pady=5)
    else:
        key_label.pack_forget()
        key_entry.pack_forget()

method_var.trace_add("write", update_buttons)

# ----------------------
# Key Management Tab
# ----------------------
aes_frame = Labelframe(tab_keys, text="AES Key Management", bootstyle="info", padding=10)
aes_frame.pack(fill="x", pady=10)

Button(aes_frame, text="Generate AES Key (16 bytes)",
       bootstyle="secondary-outline",
       command=lambda: key_entry.insert(0, get_random_bytes(16).hex())).pack(pady=5)

rsa_frame = Labelframe(tab_keys, text="RSA Key Management", bootstyle="warning", padding=10)
rsa_frame.pack(fill="x", pady=10)

def generate_rsa_key():
    global rsa_key, rsa_pub, rsa_cipher_enc, rsa_cipher_dec
    rsa_key = RSA.generate(2048)
    rsa_pub = rsa_key.publickey()
    rsa_cipher_enc = PKCS1_OAEP.new(rsa_pub)
    rsa_cipher_dec = PKCS1_OAEP.new(rsa_key)
    messagebox.showinfo("RSA", "New RSA keypair generated.")

def import_rsa_key():
    global rsa_key, rsa_pub, rsa_cipher_enc, rsa_cipher_dec
    file_path = filedialog.askopenfilename(title="Import RSA Key")
    if not file_path:
        return
    with open(file_path, "rb") as f:
        key_data = f.read()
    rsa_key = RSA.import_key(key_data)
    if rsa_key.has_private():
        rsa_pub = rsa_key.publickey()
        rsa_cipher_dec = PKCS1_OAEP.new(rsa_key)
    else:
        rsa_pub = rsa_key
    rsa_cipher_enc = PKCS1_OAEP.new(rsa_pub)
    messagebox.showinfo("RSA", f"RSA key imported from {file_path}")

def export_rsa_key(private=True):
    global rsa_key, rsa_pub
    if rsa_key is None and rsa_pub is None:
        messagebox.showerror("RSA", "No RSA key to export.")
        return
    file_path = filedialog.asksaveasfilename(title="Export RSA Key",
                                             defaultextension=".pem",
                                             filetypes=[("PEM files", "*.pem")])
    if not file_path:
        return
    with open(file_path, "wb") as f:
        if private:
            f.write(rsa_key.export_key("PEM"))
        else:
            f.write(rsa_pub.export_key("PEM"))
    messagebox.showinfo("RSA", f"RSA key exported to {file_path}")

Button(rsa_frame, text="Generate RSA Keypair", bootstyle="primary-outline", command=generate_rsa_key).pack(pady=5)
Button(rsa_frame, text="Import RSA Key", bootstyle="info-outline", command=import_rsa_key).pack(pady=5)
Button(rsa_frame, text="Export RSA Private Key", bootstyle="danger-outline", command=lambda: export_rsa_key(True)).pack(pady=5)
Button(rsa_frame, text="Export RSA Public Key", bootstyle="success-outline", command=lambda: export_rsa_key(False)).pack(pady=5)

# ----------------------
# Run App
# ----------------------
root.mainloop()
