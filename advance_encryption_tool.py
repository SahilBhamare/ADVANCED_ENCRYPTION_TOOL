import os
import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad

# ========== Function to derive a 256-bit AES key using PBKDF2 ==========
def derive_key(password, salt):
    return PBKDF2(password, salt, dkLen=32, count=1000000)

# ========== Encrypt a file using AES-256 ==========
def encrypt_file(filepath, password):
    try:
        with open(filepath, 'rb') as f:
            data = f.read()

        salt = get_random_bytes(16)
        key = derive_key(password.encode(), salt)
        iv = get_random_bytes(16)

        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(data, AES.block_size))

        # Combine salt, iv and encrypted data
        encrypted_data = salt + iv + ciphertext
        encrypted_filepath = filepath + '.enc'

        with open(encrypted_filepath, 'wb') as f:
            f.write(encrypted_data)

        return encrypted_filepath
    except Exception as e:
        return str(e)

# ========== Decrypt a file encrypted with this tool ==========
def decrypt_file(filepath, password):
    try:
        with open(filepath, 'rb') as f:
            content = f.read()

        salt = content[:16]
        iv = content[16:32]
        ciphertext = content[32:]

        key = derive_key(password.encode(), salt)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)

        decrypted_filepath = filepath.replace('.enc', '')  # Restore original filename

        with open(decrypted_filepath, 'wb') as f:
            f.write(decrypted_data)

        return decrypted_filepath
    except Exception as e:
        return str(e)

# ========== Main GUI App ==========
class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Advanced AES-256 Encryption Tool")
        self.root.geometry("550x350")
        self.root.configure(bg="#f0f8ff")  # Light blue background

        self.file_path = None

        # Title Label
        self.title_label = tk.Label(root, text="Advanced Encryption Tool", font=("Helvetica", 16, "bold"), bg="#f0f8ff", fg="#0a3d62")
        self.title_label.pack(pady=10)

        # File selection
        self.file_entry = tk.Entry(root, width=50, font=("Arial", 10))
        self.file_entry.pack(pady=5)
        self.browse_button = tk.Button(root, text="📁 Browse File", command=self.browse_file, bg="#3498db", fg="white", width=20)
        self.browse_button.pack(pady=5)

        # Password entry
        self.pass_label = tk.Label(root, text="🔑 Enter Password:", bg="#f0f8ff", font=("Arial", 11))
        self.pass_label.pack(pady=5)
        self.password_entry = tk.Entry(root, show="*", width=30, font=("Arial", 11))
        self.password_entry.pack(pady=5)

        # Encrypt and Decrypt buttons
        self.encrypt_button = tk.Button(root, text="Encrypt File 🔐", command=self.encrypt, bg="#2ecc71", fg="white", width=20)
        self.encrypt_button.pack(pady=8)

        self.decrypt_button = tk.Button(root, text="Decrypt File 🔓", command=self.decrypt, bg="#e67e22", fg="white", width=20)
        self.decrypt_button.pack(pady=5)

        # Back button to reset inputs
        self.back_button = tk.Button(root, text="🔙 Reset", command=self.reset_form, bg="#95a5a6", fg="white", width=20)
        self.back_button.pack(pady=10)

        # Status label for feedback
        self.status_label = tk.Label(root, text="", fg="blue", bg="#f0f8ff", font=("Arial", 10))
        self.status_label.pack(pady=5)

    # ========== Function to browse file ==========
    def browse_file(self):
        self.file_path = filedialog.askopenfilename()
        self.file_entry.delete(0, tk.END)
        self.file_entry.insert(0, self.file_path)

    # ========== Encrypt button action ==========
    def encrypt(self):
        if not self.file_path or not self.password_entry.get():
            messagebox.showwarning("Missing Info", "Please select a file and enter a password.")
            return

        result = encrypt_file(self.file_path, self.password_entry.get())
        if os.path.exists(result):
            self.status_label.config(text=f"✅ File encrypted successfully:\n{result}", fg="green")
        else:
            self.status_label.config(text=f"❌ Error: {result}", fg="red")

    # ========== Decrypt button action ==========
    def decrypt(self):
        if not self.file_path or not self.password_entry.get():
            messagebox.showwarning("Missing Info", "Please select a file and enter a password.")
            return

        result = decrypt_file(self.file_path, self.password_entry.get())
        if os.path.exists(result):
            self.status_label.config(text=f"✅ File decrypted successfully:\n{result}", fg="green")
        else:
            self.status_label.config(text=f"❌ Error: {result}", fg="red")

    # ========== Back/Reset button ==========
    def reset_form(self):
        self.file_path = None
        self.file_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.status_label.config(text="")

# ========== Run the GUI ==========
if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
