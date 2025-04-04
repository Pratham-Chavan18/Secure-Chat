import socket
import threading
import tkinter as tk
from tkinter import messagebox, simpledialog, Label, Entry
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import json
import hashlib
import os
# begins user management
class UserManager:
    def __init__(self, filename='users.json'):
        self.filename = filename
        self.users = self.load_users()

    def load_users(self):
        """Load users from JSON file"""
        if not os.path.exists(self.filename):
            return {}
        
        try:
            with open(self.filename, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {}

    def save_users(self):
        """Save users to JSON file"""
        with open(self.filename, 'w') as f:
            json.dump(self.users, f, indent=4)

    def hash_password(self, password):
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()

    def register_user(self, username, password):
        """Register a new user"""
        if username in self.users:
            return False
        
        hashed_password = self.hash_password(password)
        self.users[username] = hashed_password
        self.save_users()
        return True

    def validate_user(self, username, password):
        """Validate user credentials"""
        if username not in self.users:
            return False
        
        hashed_password = self.hash_password(password)
        return self.users[username] == hashed_password

class UserAuthenticationWindow:
    def __init__(self, user_manager):
        self.user_manager = user_manager
        self.username = None
        
        # Create main window
        self.root = tk.Tk()
        self.root.title("User Authentication")
        self.root.geometry("300x300")

        # Username Label and 
        Label(self.root, text="Username:").pack(pady=(20, 5))
        self.username_entry = Entry(self.root, width=30)
        self.username_entry.pack(pady=5)

        # Password Label and 
        Label(self.root, text="Password:").pack(pady=(10, 5))
        self.password_entry = Entry(self.root, show="*", width=30)
        self.password_entry.pack(pady=5)

        # Buttons
        button_frame = tk.Frame(self.root)
        button_frame.pack(pady=10)

        # Login and Register Buttons
        tk.Button(button_frame, text="Login", command=self.login).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Register", command=self.register).pack(side=tk.LEFT, padx=5)

    def login(self):
        """Handle user login"""
        username = self.username_entry.get()
        password = self.password_entry.get()

        if self.user_manager.validate_user(username, password):
            self.username = username
            messagebox.showinfo("Login", "Login Successful!")
            self.root.destroy()
        else:
            messagebox.showerror("Login Failed", "Invalid username or password")

    def register(self):
        """Handle user registration"""
        username = self.username_entry.get()
        password = self.password_entry.get()

        if not username or not password:
            messagebox.showerror("Error", "Username and password cannot be empty")
            return

        if self.user_manager.register_user(username, password):
            messagebox.showinfo("Registration", "User registered successfully!")
        else:
            messagebox.showerror("Registration Failed", "Username already exists")

class DESEncryption:
    def __init__(self, key=None, is_server=False):
        self.key = key if key else get_random_bytes(8)
        self.is_server = is_server
        if self.is_server:
            print(f"[DEBUG] DES Key: {self.key.hex()}")

    def encrypt(self, message):
        cipher = DES.new(self.key, DES.MODE_ECB)
        padded_message = pad(message.encode(), DES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        if self.is_server:
            print("\n[DEBUG] Encrypting Message:")
            print(f"  Original Message: '{message}'")
            print(f"  Padded Message (hex): {padded_message.hex()}")
            print(f"  Encrypted Message (hex): {encrypted_message.hex()}")
        return encrypted_message

    def decrypt(self, encrypted_message):
        cipher = DES.new(self.key, DES.MODE_ECB)
        decrypted_padded = cipher.decrypt(encrypted_message)
        decrypted_message = unpad(decrypted_padded, DES.block_size)
        if self.is_server:
            print("\n[DEBUG] Decrypting Message:")
            print(f"  Encrypted Message (hex): {encrypted_message.hex()}")
            print(f"  Decrypted Padded Message (hex): {decrypted_padded.hex()}")
            print(f"  Decrypted Message: '{decrypted_message.decode()}'")
        return decrypted_message.decode()

class MultiClientChatApp:
    def __init__(self, master, username):
        self.username = username
        self.master = master
        self.master.title(f"Encrypted Chat - {username}")
        self.master.geometry("600x700")

        # Chat display
        self.chat_display = tk.Text(master, height=20, width=70, state='disabled')
        self.chat_display.pack(padx=10, pady=10)

        # Message input
        self.message_entry = tk.Entry(master, width=50)
        self.message_entry.pack(padx=10, pady=5)

        # Buttons frame
        button_frame = tk.Frame(master)
        button_frame.pack(pady=5)

        # Buttons
        tk.Button(button_frame, text="Start Server", command=self.start_server).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Connect Client", command=self.start_client).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Send", command=self.send_message).pack(side=tk.LEFT, padx=5)

        # Network and encryption variables
        self.socket = None
        self.des_encryption = None

    def start_server(self):
        host = '0.0.0.0'
        port = 5000
        
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((host, port))
        self.socket.listen(1)
        
        messagebox.showinfo("Server", f"{self.username} started server. Waiting for client...")
        
        # Accept connection
        client_socket, addr = self.socket.accept()
        self.socket = client_socket
        
        # Generate and share DES key
        self.des_encryption = DESEncryption(is_server=True)
        client_socket.send(self.des_encryption.key)
        
        # Send username
        client_socket.send(self.username.encode())
        
        # Start receiving messages
        threading.Thread(target=self.receive_messages, daemon=True).start()
        
        messagebox.showinfo("Connection", f"Connected to {addr}")

    def start_client(self):
        host = simpledialog.askstring("Input", "Enter Server IP:")
        port = 5000
        
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((host, port))
        
        # Receive DES key from server
        des_key = self.socket.recv(8)
        self.des_encryption = DESEncryption(des_key)
        
        # Receive remote username
        remote_username = self.socket.recv(1024).decode()
        
        # Start receiving messages
        threading.Thread(target=self.receive_messages, daemon=True).start()
        
        messagebox.showinfo("Connection", f"Connected to {remote_username}")

    def send_message(self):
        if not self.socket or not self.des_encryption:
            messagebox.showerror("Error", "Not connected!")
            return
        
        message = self.message_entry.get()
        if message:
            full_message = f"{self.username}: {message}"
            encrypted_message = self.des_encryption.encrypt(full_message)
            self.socket.send(encrypted_message)
            self.update_chat(f"You: {message}")
            self.message_entry.delete(0, tk.END)

    def receive_messages(self):
        while True:
            try:
                encrypted_message = self.socket.recv(1024)
                if encrypted_message:
                    message = self.des_encryption.decrypt(encrypted_message)
                    self.update_chat(message)
            except Exception as e:
                messagebox.showerror("Error", f"Connection lost: {e}")
                break

    def update_chat(self, message):
        self.chat_display.configure(state='normal')
        self.chat_display.insert(tk.END, message + "\n")
        self.chat_display.configure(state='disabled')
        self.chat_display.see(tk.END)

def main():
    # Initialize user manager
    user_manager = UserManager()

    # Show authentication window
    auth_window = UserAuthenticationWindow(user_manager)
    auth_window.root.mainloop()

    # If Authentication Successful
    if auth_window.username:
        chat_root = tk.Tk()
        app = MultiClientChatApp(chat_root, auth_window.username)
        chat_root.mainloop()

if __name__ == "__main__":
    main()

