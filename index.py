import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import webbrowser
import threading
import http.server
import socketserver
import os
import smtplib
import random
import requests
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from PIL import Image, ImageTk
from io import BytesIO
import re
import hashlib
import ctypes
import sys

# Get the directory of the current script
script_dir = os.path.dirname(os.path.abspath(__file__))

# Path to store registered Gmail hash
registration_hash_file = os.path.join(script_dir, "registered_gmail_hash.txt")

# Sender email credentials
sender_email = "maliciousmail867@gmail.com"  # Replace with your sender email
sender_password = "ktcx yuny ezao vgwm"  # Replace with your sender password

# VirusTotal API key
virustotal_api_key = "dec476467236832be15270caee3a990ac50c9c5794c352a7b3b17463a3d87b82"  # Replaced with the provided API key

# Global variable to store the generated password
generated_password = None

# Function to start the local server
def start_local_server():
    PORT = 8000
    Handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print(f"Serving at port {PORT}")
        httpd.serve_forever()

# Function to open project info
def open_project_info():
    # Run the local server in a separate thread
    threading.Thread(target=start_local_server, daemon=True).start()
    # Open the HTML page in the default web browser
    webbrowser.open('http://example.com/')

# Function to validate email
def is_valid_email(email):
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_regex, email)

# Function to hash a string (Gmail in this case)
def hash_string(s):
    return hashlib.sha256(s.encode()).hexdigest()

# Function to register Gmail
def register_gmail(email):
    hashed_email = hash_string(email)
    with open(registration_hash_file, "w") as f:
        f.write(hashed_email)
    messagebox.showinfo("Registration Successful", "Gmail registered successfully.")

# Function to open registration form
def open_registration_form():
    if os.path.exists(registration_hash_file) and os.path.getsize(registration_hash_file) > 0:
        messagebox.showinfo("Already Registered", "You are already registered with your email")
        return

    registration_window = tk.Toplevel(root)
    registration_window.title("Registration Form")
    registration_window.geometry("300x200")

    tk.Label(registration_window, text="Enter your Gmail address:").pack(pady=10)
    email_entry = ttk.Entry(registration_window, width=30)
    email_entry.pack(pady=10)

    def verify_email():
        email = email_entry.get()
        if email:
            if is_valid_email(email):
                register_gmail(email)
                registration_window.destroy()  # Close registration window after registration
            else:
                messagebox.showerror("Invalid Email", "The entered email is not valid.")

    verify_button = ttk.Button(registration_window, text="Register", command=verify_email)
    verify_button.pack(pady=10)

# Function to send password email
def send_password_email(email_address):
    global generated_password
    generated_password = generate_password()

    # Email details
    subject = "Password for Website Control"
    body = f"Your generated password is: {generated_password}"

    # Create email
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = email_address
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    # Send email
    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(msg)
        return generated_password
    except Exception as e:
        print(f"Failed to send email: {e}")
        return None

# Function to generate a random password
def generate_password():
    return ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789', k=8))

# Function to open login page
def check_user_generate_password():
    if not os.path.exists(registration_hash_file) or os.path.getsize(registration_hash_file) == 0:
        messagebox.showwarning("Not Registered", "You need to register your Gmail first.")
        return

    login_window = tk.Toplevel(root)
    login_window.title("Login Page")
    login_window.geometry("350x250")

    tk.Label(login_window, text=f"Enter your Registered Gmail address to receive the password").pack(pady=5)

    tk.Label(login_window, text="Enter your Gmail address:").pack(pady=5)
    gmail_entry = ttk.Entry(login_window, width=30)
    gmail_entry.pack(pady=5)

    def generate_new_password():
        email = gmail_entry.get()
        if os.path.exists(registration_hash_file):
            with open(registration_hash_file, "r") as f:
                stored_hash = f.read().strip()
                entered_hash = hash_string(email)
                if entered_hash == stored_hash:
                    sent_password = send_password_email(email)
                    if sent_password:
                        messagebox.showinfo("Password Sent", f"Password sent to your registered mail. Please check your email.")
                        login_window.destroy()
                    else:
                        messagebox.showerror("Failed to Send", "Failed to send password email. Please try again.")
                else:
                    messagebox.showerror("Invalid Gmail", "Entered Gmail does not match registered Gmail.")
        else:
            messagebox.showwarning("Not Registered", "You need to register your Gmail first.")

    generate_button = ttk.Button(login_window, text="Generate Password", command=generate_new_password)
    generate_button.pack(pady=10)

# Function to verify the entered password
def verify_password(input_password):
    global generated_password
    if input_password == generated_password:
        return True
    else:
        messagebox.showerror("Invalid Password", "The entered password is incorrect.")
        return False

# Function to run as administrator
def run_as_admin():
    if ctypes.windll.shell32.IsUserAnAdmin():
        return True
    else:
        messagebox.showwarning("Admin Privileges Required", "This operation requires administrative privileges. The application will now restart with elevated permissions.")
        try:
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, ' '.join(sys.argv), None, 1)
            sys.exit(0)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to obtain administrative privileges: {e}")
            return False

# Function to block a website
def block_website_interface():
    if not run_as_admin():
        return

    block_window = tk.Toplevel(root)
    block_window.title("Block Website")
    block_window.geometry("300x200")

    tk.Label(block_window, text="Enter the website URL to block (e.g., example.com):").pack(pady=5)
    website_entry = ttk.Entry(block_window, width=30)
    website_entry.pack(pady=5)

    tk.Label(block_window, text="Enter the password:").pack(pady=5)
    password_entry = ttk.Entry(block_window, width=30, show='*')
    password_entry.pack(pady=5)

    def block_website_action():
        website = website_entry.get()
        password = password_entry.get()
        if password and verify_password(password):
            if website:
                try:
                    with open(r"C:\Windows\System32\drivers\etc\hosts", "a") as hosts_file:
                        hosts_file.write(f"\n127.0.0.1 {website}\n")
                    messagebox.showinfo("Website Blocked", f"Website {website} has been blocked successfully.")
                    block_window.destroy()
                except PermissionError:
                    messagebox.showerror("Error", "Access denied. Run the script with administrator privileges.")
        else:
            messagebox.showerror("Invalid Password", "Incorrect password. Operation canceled.")

    block_button = ttk.Button(block_window, text="Block", command=block_website_action)
    block_button.pack(pady=10)
# Function to scan a website using VirusTotal API
def scan_website(website):
    url = "https://www.virustotal.com/vtapi/v2/url/report"
    params = {"apikey": virustotal_api_key, "resource": website}
    response = requests.get(url, params=params)
    
    if response.status_code == 200:
        result = response.json()
        return result.get("positives", 0) > 0
    elif response.status_code == 403:
        messagebox.showerror("API Error", "Access to the VirusTotal API was denied. Check your API key and usage limits.")
    else:
        messagebox.showerror("API Error", f"Failed to get scan results: {response.status_code}")
    
    return False

# Function to unblock a website
def unblock_website_interface():
    if not run_as_admin():
        return

    unblock_window = tk.Toplevel(root)
    unblock_window.title("Unblock Website")
    unblock_window.geometry("300x200")

    tk.Label(unblock_window, text="Enter the website URL to unblock (e.g., example.com):").pack(pady=5)
    website_entry = ttk.Entry(unblock_window, width=30)
    website_entry.pack(pady=5)

    tk.Label(unblock_window, text="Enter the password:").pack(pady=5)
    password_entry = ttk.Entry(unblock_window, width=30, show='*')
    password_entry.pack(pady=5)

    def unblock_website_action():
        website = website_entry.get()
        password = password_entry.get()
        if password and verify_password(password):
            if website:
                try:
                    with open(r"C:\Windows\System32\drivers\etc\hosts", "r") as hosts_file:
                        lines = hosts_file.readlines()

                    if any(website in line for line in lines):
                        # Perform malicious scan
                        is_malicious = scan_website(website)
                        if is_malicious:
                            messagebox.showerror("Malicious Website Detected", f"The website {website} is detected as malicious.\nPermission denied to unblock.")
                        else:
                            # Remove website from hosts file
                            with open(r"C:\Windows\System32\drivers\etc\hosts", "w") as hosts_file:
                                for line in lines:
                                    if website not in line:
                                        hosts_file.write(line)
                            messagebox.showinfo("Website Unblocked", f"Website {website} has been unblocked successfully.")
                        unblock_window.destroy()
                    else:
                        messagebox.showerror("Website Not Blocked", "The website is not in the blocked list.")

                except PermissionError:
                    messagebox.showerror("Error", "Access denied. Run the script with administrator privileges.")
        else:
            messagebox.showerror("Invalid Password", "Incorrect password. Operation canceled.")

    unblock_button = ttk.Button(unblock_window, text="Unblock", command=unblock_website_action)
    unblock_button.pack(pady=10)

# Main tkinter window
root = tk.Tk()
root.title("Website Control Panel")
root.geometry("800x700")

# Project Info and Register Gmail buttons
top_frame = tk.Frame(root)
top_frame.pack(pady=20)

project_info_button = ttk.Button(top_frame, text="Project Info", command=open_project_info, style='TButton', padding=(10, 5), width=15)
project_info_button.grid(row=0, column=0, padx=10)

register_gmail_button = ttk.Button(top_frame, text="Register Gmail", command=open_registration_form, style='TButton', padding=(10, 5), width=15)
register_gmail_button.grid(row=0, column=1, padx=10)

# Image Display
image_url = "https://www.cybavo.com/img/cms/ransomware.jpg"
response = requests.get(image_url)
image_data = response.content
image = Image.open(BytesIO(image_data))
image = image.resize((300, 225))  # Resize the image
image = ImageTk.PhotoImage(image)
image_label = tk.Label(root, image=image)
image_label.image = image
image_label.pack(pady=20)

# Block and Unblock Website buttons
bottom_frame = tk.Frame(root)
bottom_frame.pack(pady=20)

block_website_button = ttk.Button(bottom_frame, text="Block Website", command=block_website_interface, style='TButton', padding=(10, 5), width=15)
block_website_button.grid(row=0, column=0, padx=10)

unblock_website_button = ttk.Button(bottom_frame, text="Unblock Website", command=unblock_website_interface, style='TButton', padding=(10, 5), width=15)
unblock_website_button.grid(row=0, column=1, padx=10)

# Check User and Generate Password button
generate_password_button = ttk.Button(root, text="Check User and Generate Password", command=check_user_generate_password, style='TButton', padding=(10, 5), width=30)
generate_password_button.pack(pady=20)

root.mainloop()
