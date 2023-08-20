# Basic Libraries
import os
import traceback
import string
import binascii
from random import choice, randint, shuffle
from base64 import b64decode
from base64 import b64encode

# Building the UI
import tkinter as tk
from tkinter import *
from tkinter import messagebox

# For 2FA and QR Code
import pyotp
import qrcode

# For SHA256
import hashlib

# Pycryptodome for AES256
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class Application(Frame):
    def __init__(self, master):
        super().__init__(master)
        self.master = master
        self.entry_window_up = False
        self.password_database_up = False
        self.auth_code_valid = False
        self.password_entries = []

        login_window(self)


# -------------------------Helper Functions----------------------------#

# Validates each entry data of user input.
# Returns True if it's a valid entry, False otherwise
def validate_entry(entry, mode):
    match mode:
        case "password":
            if len(entry) < 8:
                messagebox.showwarning(title="Password Warning",
                                       message="Your password is less than 8 characcters, please make it more than 8 characters.")
                return False

        case "email":
            has_period = False
            period_pos = 0
            has_at = False
            at_pos = 0
            for i in range(0, len(entry)):
                if entry[i] == '.':
                    has_period = True
                    period_pos = i
                if entry[i] == '@':
                    has_at = True
                    at_pos = i

            if not (has_period and has_at) or at_pos > period_pos:
                messagebox.showwarning(title="Email Warning",
                                       message="Please enter a valid email.")
                return False

        case "website":
            has_period = False
            for char in entry:
                if char == '.':
                    has_period = True

            if not has_period:
                messagebox.showwarning(title="Website Warning",
                                       message="Please enter a valid website.")
                return False

        case "not_empty":
            if len(entry) < 1:
                messagebox.showwarning(title="Empty Entry",
                                       message="One of your entry fields is empty, please put something in them.")
                return False

        case _:
            messagebox.showwarning(title="Program Error",
                                   message="Validation function has it's mode set to: " + mode + ".\n" +
                                           "Valid modes are: website, email, password, and not_empty.")
            return False

    return True


# Uses the SHA256 Hash to hash the email mostly to get a unique ID
# Returns a hex value string of the hashed data
def sha256_hash(data):
    hash = hashlib.new("SHA256")
    hash.update(binascii.a2b_qp(data))
    return hash.hexdigest()


# Encrypt and Decrypt functions. Uses the AES256 algorithm with the
# CBC Cipher.
# Returns the encrypted IV and data in base64
def encrypt_data(self, data):
    keyfile = open("Keys/" + self.current_account + ".tex", "r+")
    userkey = b64decode(keyfile.readline().strip())
    keyfile.close()

    bin_data = binascii.a2b_qp(data)
    cipher = AES.new(userkey, AES.MODE_CBC)
    cipher_data = cipher.encrypt(pad(bin_data, AES.block_size))

    iv_64 = b64encode(cipher.iv).decode('utf-8')
    data_64 = b64encode(cipher_data).decode('utf-8')
    return iv_64 + data_64


# Decrypts data from the encypted data passed to it
# Returns the decryped data in plaintext
def decrypt_data(self, data):
    # Get the Key from the stored Key file
    keyfile = open("Keys/" + self.current_account + ".tex", "r+")
    userkey = b64decode(keyfile.readline().strip())
    keyfile.close()

    # Extract the encrypted IV and data from the passed in data
    e_iv = data[0:24]
    e_data = data[24:]

    # Transform the encrypted IV and data into it's binary form
    d_iv = b64decode(e_iv)
    d_data = b64decode(e_data)

    # Decrypt the data using the IV
    cipher = AES.new(userkey, AES.MODE_CBC, iv=d_iv)
    d_data2 = unpad(cipher.decrypt(d_data), AES.block_size)
    return d_data2.decode("utf-8")


# Refreshes the Password Manager window to display all of the
# website/email/password combinations
def reload_password_database_entries(self, userfilename, current_window):
    # Gets only the entry contents of the Password Database
    userfile = open(userfilename, "r+")
    lines = userfile.readlines()
    lines.pop(0)  # Ignore the encryped password for the user
    lines.pop(0)  # Ignore the encryped OTP key for that user

    # Deletes all of the visual aspects of the Database to rebuild it again
    for entry in self.password_entries:
        try:
            entry.grid_remove()
        except:
            pass
    self.password_entries.clear()

    # Actually builds the Database
    if len(lines) > 0:
        row_count = 1  # Keeps track of which row we are on

        # Builds each row entry in the Password Database window
        for i in range(0, int(len(lines) / 3)):
            website = decrypt_data(self, lines[i * 3].strip())
            email = decrypt_data(self, lines[(i * 3) + 1].strip())
            password = decrypt_data(self, lines[(i * 3) + 2].strip())

            # Website Entry
            website_entry = Text(master=current_window, height=1)
            website_entry.insert('1.0', website)
            website_entry.config(state=DISABLED)
            website_entry.place()
            website_entry.grid(row=row_count, column=0)

            # Email/Username Entry
            email_entry = Text(master=current_window, height=1)
            email_entry.insert('1.0', email)
            email_entry.config(state=DISABLED)
            email_entry.place()
            email_entry.grid(row=row_count, column=1)

            # Password Entry
            password_entry = Text(master=current_window, height=1)
            password_entry.insert('1.0', password)
            password_entry.config(state=DISABLED)
            password_entry.place()
            password_entry.grid(row=row_count, column=2)

            # Copy/Delete Buttons
            copy_button = Button(master=current_window, width=10, text="Copy",
                                 command=lambda row=row_count: copy_password(self, userfilename, row, current_window))
            copy_button.grid(row=row_count, column=3, sticky=N + E + S + W)
            delete_button = Button(master=current_window, width=10, text="DELETE",
                                   command=lambda row=row_count: delete_entry(self, userfilename, row, current_window))
            delete_button.grid(row=row_count, column=4, sticky=N + E + S + W)

            # Makes it so that the Website/Email/Password entries scale with window
            current_window.grid_columnconfigure(0, minsize=10, weight=1)
            current_window.grid_columnconfigure(1, minsize=10, weight=1)
            current_window.grid_columnconfigure(2, minsize=10, weight=1)

            # Keep each Entry/Buttons in a list
            self.password_entries.append(website_entry)
            self.password_entries.append(email_entry)
            self.password_entries.append(password_entry)
            self.password_entries.append(copy_button)
            self.password_entries.append(delete_button)

            # Go onto the next row
            row_count += 1

    pass


# Copies the passwords from the row the button it is clicked in
def copy_password(self, userfilename, row, current_window):
    # Get the userfile
    userfile = open(userfilename, "r+")
    lines = userfile.readlines()
    userfile.close()

    lines.pop(0)  # Ignore the encryped password for the user
    lines.pop(0)  # Ignore the encryped OTP key for that user

    entry_amount = 3
    password_offset = 2

    # Decrypt the password
    e_password = lines[((row - 1) * entry_amount) + password_offset].strip()
    d_password = decrypt_data(self, e_password)

    # Copy the decrypted password to our clipboard so we can CTRL+V
    current_window.clipboard_clear()
    current_window.clipboard_append(d_password)


# Deletes an entry of the password database
def delete_entry(self, userfilename, row, current_window):
    # Get the userfile
    userfile = open(userfilename, "r+")
    lines = userfile.readlines()
    userfile.close()

    entry_amount = 3
    pass_otp_offset = 2

    # Gets rid of the entry
    lines.pop(((row - 1) * entry_amount) + pass_otp_offset + 2)  # Password
    lines.pop(((row - 1) * entry_amount) + pass_otp_offset + 1)  # Email/User
    lines.pop(((row - 1) * entry_amount) + pass_otp_offset)  # Website

    # Rebuild our userfile
    open(userfilename, "w").close()  # Clears contents of file
    userfile = open(userfilename, "w")  # Writes the contents back to the file
    for line in lines:
        userfile.write(line)
    userfile.close()

    # Refreshes the Password Database
    reload_password_database_entries(self, userfilename, current_window)


# Extra settings to set when closing the Password Database window
def pass_database_window_close(self, window):
    self.password_database_up = False
    window.destroy()


# Extra settings to set when closing the Password Entry window
def entry_window_close(self, window):
    self.entry_window_up = False
    window.destroy()


# Deletes the Generated QR Code when we are done registering our account
def qrcode_window_register_close(window):
    os.remove("qrcode.png")
    window.destroy()


# ---------------------------- PASSWORD GENERATOR ------------------------------- #

# Generates a random password with scrambled characters mixed in
def generate_password(password_entry):
    letters = string.ascii_letters
    numbers = string.digits
    symbols = string.punctuation

    password_letters = [choice(letters) for _ in range(randint(10, 12))]
    password_symbols = [choice(symbols) for _ in range(randint(3, 4))]
    password_numbers = [choice(numbers) for _ in range(randint(3, 4))]

    password_list = password_letters + password_symbols + password_numbers
    shuffle(password_list)

    password = "".join(password_list)

    # Right here, we need to clear the password_entry component of it's data
    password_entry.delete(0, len(password_entry.get()))

    password_entry.insert(0, password)


# -------------------------------- SAVE PASSWORD ------------------------------- #
# Saves the Website/Username/Password combo into the Password Database
def save(self, website_entry, email_entry, password_entry):
    # Get the contents of the entries
    website = website_entry.get()
    email = email_entry.get()
    password = password_entry.get()

    # Validates the entries
    if (validate_entry(website, "website") and
            validate_entry(email, "not_empty") and
            validate_entry(password, "password")):

        # Confirm to user if it's ok to save the entries into the database
        is_ok = messagebox.askokcancel(title=website, message=f"These are the details entered: \nEmail: {email} "
                                                              f"\nPassword: {password} \nIs it ok to save?")
        if is_ok:
            with open(self.current_account + ".tex", "a") as data_file:
                data_file.write(encrypt_data(self, website) + "\n")
                data_file.write(encrypt_data(self, email) + "\n")
                data_file.write(encrypt_data(self, password) + "\n")

                website_entry.delete(0, END)
                password_entry.delete(0, END)

                data_file.close()
                data_file = self.current_account + ".tex"
                reload_password_database_entries(self, data_file, self.pass_database_window)


# -------------------------------- LOGIN ------------------------------- #
# Handles the login verification
def login(self, email_entry, password_entry):
    # Validates the email
    if not validate_entry(email_entry.get(), "not_empty"):
        return

    # Hashes the email and sets this user as our current user
    email_data = sha256_hash(email_entry.get().strip())
    self.current_account = email_data

    # Attempts to open our userfile for the user
    try:
        with open(email_data + ".tex", 'r') as userfile:
            e_password = userfile.readline().strip()
            userfile.close()
            d_password = decrypt_data(self, e_password)

            # Checks the password if they are a match
            if d_password == password_entry.get():

                # Pops up a Auth Code window for 2FA
                qr_window = qrcode_window_login(self).wait_window()
                if (self.auth_code_valid):
                    self.auth_code_valid = False  # Reset the value
                    password_entry_window(self)  # Login the user
                    self.master.withdraw()  # "Close" the login window

            else:
                messagebox.showwarning(title="Wrong Account",
                                       message="No account with that email/username and password combo.")

    # If a userfile does not exist for this user, then prompt to make a new account
    except Exception as e:
        traceback.print_exc()
        messagebox.showerror(title="Account Registered",
                             message="Account not found, please register for a new account.")


# -------------------------------- REGISTER ------------------------------- #
# Registers a new account to the Password Manager
# SHA256 the account name and AES256 encrypts the password with
# the key stored offsite (ideally) in the "Keys" folder.
# Generates a Google Authenticator QR Code for 2FA for the user
def register(self, email_entry, password_entry):
    # Validaiton check for email and password combo
    if not (validate_entry(email_entry.get(), "not_empty")
            and validate_entry(password_entry.get(), "password")):
        return

    # Hash email and save it as the current user
    hash_email = sha256_hash(email_entry.get().strip())
    self.current_account = hash_email

    # Generate Key for unique user from password and a random salt.
    salt = get_random_bytes(32)
    key = PBKDF2(password_entry.get(), salt, dkLen=32)
    key_b64 = b64encode(key).decode("utf-8")

    # Saves the Key and Account Settings for that user
    try:
        with open(hash_email + ".tex", 'r') as userfile:
            messagebox.showinfo(title="Already Registered", message="This account has been created, login instead.")
    except:
        # Generates a Key file for the user
        keyfile = open("Keys/" + hash_email + ".tex", "w+")
        keyfile.write(key_b64)
        keyfile.close()

        # Generates a userfile for the user
        # Stores the encrypted password to it
        userfile = open(hash_email + ".tex", 'w+')
        userfile.write(encrypt_data(self, password_entry.get()) + '\n')

        # QR Code generator for Authenticator and stores the Auth token
        otp_userkey = pyotp.random_base32()
        userfile.write(encrypt_data(self, otp_userkey) + "\n")
        totp = pyotp.TOTP(otp_userkey)
        uri = totp.provisioning_uri(name=email_entry.get(),
                                    issuer_name="Password Manager")
        qrcode.make(uri).save("qrcode.png")
        userfile.close()

        # Opens the window to show QR Code
        qrcode_window_register(self)


# -------------------------------- VERIFY AUTH ------------------------------- #
# Verifies the Auth Code from the user's Auth App
def verify_auth(self, auth_entry, email_entry, current_window):
    userfile = open(self.current_account + ".tex", "r")

    # Decrypt the Auth Token
    e_otp_key = userfile.readline().strip()
    e_otp_key = userfile.readline().strip()
    d_otp_key = decrypt_data(self, e_otp_key)

    # Do validation check of Auth Code from Auth App
    totp = pyotp.TOTP(d_otp_key)
    if totp.verify(auth_entry.get()):
        self.auth_code_valid = True

    else:
        messagebox.showwarning(title="Wrong Code",
                               message="You entered the wrong code, check your auth app again and check to see if it's the same.")

    current_window.destroy()


# ---------------------------- UI SETUP ------------------------------- #
# Builds and opens the Password Entry window
def password_entry_window(self):
    if (self.entry_window_up):
        return

    # Window Settings
    self.entry_window_up = True
    self.pass_entry_window = tk.Toplevel()
    self.pass_entry_window.title("Password Entry")
    self.pass_entry_window.config(padx=10, pady=10)
    self.pass_entry_window.focus_force()
    self.pass_entry_window.protocol("WM_DELETE_WINDOW", lambda: entry_window_close(self, self.master))

    # Icon image
    self.pass_entry_canvas = Canvas(master=self.pass_entry_window, height=200, width=200)
    self.pass_entry_logo_img = PhotoImage(master=self.pass_entry_window, file="ShallNotPassLogo.png")
    self.pass_entry_canvas.create_image(100, 100, image=self.pass_entry_logo_img)
    self.pass_entry_canvas.grid(row=0, column=1)

    # Labels
    self.pass_entry_website_label = Label(master=self.pass_entry_window, text="Website:", font="bold")
    self.pass_entry_website_label.grid(row=1, column=0)
    self.pass_entry_email_label = Label(master=self.pass_entry_window, text="Email/Username:", font="bold")
    self.pass_entry_email_label.grid(row=2, column=0)
    self.pass_entry_password_label = Label(master=self.pass_entry_window, text="Password:", font="bold")
    self.pass_entry_password_label.grid(row=3, column=0)

    # Entries
    self.pass_entry_website_entry = Entry(master=self.pass_entry_window, width=52)
    self.pass_entry_website_entry.focus()
    self.pass_entry_website_entry.grid(row=1, column=1, columnspan=2)
    self.pass_entry_email_entry = Entry(master=self.pass_entry_window, width=52)
    self.pass_entry_email_entry.grid(row=2, column=1, columnspan=2)
    self.pass_entry_password_entry = Entry(master=self.pass_entry_window, width=33)
    self.pass_entry_password_entry.grid(row=3, column=1)

    # Button
    self.pass_entry_open_pass_database_button = Button(master=self.pass_entry_window, text="Password Database",
                                                       command=lambda: password_database_window(self))
    self.pass_entry_open_pass_database_button.grid(row=4, column=0)
    self.pass_entry_generate_password_button = Button(master=self.pass_entry_window, text="Generate Password",
                                                      command=lambda: generate_password(self.pass_entry_password_entry))
    self.pass_entry_generate_password_button.grid(row=3, column=2)
    self.pass_entry_add_button = Button(master=self.pass_entry_window, text="Add", width=44,
                                        command=lambda: save(self, self.pass_entry_website_entry,
                                                             self.pass_entry_email_entry,
                                                             self.pass_entry_password_entry))
    self.pass_entry_add_button.grid(row=4, column=1, columnspan=2)


# Builds and opens the Login window
def login_window(self):
    # Window Settings
    self.master.title("Login")
    self.master.config(padx=20, pady=10)

    # Icon Image
    self.login_canvas = Canvas(master=self.master, height=200, width=200)
    self.login_logo_img = PhotoImage(master=self.master, file="ShallNotPassLogo.png")
    self.login_canvas.create_image(100, 100, image=self.login_logo_img)
    self.login_canvas.grid(row=0, column=1)

    # Labels
    self.login_email_label = Label(master=self.master, text="Email/Username:", font="bold")
    self.login_email_label.grid(row=1, column=0)
    self.login_password_label = Label(master=self.master, text="Password:", font="bold")
    self.login_password_label.grid(row=2, column=0)

    # Entries
    self.login_email_entry = Entry(master=self.master)
    self.login_email_entry.focus()
    self.login_email_entry.grid(row=1, column=1, columnspan=5, sticky=N + E + S + W)
    self.login_password_entry = Entry(master=self.master)
    self.login_password_entry.grid(row=2, column=1, columnspan=5, sticky=N + E + S + W)

    # Button
    self.login_login_button = Button(master=self.master, text="Login",
                                     command=lambda: login(self, self.login_email_entry, self.login_password_entry))
    self.login_login_button.grid(row=3, column=2, sticky=N + E + S + W)
    self.login_register_button = Button(master=self.master, text="Register",
                                        command=lambda: register(self, self.login_email_entry,
                                                                 self.login_password_entry))
    self.login_register_button.grid(row=3, column=4, sticky=N + E + S + W)


# Builds and opens the Password Database window
def password_database_window(self):
    if (self.password_database_up):
        self.pass_database_window.focus_force()
        return

    userfilename = self.current_account + ".tex"
    self.password_database_up = True

    # Window Settings
    self.pass_database_window = tk.Toplevel()
    self.pass_database_window.title("Password Database")
    self.pass_database_window.config(padx=10, pady=10)
    self.pass_database_window.geometry("800x500")
    self.pass_database_window.focus_force()
    self.pass_database_window.protocol("WM_DELETE_WINDOW",
                                       lambda: pass_database_window_close(self, self.pass_database_window))

    # Website Label
    self.pass_database_window_website_frame = Frame(master=self.pass_database_window)
    self.pass_database_window_website_label = Label(master=self.pass_database_window_website_frame, text="Website")
    self.pass_database_window_website_label.pack(side=LEFT)
    self.pass_database_window_website_frame.grid(row=0, column=0, sticky=W)

    # Email Label
    self.pass_database_window_email_frame = Frame(master=self.pass_database_window)
    self.pass_database_window_email_label = Label(master=self.pass_database_window_email_frame, text="Eamil/Username")
    self.pass_database_window_email_label.pack(side=LEFT)
    self.pass_database_window_email_frame.grid(row=0, column=1, sticky=W)

    # Password Label
    self.pass_database_window_password_frame = Frame(master=self.pass_database_window)
    self.pass_database_window_password_label = Label(master=self.pass_database_window_password_frame, text="Password")
    self.pass_database_window_password_label.pack(side=LEFT)
    self.pass_database_window_password_frame.grid(row=0, column=2, sticky=W)

    self.pass_database_window_frame = Frame(master=self.pass_database_window)
    self.pass_database_window_frame.grid(row=1, column=0, columnspan=3)

    # Builds the entries for the Password Database
    reload_password_database_entries(self, userfilename, self.pass_database_window)

    # Adjustable length sizes for the labels
    self.pass_database_window.grid_columnconfigure(0, minsize=10, weight=1)
    self.pass_database_window.grid_columnconfigure(1, minsize=10, weight=1)
    self.pass_database_window.grid_columnconfigure(2, minsize=10, weight=1)


# Builds and opens the initial QR Code window for users to scan
def qrcode_window_register(self):
    # Window Settings
    self.qrcode_window_register = tk.Toplevel()
    self.qrcode_window_register.title("Account Registered")
    self.qrcode_window_register.focus_force()
    self.qrcode_window_register.protocol("WM_DELETE_WINDOW",
                                         lambda: qrcode_window_register_close(self.qrcode_window_register))

    # Label
    self.qrcode_window_register_label = Label(master=self.qrcode_window_register,
                                              text="Your account has been registerd, please scan this QR code for your 2 Factor Auth and login again.")
    self.qrcode_window_register_label.grid(row=0, column=0)

    # QR Code Image
    self.qrcode_window_register_canvas = Canvas(master=self.qrcode_window_register, height=500, width=500)
    self.qrcode_window_register_img = PhotoImage(master=self.qrcode_window_register, file="qrcode.png")
    self.qrcode_window_register_canvas.create_image(250, 250, image=self.qrcode_window_register_img)
    self.qrcode_window_register_canvas.grid(row=1, column=0)


# Builds and opens the Auth Code window for users to type down the code from
# their Auth App
def qrcode_window_login(self):
    # WIndow Settings
    self.qrcode_window_login = tk.Toplevel()
    self.qrcode_window_login.title("Auth Code")
    self.qrcode_window_login.focus_force()

    # Label
    self.qrcode_window_login_label = Label(master=self.qrcode_window_login,
                                           text="Enter your auth code from your Authenticator App")
    self.qrcode_window_login_label.grid(row=0, column=0)

    # Entry
    self.qrcode_window_login_Entry = Entry(master=self.qrcode_window_login, width=20)
    self.qrcode_window_login_Entry.focus()
    self.qrcode_window_login_Entry.grid(row=1, column=0)

    # Confirmation Button
    self.qrcode_window_login_Button = Button(master=self.qrcode_window_login, text="Enter",
                                             command=lambda: verify_auth(self, self.qrcode_window_login_Entry,
                                                                         self.login_email_entry,
                                                                         self.qrcode_window_login))
    self.qrcode_window_login_Button.grid(row=2, column=0)

    return self.qrcode_window_login
