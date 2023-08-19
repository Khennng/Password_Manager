import tkinter as tk
from tkinter import *
from tkinter import ttk
from tkinter import messagebox
from random import choice, randint, shuffle
import string
import pyotp
import qrcode
import traceback

# TODO:
# 1. Reload the password manager when an entry gets entered into the database
# 2. Make sure when both the password manager and password entry closes, close
#    the whole program itself. Exit function should be fine I think?
# 3.
#
#
#

class Application(Frame):
    def __init__(self, master):
        super().__init__(master)
        self.master = master
        self.master.title("Login")
        self.hextable = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F']

        self.entry_window_up = True
        self.password_manager_up = True
        self.auth_code_valid = False
        self.current_account = ""
        self.password_entry_width = 25
        self.password_entry_height = 1

        login_window(self)

# -------------------------Helper Functions----------------------------#

# This will check to see if there's any spaces or pipe characters in
# the entry so it doesn't mess up our delimiter when we retrieve data back
# from the database
def validate_entry(entry):
    for i in range(0, len(entry)):
        if entry[i] == ' ' or entry[i] == '|':
            return False
    return True

# Encrypt and Decrypt functions. Uses the XOR bitwise operator to scramble
# data back and forth from the database to the user.
def encrypt_data(self, data):
    byte_array = bytes(data, 'ascii')
    e_data = ""
    for byte in byte_array:
        byte = byte ^ 0xFF

        upper_bits = (byte >> 4)
        lower_bits = (byte & 0x0F)

        upper_hexvalue = self.hextable[upper_bits]
        lower_hexvalue = self.hextable[lower_bits]

        e_data = e_data + upper_hexvalue + lower_hexvalue
    return e_data

def decrypt_data(self, data):
    byte_array = bytes(data, 'ascii')
    d_data = ""
    for i in range(0, int(len(data)/2)):
        upper_bits = data[i*2]
        lower_bits = data[(i*2)+1]

        byte = int(upper_bits + lower_bits, 16)

        char = chr(byte ^ 0xFF)

        d_data = d_data + char
    return d_data

    pass

def reload_password_manager_entries(self, userfile, current_window):
    lines = userfile.readlines()
    lines.pop(0) # Ignore the encryped password for the user
    lines.pop(0) # Ignore the encryped OTP key for that user

    self.password_entries = []

    if len(lines) > 0:
        row_count = 1
        for line in lines:
            entry_array = line.split(" | ")
            website = decrypt_data(self, entry_array[0].strip())
            email = decrypt_data(self, entry_array[1].strip())
            password = decrypt_data(self, entry_array[2].strip())
            print(website + " | " + email + " | " + password)

            website_entry = Text(master=current_window, height=self.password_entry_height)
            website_entry.insert('1.0', website)
            website_entry.config(state=DISABLED)
            website_entry.place()
            website_entry.grid(row=row_count, column=0)
            email_entry = Text(master=current_window, height=self.password_entry_height)
            email_entry.insert('1.0', email)
            email_entry.config(state=DISABLED)
            email_entry.place()
            email_entry.grid(row=row_count, column=1)
            password_entry = Text(master=current_window, height=self.password_entry_height)
            password_entry.insert('1.0', password)
            password_entry.config(state=DISABLED)
            password_entry.place()
            password_entry.grid(row=row_count, column=2)

            copy_button = Button(master=current_window, width=10, text="Copy", command=lambda: copy_password(self, userfile, row_count))
            copy_button.grid(row=row_count, column=3, sticky=N+E+S+W)
            delete_button = Button(master=current_window, width=10, text="DELETE", command=lambda: delete_entry(self, userfile, website_entry, email_entry, password_entry))
            delete_button.grid(row=row_count, column=4, sticky=N+E+S+W)

            current_window.grid_columnconfigure(0, minsize=10, weight=1)
            current_window.grid_columnconfigure(1, minsize=10, weight=1)
            current_window.grid_columnconfigure(2, minsize=10, weight=1)

            self.password_entries.append(website_entry)
            self.password_entries.append(email_entry)
            self.password_entries.append(password_entry)
            self.password_entries.append(copy_button)
            self.password_entries.append(delete_button)

            row_count += 1

    pass

def copy_password(self, userfile, row_count):

    pass

def delete_entry(self, userfile, webiste_entry, email_entry, password_entry):
    pass

# ---------------------------- PASSWORD GENERATOR ------------------------------- #

# Password Generator Project

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

    #####
    # Right here, we need to clear the password_entry component of it's data
    password_entry.delete(0, len(password_entry.get()))
    #####

    password_entry.insert(0, password)
    # pyperclip.copy(password)


# -------------------------------- SAVE PASSWORD ------------------------------- #
def save(self, website_entry, email_entry, password_entry):
    website = website_entry.get()
    email = email_entry.get()
    password = password_entry.get()

    valid_length = len(website) > 0 or len(email) > 0 or len(password) > 0
    valid_entry = validate_entry(website) and validate_entry(email) and validate_entry(password)

    if not valid_length or not valid_entry:
        messagebox.showinfo(title="Ooops", message="Please make sure you haven't left any fields empty.")
    else:
        is_ok = messagebox.askokcancel(title=website, message=f"These are the details entered: \nEmail: {email} "
                                                              f"\nPassword: {password} \nIs it ok to save?")
        if is_ok:
            with open(encrypt_data(self, self.current_account) + ".tex", "a") as data_file:
                data_file.write(f"{encrypt_data(self, website)} | {encrypt_data(self, email)} | {encrypt_data(self, password)}\n")
                website_entry.delete(0, END)
                password_entry.delete(0, END)

                data_file.close()
                data_file = open(encrypt_data(self, self.current_account) + ".tex", "r+")
                reload_password_manager_entries(self, data_file, self.pass_man_window)

# -------------------------------- LOGIN ------------------------------- #

def login(self, email_entry, password_entry):
    email_data = encrypt_data(self, email_entry.get())
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
                    self.current_account = email_entry.get()
                    self.auth_code_valid = False # Reset the value
                    # Also open up the password manager database itself
                    password_entry_window(self)
                    password_manager_window(self)
                    self.master.withdraw()


            else:
                #Wrong password, need to display the do not pass image
                pass


    except Exception as e:
        traceback.print_exc()
        messagebox.showerror(title="Account Registered",
                            message="Account not found, please register for a new account.")
    return

# -------------------------------- REGISTER ------------------------------- #

def register(self, email_entry, password_entry):
    email_data = encrypt_data(self, email_entry.get())
    try:
        with open(email_data + ".tex", 'r') as userfile:
            messagebox.showinfo(title="Already Registered", message="This account has been created, login instead.")
    except:
        userfile = open(email_data + ".tex", 'w+')
        userfile.write(encrypt_data(self, password_entry.get()) + '\n')

        otp_userkey = pyotp.random_base32()
        userfile.write(encrypt_data(self, otp_userkey) + "\n")
        totp = pyotp.TOTP(otp_userkey)
        uri = totp.provisioning_uri(name=email_entry.get(),
                                    issuer_name="Password Manager")
        qrcode.make(uri).save("qrcode.png")
        userfile.close()
        qrcode_window_register(self)

# -------------------------------- VERIFY AUTH ------------------------------- #

def verify_auth(self, auth_entry, email_entry, current_window):
    e_email = encrypt_data(self, email_entry.get())
    userfile = open(e_email + ".tex", "r")

    e_otp_key = userfile.readline().strip()
    e_otp_key = userfile.readline().strip()
    d_otp_key = decrypt_data(self, e_otp_key)

    totp = pyotp.TOTP(d_otp_key)
    if totp.verify(auth_entry.get()):
        self.auth_code_valid = True
        current_window.destroy()


    else:
        messagebox.showwarning(title="Wrong Code", message="You entered the wrong code, check your auth app again and check to see if it's the same.")


# ---------------------------- UI SETUP ------------------------------- #

def password_entry_window(self):
    self.entry_window_up = True

    self.pass_entry_window = tk.Tk()
    self.pass_entry_window.title("Password Entry")
    self.pass_entry_window.config(padx=10, pady=10)

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
    self.pass_entry_website_entry.grid(row=1, column=1, columnspan=2)
    self.pass_entry_email_entry = Entry(master=self.pass_entry_window, width=52)
    self.pass_entry_email_entry.grid(row=2, column=1, columnspan=2)
    self.pass_entry_password_entry = Entry(master=self.pass_entry_window, width=33)
    self.pass_entry_password_entry.grid(row=3, column=1)

    # Button
    self.pass_entry_generate_password_button = Button(master=self.pass_entry_window, text="Generate Password", command=lambda: generate_password(self.pass_entry_password_entry))
    self.pass_entry_generate_password_button.grid(row=3, column=2)
    self.pass_entry_add_button = Button(master=self.pass_entry_window, text="Add", width=44, command=lambda: save(self, self.pass_entry_website_entry, self.pass_entry_email_entry, self.pass_entry_password_entry))
    self.pass_entry_add_button.grid(row=4, column=1, columnspan=2)

def login_window(self):
    self.master.title("Login")
    self.master.config(padx=20, pady=10)

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
    self.login_email_entry.grid(row=1, column=1, columnspan=5, sticky=N+E+S+W)
    self.login_password_entry = Entry(master=self.master)
    self.login_password_entry.grid(row=2, column=1, columnspan=5, sticky=N+E+S+W)

    # Button
    self.login_login_button = Button(master=self.master, text="Login", command=lambda: login(self, self.login_email_entry, self.login_password_entry))
    self.login_login_button.grid(row=3, column=2, sticky=N+E+S+W)
    self.login_register_button = Button(master=self.master, text="Register", command=lambda: register(self, self.login_email_entry, self.login_password_entry))
    self.login_register_button.grid(row=3, column=4, sticky=N+E+S+W)

def password_manager_window(self):
    userfile = open(encrypt_data(self, self.current_account) + ".tex", "r+")
    self.password_manager_up = True

    self.pass_man_window = tk.Tk()
    self.pass_man_window.title("Password Manager")
    self.pass_man_window.config(padx=10, pady=10)
    self.pass_man_window.geometry("800x500")

    self.pass_man_window_website_frame = Frame(master=self.pass_man_window)
    self.pass_man_window_website_label = Label(master=self.pass_man_window_website_frame, text="Website")
    self.pass_man_window_website_label.pack(side=LEFT)
    self.pass_man_window_website_frame.grid(row=0, column=0, sticky=W)

    self.pass_man_window_email_frame = Frame(master=self.pass_man_window)
    self.pass_man_window_email_label = Label(master=self.pass_man_window_email_frame, text="Eamil/Username")
    self.pass_man_window_email_label.pack(side=LEFT)
    self.pass_man_window_email_frame.grid(row=0, column=1, sticky=W)

    self.pass_man_window_password_frame = Frame(master=self.pass_man_window)
    self.pass_man_window_password_label = Label(master=self.pass_man_window_password_frame, text="Password")
    self.pass_man_window_password_label.pack(side=LEFT)
    self.pass_man_window_password_frame.grid(row=0, column=2, sticky=W)

    self.pass_mam_window_frame = Frame(master=self.pass_man_window)
    self.pass_mam_window_frame.grid(row=1, column=0, columnspan=3)

    reload_password_manager_entries(self, userfile, self.pass_mam_window_frame)

    self.pass_man_window.grid_columnconfigure(0, minsize=10, weight=1)
    self.pass_man_window.grid_columnconfigure(1, minsize=10, weight=1)
    self.pass_man_window.grid_columnconfigure(2, minsize=10, weight=1)

def qrcode_window_register(self):
    self.qrcode_window_register = tk.Tk()
    self.qrcode_window_register.title("Account Registered")

    self.qrcode_window_register_label = Label(master=self.qrcode_window_register, text="Your account has been registerd, please scan this QR code for your 2 Factor Auth and login again.")
    self.qrcode_window_register_label.grid(row=0, column=0)

    self.qrcode_window_register_canvas = Canvas(master=self.qrcode_window_register, height=500, width=500)
    self.qrcode_window_register_img = PhotoImage(master=self.qrcode_window_register, file="qrcode.png")
    self.qrcode_window_register_canvas.create_image(250, 250, image=self.qrcode_window_register_img)
    self.qrcode_window_register_canvas.grid(row=1, column=0)

def qrcode_window_login(self):
    self.qrcode_window_login = tk.Tk()
    self.qrcode_window_login.title("Auth Code")

    self.qrcode_window_login_label = Label(master=self.qrcode_window_login, text="Enter your auth code from your Authenticator App")
    self.qrcode_window_login_label.grid(row=0, column=0)
    self.qrcode_window_login_Entry = Entry(master=self.qrcode_window_login, width=20)
    self.qrcode_window_login_Entry.grid(row=1, column=0)
    self.qrcode_window_login_Button = Button(master=self.qrcode_window_login, text="Enter", command=lambda: verify_auth(self, self.qrcode_window_login_Entry, self.login_email_entry, self.qrcode_window_login))
    self.qrcode_window_login_Button.grid(row=2, column=0)

    return self.qrcode_window_login