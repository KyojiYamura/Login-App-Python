import customtkinter as ctk
import sqlite3
import re
import socket
from datetime import datetime



class Start_window(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title('Test Application')
        self.geometry("300x350")
        self.custom_font = ctk.CTkFont()
        self.custom_font.configure(size=24, family="Rubik Maps")
        self.frame = ctk.CTkFrame(self)
        self.frame.pack(pady=20, padx=12, fill='both', expand=True)
        self.buttons()

    def buttons(self):
        self.login_button = ctk.CTkButton(self.frame, text='Login', command=lambda: self.open_login_window())
        self.login_button.pack(pady=20, padx=12)
        self.register_button = ctk.CTkButton(self.frame, text='Register', command=lambda: self.open_register_window())
        self.register_button.pack(pady=20, padx=12)

    def open_register_window(self):
        register_window = App_register()
        register_window.after(500, self.close_window)
        register_window.mainloop()

    def open_login_window(self):
        login_window = App_login()
        login_window.after(500, self.close_window)
        login_window.mainloop()

    def close_window(self):
        self.destroy()


class App_register(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title('Register')
        self.geometry("300x350")
        self.custom_font = ctk.CTkFont()
        self.custom_font.configure(size=24, family="Rubik Maps")
        self.frame = ctk.CTkFrame(self)
        self.frame.pack(pady=20, padx=12, fill='both', expand=True)

        self.label = ctk.CTkLabel(master=self.frame, text="Register", font=self.custom_font, fg_color="transparent")
        self.label.pack(pady=12, padx=10)

        self.username_entry = ctk.CTkEntry(master=self.frame, placeholder_text="Username", fg_color="transparent",
                                           width=150)
        self.username_entry.pack(pady=12, padx=10)

        self.email_entry = ctk.CTkEntry(master=self.frame, placeholder_text="Email", fg_color="transparent")
        self.email_entry.pack(pady=12, padx=10)

        self.password_entry = ctk.CTkEntry(master=self.frame, placeholder_text="Password", show="*",
                                           fg_color="transparent")
        self.password_entry.pack(pady=12, padx=10)

        self.submit_button = ctk.CTkButton(master=self.frame, text="Register", command=lambda: self.add_user(
            self.username_entry.get(), self.email_entry.get(), self.password_entry.get(),
            self.username_entry, self.email_entry, self.password_entry))
        self.submit_button.pack(pady=12, padx=10)

        self.result = ctk.CTkLabel(master=self.frame, text="")
        self.result.pack()

    def open_start_window(self):
        start_window = Start_window()
        start_window.after(2000, self.close_window)
        self.after(2000, start_window.mainloop())

    def close_window(self):
        self.destroy()

    def add_user(self, username, email, password, username_entry, email_entry, password_entry):
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()

        current_datetime = datetime.now()
        formatted_datetime = current_datetime.strftime("%Y-%m-%d %H:%M:%S")

        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)

        try:
            pattern_email = r'^[\w.-]+@([\w-]+\.)+[\w-]{2,4}$'
            pattern_password = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
            is_valid_email = re.match(pattern_email, email)
            is_valid_password = re.match(pattern_password, password)

            if is_valid_email and is_valid_password:
                if self.is_duplicate(username, email):
                    self.result.configure(text="Username or Email already exists.")
                else:


                    cursor.execute(
                        "INSERT INTO credentials (username, email, password, datetime,ip) VALUES (?, ?, ?,?,?)",
                        (username, email, password, formatted_datetime, ip_address))
                    conn.commit()

                    email_entry.configure(placeholder_text="Email")
                    password_entry.configure(placeholder_text="Password")
                    self.result.configure(text="Account successfully created!")
                    self.open_start_window()

            else:
                if not is_valid_email:
                    email_entry.configure(placeholder_text="Invalid email")
                    self.result.configure(text="Invalid email or password!")
                if not is_valid_password:
                    password_entry.configure(placeholder_text="Invalid Password", show="*")
                    self.result.configure(text="Invalid email or password!")

        finally:
            cursor.close()
            conn.close()

        username_entry.delete(0, 'end')
        email_entry.delete(0, 'end')
        password_entry.delete(0, 'end')

    def is_duplicate(self, username, email):
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()

        try:
            cursor.execute("SELECT COUNT(*) FROM credentials WHERE username = ? OR email = ?", (username, email))
            count = cursor.fetchone()[0]
            return count > 0
        finally:
            cursor.close()
            conn.close()


class App_login(ctk.CTk):
    user_id = 0

    def __init__(self):
        super().__init__()
        self.title('Register')
        self.geometry("300x350")
        self.custom_font = ctk.CTkFont()
        self.custom_font.configure(size=24, family="Rubik Maps")
        self.frame = ctk.CTkFrame(self)
        self.frame.pack(pady=20, padx=12, fill='both', expand=True)

        self.label = ctk.CTkLabel(master=self.frame, text="Login", font=self.custom_font, fg_color="transparent")
        self.label.pack(pady=12, padx=10)

        self.email_entry = ctk.CTkEntry(master=self.frame, placeholder_text="Email", fg_color="transparent")
        self.email_entry.pack(pady=12, padx=10)

        self.password_entry = ctk.CTkEntry(master=self.frame, placeholder_text="Password", show="*",
                                           fg_color="transparent")
        self.password_entry.pack(pady=12, padx=10)

        self.submit_button = ctk.CTkButton(master=self.frame, text="Login", command=lambda: self.login(
            self.email_entry.get(), self.password_entry.get(),
            self.email_entry, self.password_entry))
        self.submit_button.pack(pady=12, padx=10)

        self.result = ctk.CTkLabel(master=self.frame, text="")
        self.result.pack()

    def login(self, email, password, email_entry, password_entry):
        if self.user_exist(email, password):

            self.result.configure(text="Welcome")
            self.open_main_window()

        else:
            self.result.configure(text="Wrong credentials")

    def open_main_window(self):
        main_window = Main_window()
        main_window.after(2000, self.close_window)
        self.after(2000, main_window.mainloop())

    def close_window(self):
        self.destroy()

    def user_exist(self, email, password):
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()

        try:
            cursor.execute("SELECT id FROM credentials WHERE email = ? AND password = ?", (email, password))
            result = cursor.fetchone()
            if result:
                App_login.user_id = result[0]
                return True, App_login.user_id
        finally:
            cursor.close()
            conn.close()


class Main_window(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.user_id = App_login.user_id
        self.title('Welcome')
        self.geometry("1200x600")

        self.custom_font = ctk.CTkFont()
        self.custom_font.configure(size=24, family="Rubik Maps")

        self.frame_user = ctk.CTkFrame(self)
        self.frame_user.pack(pady=20, padx=12, fill='both', side='top')
        self.frame_user1 = ctk.CTkFrame(self.frame_user)
        self.frame_user1.pack(side="left", padx=100)
        self.frame_user2 = ctk.CTkFrame(self.frame_user)
        self.frame_user2.pack(side="left", padx=127, )
        self.frame_user3 = ctk.CTkFrame(self.frame_user)
        self.frame_user3.pack(side="left", padx=127, )

        self.frame_data_edit = ctk.CTkFrame(self, height=5)
        self.frame_data_edit.pack(pady=5, padx=12, fill='both', side='top')
        self.frame_data_edit1 = ctk.CTkFrame(self.frame_data_edit, height=5)
        self.frame_data_edit1.grid(column=0, row=0, padx=5)
        self.frame_data_edit2 = ctk.CTkFrame(self.frame_data_edit, height=5)
        self.frame_data_edit2.grid(column=1, row=0, padx=140)
        self.frame_data_edit3 = ctk.CTkFrame(self.frame_data_edit, height=5)
        self.frame_data_edit3.grid(column=2, row=0, padx=50)

        self.frame_table = ctk.CTkFrame(self, height= 400)
        self.frame_table.pack(pady=20, padx=12, fill='both')

        self.button_change_username = ctk.CTkButton(master=self.frame_data_edit1, text="Change Username",
                                                    command=lambda: self.change_username(self.user_id))
        self.button_change_email = ctk.CTkButton(master=self.frame_data_edit1, text="Change Email",
                                                 command=lambda: self.change_email(self.user_id))
        self.button_change_password = ctk.CTkButton(master=self.frame_data_edit1, text="Change Password",
                                                    command=lambda: self.change_password(self.user_id))
        self.button_change_username.grid(column=0, row=0, padx=9)
        self.button_change_email.grid(column=1, row=0, padx=9)
        self.button_change_password.grid(column=2, row=0, padx=9)
        self.button_make_admin = ctk.CTkButton(master=self.frame_data_edit3, text="Admin",
                                               command=lambda: self.admin_login(self.user_id))
        self.button_make_admin.pack(side='right')

        self.textbox = ctk.CTkTextbox(master=self.frame_table, font=self.custom_font, height= 350 )
        self.textbox.pack(pady=5, padx=12, fill='both', side='top')

        self.print_button = ctk.CTkButton(master=self.frame_table, text="Show Users", command=lambda: self.adminview(
            self.user_id))
        self.print_button.pack()

        user_info = self.get_user_info(self.user_id)
        if user_info:
            self.label_user_id = ctk.CTkLabel(master=self.frame_user1, text=f"User ID: {user_info['id']}",
                                              font=self.custom_font)
            self.label_user_id.pack()

            self.label_username = ctk.CTkLabel(master=self.frame_user2, text=f"Username: {user_info['username']}",
                                               font=self.custom_font)
            self.label_username.pack()

            self.label_admin = ctk.CTkLabel(master=self.frame_user3, text=f"Admin: {user_info['admin']}",
                                            font=self.custom_font)
            self.label_admin.pack()

    def get_user_info(self, user_id):
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()

        try:
            cursor.execute("SELECT id, username, admin FROM credentials WHERE id = ?", (user_id,))
            result = cursor.fetchone()

            if result:
                user_id, username, admin = result
                return {"id": user_id, "username": username, "admin": bool(admin)}
            else:
                # No match found
                return None

        finally:
            cursor.close()
            conn.close()

    def adminview(self, user_id):
        user_info = self.get_user_info(user_id)

        if user_info and user_info.get("admin"):
            try:
                conn = sqlite3.connect('database.db')
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM credentials")
                rows = cursor.fetchall()
                column_names = [description[0] for description in cursor.description]
                formatted_data = []
                formatted_data.append(column_names)
                formatted_data.extend(rows)

                table_string = "\n".join([" | ".join(map(str, row)) for row in formatted_data])
                self.textbox.delete(1.0, ctk.END)
                self.textbox.insert(ctk.END, table_string)
            finally:
                if conn:
                    conn.close()
        else:
            table_string = "Access denied. User is not an admin."
            self.textbox.delete(1.0, ctk.END)
            self.textbox.insert(ctk.END, table_string)

    def admin_login(self, user_id):
        user_info = self.get_user_info(user_id)
        admin_password = "Admin123"

        if user_info and not user_info.get("admin"):
            admin_window = ctk.CTkInputDialog(text="Type in admin password:", title="Admin Login", )
            entered_password = admin_window.get_input()
            while True:
                if entered_password is None:
                    break

                if entered_password == admin_password:
                    self.set_admin(user_id)
                    self.label_admin.configure(text=f"Admin: {True}")
                    break
                else:
                    admin_window = ctk.CTkInputDialog(text="Error: Wrong password", title="Admin Login", )
                    entered_password = admin_window.get_input()

    def set_admin(self, user_id):
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()

        try:
            cursor.execute("UPDATE credentials SET admin = ? WHERE id = ?", (1, user_id))
            conn.commit()
        finally:
            cursor.close()
            conn.close()

    def is_duplicate_username(self, username):
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()

        try:
            cursor.execute("SELECT COUNT(*) FROM credentials WHERE username = ? ", (username,))
            count = cursor.fetchone()[0]
            return count > 0
        finally:
            cursor.close()
            conn.close()

    def change_username(self, user_id):
        admin_window = ctk.CTkInputDialog(text="Enter new username: ", title="Change username")
        new_username = admin_window.get_input()
        while True:

            if self.is_duplicate_username(new_username):
                admin_window = ctk.CTkInputDialog(
                    text="Error: Username already exists. Please choose a different username.", title="Change username")
                new_username = admin_window.get_input()
            else:

                self.set_username(new_username, user_id)
                self.label_username.configure(text=f"Username: {new_username}")
                break

    def set_username(self, new_username, user_id):
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()

        try:
            cursor.execute("UPDATE credentials SET username = ? WHERE id = ?", (new_username, user_id))
            conn.commit()
        finally:
            cursor.close()
            conn.close()

    def is_duplicate_email(self, email):
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()

        try:
            cursor.execute("SELECT COUNT(*) FROM credentials WHERE email = ? ", (email,))
            count = cursor.fetchone()[0]
            return count > 0
        finally:
            cursor.close()
            conn.close()

    def change_email(self, user_id):
        admin_window = ctk.CTkInputDialog(text="Enter new email: ", title="Change email")
        new_email = admin_window.get_input()
        while True:
            if self.is_duplicate_email(new_email):
                admin_window = ctk.CTkInputDialog(text="Error: Email already exists. Please choose a different email.",
                                                  title="Change email")
                new_email = admin_window.get_input()

            elif not re.match(r'^[\w.-]+@([\w-]+\.)+[\w-]{2,4}$', new_email):
                admin_window = ctk.CTkInputDialog(text="Error: Invalid email format. Please enter a valid email.",
                                                  title="Change email")
                new_email = admin_window.get_input()

            else:
                self.set_email(new_email, user_id)
                self.label_email.configure(text=f"Email: {new_email}")
                break

    def set_email(self, new_email, user_id):
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()

        try:
            cursor.execute("UPDATE credentials SET email = ? WHERE id = ?", (new_email, user_id))
            conn.commit()
        finally:
            cursor.close()
            conn.close()

    def change_password(self, user_id):
        admin_window = ctk.CTkInputDialog(text="Enter new password: ", title="Change password")
        new_password = admin_window.get_input()
        while True:
            if re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$", new_password):
                self.set_password(new_password, user_id)
                break

            else:
                admin_window = ctk.CTkInputDialog(text="Error: Invalid password ", title="Change password")
                new_password = admin_window.get_input()

    def set_password(self, new_password, user_id):
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()

        try:
            cursor.execute("UPDATE credentials SET password = ? WHERE id = ?", (new_password, user_id))
            conn.commit()
        finally:
            cursor.close()
            conn.close()


start_window = Start_window()
start_window.mainloop()
