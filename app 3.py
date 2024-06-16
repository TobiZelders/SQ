import re
import os
import bcrypt
import sqlite3
import npyscreen
import datetime
import base64
import zipfile
from datetime import datetime, timedelta
from cryptography.fernet import Fernet

# --------------------------------------------------------- Paths ----------------------------------------------------------------

data_directory = "./AppFiles/"
db_name = "unique-meal.db"

log_path = os.path.join(data_directory, "log.txt")
key_path = os.path.join(data_directory, "key_file.key")

# --------------------------------------------------------- Login ----------------------------------------------------------------

class Logger:
    @staticmethod
    def log(log_line):
        with open(log_path, 'a') as log_file:
            log_file.write(base64.b64encode(Logger.encrypt_data(log_line)).decode() + "\n")
            log_file.flush()

    @staticmethod
    def encrypt_data(string_to_encrypt):
        with open(key_path, 'rb') as key_file:
            key = key_file.read()

        fernet = Fernet(key)

        encoded_string = string_to_encrypt.encode()
        encrypted_data = fernet.encrypt(encoded_string)

        return encrypted_data


class LoginForm(npyscreen.ActionForm):
    def create(self):
        self.username = self.add(npyscreen.TitleText, name='Username:')
        self.password = self.add(npyscreen.TitlePassword, name='Password:')

        self.add(npyscreen.FixedText, value="Use Ok to login and Cancel to exit", rely=7)

    def validate_input(self):
        if self.username.value != "super_admin":
            username_pattern =  r'^(?=[a-zA-Z_])(?!.*(_)\1)(?!.*[a-zA-Z0-9_.\'&]{11,})([a-zA-Z0-9_.\'&]{8,10})$'
            if not re.match(username_pattern, self.username.value):
                raise ValueError("Invalid credentials")

        if self.password.value != "Admin_123?":
            password_pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[~!@#$%&amp;_\-+=`|\\(){}[\]:;'<>,.?/]).{12,30}$"
            if not re.match(password_pattern, self.password.value):
                raise ValueError("Invalid credentials")

    def fetch_user(self):
        self.validate_input()

        cursor.execute("SELECT * FROM users WHERE LOWER(username) = ?", (self.username.value.lower(),))

        user = cursor.fetchone()

        if not user:
            raise ValueError("Invalid credentials")

        return user

    def fetch_login_attempts(self):
        user = self.fetch_user()

        cursor.execute("SELECT * FROM users WHERE LOWER(username) = ?", (self.username.value.lower(),))
        attempts = cursor.fetchone()[9]

        return attempts

    def validate_password(self):
        user = self.fetch_user()
        
        current_date = datetime.now().date()
        current_time = datetime.now().strftime('%H:%M')

        suspicious = "Yes" if int(user[9]) >= 3 else "No"

        if not bcrypt.checkpw(self.password.value.encode('utf-8'), user[2].encode('utf8')):
            attempts = int(self.fetch_login_attempts()) + 1

            cursor.execute("UPDATE users SET failed_attempts = ? WHERE id = ?", (attempts, user[0]))
            conn.commit()

            log_line = f"{current_date}, {current_time}, {user[1]}, Failed login,  , {suspicious}"
            Logger.log(log_line)

            raise ValueError("Invalid credentials")

        if int(user[9]) >= 3:
            log_line = f"{current_date}, {current_time}, {user[1]}, Account blocked,  , {suspicious}"
            Logger.log(log_line)

            raise ValueError("Account blocked")

        if user[6] == 1:
            date_format = "%Y-%m-%d %H:%M:%S.%f"
            expire_date = datetime.strptime(user[7], date_format)

            if datetime.now() > expire_date:
                log_line = f"{current_date}, {current_time}, {user[1]}, Expired password login,  , {suspicious}"
                Logger.log(log_line)

                raise ValueError("Temporary password expired!")

    def clear_fields(self):
        for widget in self._widgets__:
            if isinstance(widget, npyscreen.TitleText):
                widget.value = ""

    def on_ok(self):
        try:
            self.validate_password()

            user = self.fetch_user()
            role = user[3]

            current_date = datetime.now().date()
            current_time = datetime.now().strftime('%H:%M')

            suspicious = "Yes" if user[9] > 3 else "No"

            log_line = f"{current_date}, {current_time}, {user[1]}, Succesfull login,  , {suspicious}"
            Logger.log(log_line)

            cursor.execute('INSERT INTO active_user (username, role) VALUES (?, ?)', (user[1], user[3]))
            conn.commit()

            if role == "CONSULTANT":
                self.clear_fields()
                self.parentApp.switchForm("CONSULTANTS MENU")
            elif role == "SYSTEM ADMIN":
                self.clear_fields()
                self.parentApp.switchForm("SYSTEM ADMINS MENU")
            elif role == "SUPER ADMIN":
                self.clear_fields()
                self.parentApp.switchForm("SUPER ADMINS MENU")
        except ValueError as e:
            npyscreen.notify_confirm(str(e), title="Error", wrap=True)
            self.clear_fields()

    def on_cancel(self):
        cursor.execute('DELETE FROM active_user;')
        conn.commit()
        
        conn.close()
        self.parentApp.switchForm(None)

# --------------------------------------------------------- Member Actions ----------------------------------------------------------------

class AddMemberForm(npyscreen.ActionForm):
    european_cities = ['London', 'Paris', 'Berlin', 'Madrid', 'Rome', 'Amsterdam', 'Vienna', 'Prague', 'Barcelona', 'Dublin']
    
    def create(self):
        self.first_name = self.add(npyscreen.TitleText, name='First Name:')
        self.last_name = self.add(npyscreen.TitleText, name='Last Name:')
        self.age = self.add(npyscreen.TitleText, name='Age:')
        self.gender = self.add(npyscreen.TitleText, name='Gender:')
        self.weight = self.add(npyscreen.TitleText, name='Weight(kg):')
        self.street_name = self.add(npyscreen.TitleText, name='Street Name:')
        self.house_number = self.add(npyscreen.TitleText, name='House Number:')
        self.zip_code = self.add(npyscreen.TitleText, name='Zip Code:')
        self.city = self.add(npyscreen.TitleText, name='City:', values=self.european_cities)
        self.email_address = self.add(npyscreen.TitleText, name='Email:')
        self.mobile_phone = self.add(npyscreen.TitleText, name='Mobile Phone:')

        self.add(npyscreen.FixedText, value="Use Ok to create member or Cancel to go back", rely=15)

    def validate_input(self):
        letters_only_pattern = r'^[a-zA-Z]+$'

        if not re.match(letters_only_pattern, self.first_name.value):
            raise ValueError("Invalid first name: Only letters allowed")

        if not re.match(letters_only_pattern, self.last_name.value):
            raise ValueError("Invalid last name: Only letters allowed")

        age_pattern = r'^\d{1,3}$'
        if not re.match(age_pattern, self.age.value):
            if self.age.value.isdigit() and len(str(self.age.value)) > 3:
                raise ValueError("Invalid age: Max 3 digits allowed")
            else:
                raise ValueError("Invalid age: must be digits only")

        gender_pattern = r'^(Man|Women)$'
        if not re.match(gender_pattern, self.gender.value):
            raise ValueError("Invalid gender: Gender must be 'Man' or 'Women'")

        weight_pattern = r'^\d{1,3}$'
        if not re.match(weight_pattern, self.weight.value):
            if self.weight.value.isdigit() and len(str(self.weight.value)) > 3:
                raise ValueError("Invalid weight: Max 3 digits allowed")
            else:
                raise ValueError("Invalid weight: must a digits only")

        if not re.match(letters_only_pattern, self.street_name.value):
            raise ValueError("Invalid street name: Only letters allowed")

        house_number_patterm = r'^\d+[a-zA-Z]*$'
        if not re.match(house_number_patterm, self.house_number.value):
            raise ValueError("Invalid house number: a house number can only has digits and letters and must start with a digit")

        zip_code_pattern = r'^\d{4}[a-zA-Z]{2}$'
        if not re.match(zip_code_pattern, self.zip_code.value):
            raise ValueError("Invalid emazip code. zip code must be as followed DDDDXX")

        if self.city.value not in self.european_cities:
            raise ValueError("Invalid city")

        email_pattern = r'^[a-zA-Z0-9._-]+@[a-zA-Z0-9-]+\.[a-z]+$'
        if not re.match(email_pattern, self.email_address.value):
            raise ValueError("Invalid email address format. Please enter a valid email address in the format [a-z]+@[a-z]+\.[a-z]")

        mobile_phone_pattern = r'^\d{8}$'
        if not re.match(mobile_phone_pattern, self.mobile_phone.value):
            raise ValueError("Invalid phone number format. Please enter a valid mobile number in the format DDDDDDDD where D stands for one digit")

    def add_member(self):
        self.validate_input()

        cursor.execute("SELECT * FROM members WHERE first_name = ? and last_name = ?", (self.first_name.value, self.last_name.value))
        member = cursor.fetchone()

        if member:
            raise ValueError("Member already exists")

        cursor.execute('INSERT INTO members (first_name, last_name, age, gender, weight, street_name, house_number, zip_code, city, email_address, mobile_phone) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        (self.first_name.value, self.last_name.value, self.age.value, self.gender.value, self.weight.value, self.street_name.value, self.house_number.value, self.zip_code.value, self.city.value, self.email_address.value, self.mobile_phone.value))
        
        conn.commit()

    def clear_fields(self):
        for widget in self._widgets__:
            if isinstance(widget, npyscreen.TitleText):
                widget.value = ""

    def on_ok(self):
        try:
            self.add_member()
            npyscreen.notify_confirm(f"Added member: {self.first_name.value} {self.last_name.value}", title="Success", wrap=True)

            self.clear_fields()

        except ValueError as e:
            npyscreen.notify_confirm(str(e), title="Error", wrap=True)

    def on_cancel(self):
        self.clear_fields()
        self.parentApp.switchFormPrevious()

class ModifyMemberForm(npyscreen.ActionForm):
    european_cities = ['London', 'Paris', 'Berlin', 'Madrid', 'Rome', 'Amsterdam', 'Vienna', 'Prague', 'Barcelona', 'Dublin']

    def create(self):
        self.first_name = self.add(npyscreen.TitleText, name='First Name:')
        self.last_name = self.add(npyscreen.TitleText, name='Last Name:')

        self.add(npyscreen.FixedText, value="New values for member:", rely=5)

        self.modified_first_name = self.add(npyscreen.TitleText, name='First Name:', rely=7)
        self.modified_last_name = self.add(npyscreen.TitleText, name='Last Name:')
        self.modified_age = self.add(npyscreen.TitleText, name='Age:')
        self.modified_gender = self.add(npyscreen.TitleText, name='Gender:')
        self.modified_weight = self.add(npyscreen.TitleText, name='Weight(kg):')
        self.modified_street_name = self.add(npyscreen.TitleText, name='Street Name:')
        self.modified_house_number = self.add(npyscreen.TitleText, name='House Number:')
        self.modified_zip_code = self.add(npyscreen.TitleText, name='Zip Code:')
        self.modified_city = self.add(npyscreen.TitleText, name='City:', values=self.european_cities)
        self.modified_email_address = self.add(npyscreen.TitleText, name='Email:')
        self.modified_mobile_phone = self.add(npyscreen.TitleText, name='Mobile Phone:')
    
        self.add(npyscreen.FixedText, value="Use Ok to modify member or Cancel to go back", rely=20)

    def validate_input(self):
        letters_only_pattern = r'^[a-zA-Z]+$'

        if not re.match(letters_only_pattern, self.first_name.value):
            raise ValueError("Invalid first name: Only letters allowed")

        if not re.match(letters_only_pattern, self.last_name.value):
            raise ValueError("Invalid last name: Only letters allowed")

        if self.modified_first_name.value != "":
            if not re.match(letters_only_pattern, self.modified_first_name.value):
                raise ValueError("Invalid first name: Only letters allowed")

        if self.modified_last_name.value != "":
            if not re.match(letters_only_pattern, self.modified_last_name.value):
                raise ValueError("Invalid last name: Only letters allowed")
    
        if self.modified_age.value != "":        
            age_pattern = r'^\d{1,3}$'

            if self.age.value.isdigit() and len(str(self.modified_age.value)) > 3:
                    raise ValueError("Invalid age: Max 3 digits allowed")

            if not re.match(age_pattern, self.modified_age.value):
                raise ValueError("Invalid age: must be digits only")

        if self.modified_gender.value != "":
            gender_pattern = r'^(Man|Women)$'

            if not re.match(gender_pattern, self.modified_gender.value):
                raise ValueError("Invalid gender: Gender must be 'Man' or 'Women'")

        if self.modified_weight.value != "":
            weight_pattern = r'^\d{1,3}$'

            if self.modified_weight.value.isdigit() and len(str(self.modified_weight.value)) > 3:
                raise ValueError("Invalid weight: Max 3 digits allowed")

            if not re.match(weight_pattern, self.modified_weight.value):
                raise ValueError("Invalid weight: must a digits only")

        if self.modified_street_name.value != "":
            if not re.match(letters_only_pattern, self.modified_street_name.value):
                raise ValueError("Invalid street name: Only letters allowed")

        if self.modified_house_number.value != "":
            house_number_patterm = r'^\d+[a-zA-Z]*$'

            if not re.match(house_number_patterm, self.modified_house_number.value):
                raise ValueError("Invalid house number: a house number can only has digits and letters and must start with a digit")

        if self.modified_zip_code.value != "":
            zip_code_pattern = r'^\d{4}[a-zA-Z]{2}$'

            if not re.match(zip_code_pattern, self.modified_zip_code.value):
                raise ValueError("Invalid emazip code. zip code must be as followed DDDDXX")

        if self.modified_city.value != "":
            if self.modified_city.value not in self.european_cities:
                raise ValueError("Invalid city")

        if self.modified_email_address.value != "":
            email_pattern = r'^[a-zA-Z0-9._-]+@[a-zA-Z0-9-]+\.[a-z]+$'

            if not re.match(email_pattern, self.modified_email_address.value):
                raise ValueError("Invalid email address format. Please enter a valid email address in the format [a-z]+@[a-z]+\.[a-z]")

        if self.modified_mobile_phone.value != "":
            mobile_phone_pattern = r'^\d{8}$'

            if not re.match(mobile_phone_pattern, self.modified_mobile_phone.value):
                raise ValueError("Invalid phone number format. Please enter a valid mobile number in the format DDDDDDDD where D stands for one digit")

    def fetch_member(self):
        self.validate_input()

        cursor.execute("SELECT * FROM members WHERE first_name = ? and last_name = ?", (self.first_name.value, self.last_name.value))
        member = cursor.fetchone()

        if not member:
            raise ValueError("Member not found")

        return member

    def values_to_modify(self):
        modify = False

        if self.modified_first_name.value != "":
            modify = True

        if self.modified_last_name.value != "":     
            modify = True

        if self.modified_age.value != "":
            modify = True

        if self.modified_gender.value != "":
            modify = True

        if self.modified_weight.value != "":
            modify = True

        if self.modified_street_name.value != "":
            modify = True

        if self.modified_house_number.value != "":
            modify = True

        if self.modified_zip_code.value != "":
            modify = True

        if self.modified_city.value != "":
            modify = True

        if self.modified_email_address.value != "":
            modify = True

        if self.modified_mobile_phone.value != "":
            modify = True

        return modify

    def modify_member(self):
        member = self.fetch_member()

        if self.modified_first_name.value != "":
            cursor.execute("UPDATE members SET first_name = ? WHERE id = ?", (self.modified_first_name.value, member[0]))

        if self.modified_last_name.value != "":     
            cursor.execute("UPDATE members SET last_name = ? WHERE id = ?", (self.modified_last_name.value, member[0]))

        if self.modified_age.value != "":
            cursor.execute("UPDATE members SET age = ? WHERE id = ?", (self.modified_age.value, member[0]))

        if self.modified_gender.value != "":
            cursor.execute("UPDATE members SET gender = ? WHERE id = ?", (self.modified_gender.value, member[0]))

        if self.modified_weight.value != "":
            cursor.execute("UPDATE members SET weight = ? WHERE id = ?", (self.modified_weight.value, member[0]))

        if self.modified_street_name.value != "":
            cursor.execute("UPDATE members SET street_name = ? WHERE id = ?", (self.modified_street_name.value, member[0]))

        if self.modified_house_number.value != "":
            cursor.execute("UPDATE members SET house_number = ? WHERE id = ?", (self.modified_house_number.value, member[0]))

        if self.modified_zip_code.value != "":
            cursor.execute("UPDATE members SET zip_code = ? WHERE id = ?", (self.modified_zip_code.value, member[0]))

        if self.modified_city.value != "":
            cursor.execute("UPDATE members SET city = ? WHERE id = ?", (self.modified_city.value, member[0]))

        if self.modified_email_address.value != "":
            cursor.execute("UPDATE members SET email_address = ? WHERE id = ?", (self.modified_email_address.value, member[0]))

        if self.modified_mobile_phone.value != "":
            cursor.execute("UPDATE members SET mobile_phone = ? WHERE id = ?", (self.modified_mobile_phone.value, member[0]))

        conn.commit()

    def clear_fields(self):
        for widget in self._widgets__:
            if isinstance(widget, npyscreen.TitleText):
                widget.value = ""

    def on_ok(self):
        try:
            if (self.values_to_modify() == False):
                raise ValueError("No values to modify")

            self.modify_member()
            npyscreen.notify_confirm("Modified member successfully", title="Succes", wrap=True)

            self.clear_fields()

        except ValueError as e:
            npyscreen.notify_confirm(str(e), title="Error", wrap=True)

    def on_cancel(self):
        for widget in self._widgets__:
            if isinstance(widget, npyscreen.TitleText):
                widget.value = ""

        self.parentApp.switchFormPrevious()

class DeleteMemberForm(npyscreen.ActionForm):
    def create(self):
        self.first_name = self.add(npyscreen.TitleText, name='First Name:')
        self.last_name = self.add(npyscreen.TitleText, name='Last Name:')

        self.user_info = self.add(npyscreen.MultiLineEdit, editable=False, rely=6)

        self.add(npyscreen.FixedText, value="Use Ok to search and Cancel to go back", rely=5)
        self.add(npyscreen.ButtonPress, name="Delete member", when_pressed_function=self.delete_member, rely=18, relx=0)

    def validate_input(self):
        letters_only_pattern = r'^[a-zA-Z]+$'

        if not re.match(letters_only_pattern, self.first_name.value):
            raise ValueError("Invalid first name")

        if not re.match(letters_only_pattern, self.last_name.value):
            raise ValueError("Invalid last name")

    def fetch_member(self):
        self.validate_input()

        cursor.execute("SELECT * FROM members WHERE first_name = ? and last_name = ?", (self.first_name.value, self.last_name.value))
        member = cursor.fetchone()

        return member

    def delete_member(self):
        try:
            member = self.fetch_member()

            if not admin:
                raise ValueError("No member to delete")

            confirmed = npyscreen.notify_ok_cancel(f"Are you sure you want to delete member {member[1]} {member[2]}", wrap=True)
            
            if confirmed:
                cursor.execute("DELETE FROM members WHERE id = ?", (member[0]))
                conn.commit()

                self.user_info.value = ""

        except ValueError as e:
            npyscreen.notify_confirm(str(e), title="Error", wrap=True)

    def on_ok(self):
        try:
            member = self.fetch_admin()
    
            if member:
                self.user_info.value = f"\nFirst Name: {member[4]}\nLast Name: {member[5]}"
            else:
                self.user_info.value = "\nNo member found"

        except ValueError as e:
            npyscreen.notify_confirm(str(e), title="Error", wrap=True)

    def on_cancel(self):
        for widget in self._widgets__:
            if isinstance(widget, npyscreen.TitleText):
                widget.value = ""

        self.user_info.value = ""

        self.parentApp.switchFormPrevious()

class SearchMemberForm(npyscreen.ActionForm):
    def create(self):
        self.value = None
        self.first_name = self.add(npyscreen.TitleText, name='First Name:')
        self.last_name = self.add(npyscreen.TitleText, name='Last Name:')
        self.user_info = self.add(npyscreen.MultiLineEdit, editable=False)
        self.add(npyscreen.FixedText, value="Use Ok to search member and Cancel to go back", rely=5, relx=2)

    def validate_input(self):
        letters_only_pattern = r'^[a-zA-Z]+$'

        if not re.match(letters_only_pattern, self.first_name.value):
            raise ValueError("Invalid first name: Only letters allowed")

        if not re.match(letters_only_pattern, self.last_name.value):
            raise ValueError("Invalid last name: Only letters allowed")

    def on_ok(self): 
        try:
            self.validate_input()

            f_name = self.first_name.value
            l_name = self.last_name.value

            conn = sqlite3.connect('unique_mail.db')
            cursor = conn.cursor()
            
            # Execute a query to search for the user
            cursor.execute("SELECT * FROM members WHERE first_name = ? and last_name = ?", (f_name, l_name))
            user_data = cursor.fetchone()
            
            if user_data:
                # Display user information
                self.user_info.value = f"\nFound member:\n\nFirst Name: {user_data[1]}\nLast Name: {user_data[2]}\nAge: {user_data[3]}\nGender: {user_data[4]}\nWeight: {user_data[5]}\nStreet name: {user_data[6]}\nHouse number: {user_data[7]}\nZip Code: {user_data[8]}\nCity: {user_data[9]}\nEmail: {user_data[10]}"

            else:
                self.user_info.value = "\nUser not found."

        except ValueError as e:
            npyscreen.notify_confirm(str(e), title="Error", wrap=True)

    def on_cancel(self):
        for widget in self._widgets__:
            if isinstance(widget, npyscreen.TitleText):
                widget.value = ""

        self.parentApp.switchFormPrevious()

# --------------------------------------------------------- Consultant Actions ----------------------------------------------------------------

class AddConsultantForm(npyscreen.ActionForm):
    def create(self):
        self.add(npyscreen.FixedText, value="Account:", rely=1)
        self.username = self.add(npyscreen.TitleText, name='Username:')
        self.password = self.add(npyscreen.TitlePassword, name='Password:')
        self.role = "CONSULTANT"

        self.add(npyscreen.FixedText, value="Profile:", rely=5)
        self.first_name = self.add(npyscreen.TitleText, name='First Name:')
        self.last_name = self.add(npyscreen.TitleText, name='Last Name:')

        self.add(npyscreen.FixedText, value="Use Ok to add consultant or Cancel to go back", rely=10)

    def validate_input(self):
        username_pattern = r'^(?=[a-zA-Z_])(?!.*(_)\1)(?!.*[a-zA-Z0-9_.\'&]{11,})([a-zA-Z0-9_.\'&]{8,10})$'

        if not re.match(username_pattern, self.username.value):
            raise ValueError("Username:\n- Must have min 8 and max 10 characters\n- Must start with a letter or underscores\n- Can contain letters (a-z), numbers (0-9), underscores (_), apostrophes ('), and periods (.)")

        password_pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[~!@#$%&amp;_\-+=`|\\(){}[\]:;'<>,.?/]).{12,30}$"
        if not re.match(password_pattern, self.password.value):
            raise ValueError("Password:\n- Must have min 12 and max 30 characters\n- Can contain letters, numbers, and special characters [~!@#$%&_-+=`|\(){}[]:;'<>,.?/]\n- Must be a combination of at least one lowercase letter, one uppercase letter, one digit and one special character")

        letters_only_pattern = r'^[a-zA-Z]+$'

        if not re.match(letters_only_pattern, self.first_name.value):
            raise ValueError("Invalid first name: Only letters allowed")

        if not re.match(letters_only_pattern, self.last_name.value):
            raise ValueError("Invalid last name: Only letters allowed")

    def add_consultant(self):
        self.validate_input()

        cursor.execute("SELECT * FROM users WHERE LOWER(username) = ?", (self.username.value.lower(),))
        username = cursor.fetchone()

        if username:
            raise ValueError("Username already exists")

        cursor.execute("SELECT * FROM users WHERE first_name = ? and last_name = ?", (self.first_name.value, self.last_name.value))
        profile = cursor.fetchone()

        if profile:
            raise ValueError("Profile already exists")

        hashed_password = bcrypt.hashpw(self.password.value.encode('utf-8'), bcrypt.gensalt())
        registration_date = datetime.now()

        cursor.execute('INSERT INTO users (username, password, role, first_name, last_name, temporary, expiration, registration_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        (self.username.value, hashed_password.decode('utf-8'), self.role, self.first_name.value, self.last_name.value, 0, None, registration_date))

        conn.commit()

    def clear_fields(self):
        for widget in self._widgets__:
            if isinstance(widget, npyscreen.TitleText):
                widget.value = ""

    def on_ok(self):
        try:
            self.add_consultant() 
            npyscreen.notify_confirm(f"Added consultant: {self.first_name.value} {self.last_name.value}", title="Success", wrap=True)
            
            self.clear_fields()

        except ValueError as e:
            npyscreen.notify_confirm(str(e), title="Error", wrap=True)

    def on_cancel(self):
        self.clear_fields()
        self.parentApp.switchFormPrevious()

class ModifyConsultantForm(npyscreen.ActionForm):
    def create(self):
        self.username = self.add(npyscreen.TitleText, name='Username:')
        self.role = "CONSULTANT"

        self.add(npyscreen.FixedText, value="New value for username:", rely=4)
        self.modified_username = self.add(npyscreen.TitleText, name='Username:', rely=5)

        self.add(npyscreen.FixedText, value="New values for profile:", rely=7)

        self.modified_first_name = self.add(npyscreen.TitleText, name='First Name:', rely=8)
        self.modified_last_name = self.add(npyscreen.TitleText, name='Last Name:')

        self.add(npyscreen.FixedText, value="Use Ok to modify consultant or Cancel to go back", rely=12)

    def validate_input(self):
        username_pattern = r'^(?=[a-zA-Z_])(?!.*(_)\1)(?!.*[a-zA-Z0-9_.\'&]{11,})([a-zA-Z0-9_.\'&]{8,10})$'

        if not re.match(username_pattern, self.username.value):
            raise ValueError("Invalid credentials")

        if not re.match(username_pattern, self.modified_username.value):
            raise ValueError("Username:\n- Must have min 8 and max 10 characters\n- Must start with a letter or underscores\n- Can contain letters (a-z), numbers (0-9), underscores (_), apostrophes ('), and periods (.)")

        letters_only_pattern = r'^[a-zA-Z]*$'

        if not re.match(letters_only_pattern, self.modified_first_name.value):
            raise ValueError("Invalid first name: Only letters allowed")

        if not re.match(letters_only_pattern, self.modified_last_name.value):
            raise ValueError("Invalid last name: Only letters allowed")

    def fetch_consultant(self):
        self.validate_input()

        cursor.execute("SELECT * FROM users WHERE LOWER(username) = ? and role = ?", (self.username.value.lower(), self.role))
        consultant = cursor.fetchone()

        if not consultant:
            raise ValueError("Consultant not found")

        return consultant

    def values_to_modify(self):
        modify = False

        if self.modified_username.value != "":
            modify = True

        if self.modified_first_name.value != "":
            modify = True

        if self.modified_last_name.value != "":
            modify = True

        return modify

    def modify_consultant(self):
        consultant = self.fetch_consultant()

        if self.values_to_modify() == False:
            raise ValueError("No values to modify")

        if self.modified_username.value != "":
            cursor.execute("UPDATE users SET username = ? WHERE LOWER(username) = ? and role = ?", (self.modified_username.value, consultant[1].lower(), self.role))
            conn.commit()

        if self.modified_first_name.value != "":
            cursor.execute("UPDATE users SET first_name = ? WHERE LOWER(username) = ? and role = ?", (self.modified_first_name.value, consultant[1].lower(), self.role))
            conn.commit()

        if self.modified_last_name.value != "":     
            cursor.execute("UPDATE users SET last_name = ? WHERE LOWER(username) = ? and role = ?", (self.modified_last_name.value, consultant[1].lower(), self.role))
            conn.commit()

    def clear_fields(self):
        for widget in self._widgets__:
            if isinstance(widget, npyscreen.TitleText):
                widget.value = ""

    def on_ok(self):
        try:
            self.modify_consultant()
            npyscreen.notify_confirm("Modified consultant successfully", title="Success", wrap=True)
            
            self.clear_fields()
        
        except ValueError as e:
            npyscreen.notify_confirm(str(e), title="Error", wrap=True)

    def on_cancel(self):
        self.clear_fields()
        self.parentApp.switchFormPrevious()

class DeleteConsultantForm(npyscreen.ActionForm):
    def create(self):
        self.username = self.add(npyscreen.TitleText, name='Username:')
        self.role = "CONSULTANT"

        self.user_info = self.add(npyscreen.MultiLineEdit, editable=False, rely=6)

        self.add(npyscreen.FixedText, value="Use Ok to search or Cancel to go back", rely=4)

        self.add(npyscreen.ButtonPress, name="Delete consultant", when_pressed_function=self.delete_consultant, rely=10, relx=0)

    def validate_input(self):
        username_pattern = r'^(?=[a-zA-Z_])(?!.*(_)\1)(?!.*[a-zA-Z0-9_.\'&]{11,})([a-zA-Z0-9_.\'&]{8,10})$'

        if not re.match(username_pattern, self.username.value):
            raise ValueError("Invalid credentials")

    def fetch_consultant(self):
        self.validate_input()

        cursor.execute("SELECT * FROM users WHERE LOWER(username) = ? and role = ?", (self.username.value.lower(), self.role))

        consultant = cursor.fetchone()

        return consultant

    def delete_consultant(self):
        try:
            consultant = self.fetch_consultant()

            if not consultant:
                raise ValueError("No consultant to delete")

            confirmed = npyscreen.notify_ok_cancel(f"Are you sure you want to delete consultant: {consultant[4]} {consultant[5]}", wrap=True)
            
            if confirmed:
                cursor.execute("DELETE FROM users WHERE LOWER(username) = ? and role = ?", (consultant[1].lower(), self.role))
                conn.commit()

                self.user_info.value = ""

        except ValueError as e:
            npyscreen.notify_confirm(str(e), title="Error", wrap=True)

    def on_ok(self): 
        try:
            consultant = self.fetch_consultant()
    
            if consultant:
                self.user_info.value = f"\nFirst Name: {consultant[4]}\nLast Name: {consultant[5]}"
            else:
                self.user_info.value = "\nNo consultant found"

        except ValueError as e:
            npyscreen.notify_confirm(str(e), title="Error", wrap=True)

    def on_cancel(self):
        for widget in self._widgets__:
            if isinstance(widget, npyscreen.TitleText):
                widget.value = ""

        self.user_info.value = ""

        self.parentApp.switchFormPrevious()

class UpdateConsultantPasswordForm(npyscreen.ActionForm):
    def create(self):
        self.username = self.add(npyscreen.TitleText, name='Username:')
        self.password = self.add(npyscreen.TitlePassword, name='Password:')
        self.role = "CONSULTANT"

        self.add(npyscreen.FixedText, value="Fill in a new password", rely=5)
        self.modified_password = self.add(npyscreen.TitlePassword, name='Password:')

        self.add(npyscreen.FixedText, value="Use Ok to update password or Cancel to go back", rely=10)

    def validate_input(self):
        username_pattern = r'^(?=[a-zA-Z_])(?!.*(_)\1)(?!.*[a-zA-Z0-9_.\'&]{11,})([a-zA-Z0-9_.\'&]{8,10})$'

        if not re.match(username_pattern, self.username.value):
            raise ValueError("Invalid credentials")

        password_pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[~!@#$%&amp;_\-+=`|\\(){}[\]:;'<>,.?/]).{12,30}$"

        if not re.match(password_pattern, self.password.value):
            raise ValueError("Invalid credentials")
    
        if not re.match(password_pattern, self.modified_password.value):
            raise ValueError("New password:\n- Must have min 12 and max 30 characters\n- Can contain letters, numbers, and special characters [~!@#$%&_-+=`|\(){}[]:;'<>,.?/]\n- Must be a combination of at least one lowercase letter, one uppercase letter, one digit and one special character")

    def fetch_consultant(self):
        self.validate_input()

        cursor.execute("SELECT * FROM users WHERE LOWER(username) = ? and role = ?", (self.username.value.lower(), self.role))

        consultant = cursor.fetchone()

        if not consultant:
            raise ValueError("Consultant not found")

        if not bcrypt.checkpw(self.password.value.encode('utf-8'), consultant[2].encode('utf8')):
            raise ValueError("Invalid credentials")

        return consultant

    def modify_password(self):
        consultant = self.fetch_consultant()

        if bcrypt.checkpw(self.modified_password.value.encode('utf-8'), consultant[2].encode('utf8')):
            raise ValueError("Password cannot be the same as your previous password")

        hashed_password = bcrypt.hashpw(self.modified_password.value.encode('utf-8'), bcrypt.gensalt())

        cursor.execute("UPDATE users SET password = ?, temporary = ?, expiration = ? WHERE LOWER(username) = ? and role = ?", (hashed_password.decode('utf-8'), 0, None, consultant[1].lower(), self.role))
        conn.commit()

    def clear_fields(self):
        for widget in self._widgets__:
            if isinstance(widget, npyscreen.TitleText):
                widget.value = ""

    def on_ok(self): 
        try:
            self.modify_password()
            npyscreen.notify_confirm("Updated password succesfully", title="Success", wrap=True)

            self.clear_fields()

        except ValueError as e:
            npyscreen.notify_confirm(str(e), title="Error", wrap=True)

    def on_cancel(self):
        self.clear_fields()
        self.parentApp.switchFormPrevious()

class ResetConsultantPasswordForm(npyscreen.ActionForm):
    def create(self):
        self.username = self.add(npyscreen.TitleText, name='Username:')
        self.role = "CONSULTANT"

        self.add(npyscreen.FixedText, value="Fill in a temporary password", rely=5)
        self.modified_password = self.add(npyscreen.TitlePassword, name='Password:')

        self.add(npyscreen.FixedText, value="Use Ok to reset password or Cancel to go back", rely=10)

    def validate_input(self):
        username_pattern = r'^(?=[a-zA-Z_])(?!.*(_)\1)(?!.*[a-zA-Z0-9_.\'&]{11,})([a-zA-Z0-9_.\'&]{8,10})$'

        if not re.match(username_pattern, self.username.value):
            raise ValueError("Invalid credentials")

        password_pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[~!@#$%&amp;_\-+=`|\\(){}[\]:;'<>,.?/]).{12,30}$"

        if not re.match(password_pattern, self.modified_password.value):
            raise ValueError("Temporary password:\n- Must have min 12 and max 30 characters\n- Can contain letters, numbers, and special characters [~!@#$%&_-+=`|\(){}[]:;'<>,.?/]\n- Must be a combination of at least one lowercase letter, one uppercase letter, one digit and one special character")

    def fetch_consultant(self):
        self.validate_input()

        cursor.execute("SELECT * FROM users WHERE LOWER(username) = ? and role = ?", (self.username.value.lower(), self.role))

        consultant = cursor.fetchone()

        if not consultant:
            raise ValueError("Consultant not found")

        return consultant

    def reset_password(self):
        consultant = self.fetch_consultant()

        if bcrypt.checkpw(self.modified_password.value.encode('utf-8'), consultant[2].encode('utf8')):
            raise ValueError("Password cannot be the same as your previous password")

        expire_date =  datetime.now() + timedelta(minutes=1)
        hashed_password = bcrypt.hashpw(self.modified_password.value.encode('utf-8'), bcrypt.gensalt())

        cursor.execute("UPDATE users SET password = ?, temporary = ?, expiration = ?, failed_attempts = ? WHERE LOWER(username) = ? and role = ?", (hashed_password.decode('utf-8'), 1, expire_date, 0, consultant[1].lower(), self.role))
        conn.commit()

    def clear_fields(self):
        for widget in self._widgets__:
            if isinstance(widget, npyscreen.TitleText):
                widget.value = ""

    def on_ok(self): 
        try:
            self.reset_password()
            npyscreen.notify_confirm("Password reset succesfully. Password is valid for 1 minute", title="Success", wrap=True)

            self.clear_fields()

        except ValueError as e:
            npyscreen.notify_confirm(str(e), title="Error", wrap=True)

    def on_cancel(self):
        self.clear_fields()
        self.parentApp.switchFormPrevious()

# --------------------------------------------------------- Admins ----------------------------------------------------------------

class AddAdminForm(npyscreen.ActionForm):
    def create(self):
        self.add(npyscreen.FixedText, value="Account:", rely=1)
        self.username = self.add(npyscreen.TitleText, name='Username:')
        self.password = self.add(npyscreen.TitlePassword, name='Password:')
        self.role = "SYSTEM ADMIN"

        self.add(npyscreen.FixedText, value="Profile:", rely=5)
        self.first_name = self.add(npyscreen.TitleText, name='First Name:')
        self.last_name = self.add(npyscreen.TitleText, name='Last Name:')

        self.add(npyscreen.FixedText, value="Use Ok to add admin or Cancel to go back", rely=10)

    def validate_input(self):
        username_pattern = r'^(?=[a-zA-Z_])(?!.*(_)\1)(?!.*[a-zA-Z0-9_.\'&]{11,})([a-zA-Z0-9_.\'&]{8,10})$'

        if not re.match(username_pattern, self.username.value):
            raise ValueError("Username:\n- Must have min 8 and max 10 characters\n- Must start with a letter or underscores\n- Can contain letters (a-z), numbers (0-9), underscores (_), apostrophes ('), and periods (.)")

        password_pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[~!@#$%&amp;_\-+=`|\\(){}[\]:;'<>,.?/]).{12,30}$"
        if not re.match(password_pattern, self.password.value):
            raise ValueError("Password:\n- Must have min 12 and max 30 characters\n- Can contain letters, numbers, and special characters [~!@#$%&_-+=`|\(){}[]:;'<>,.?/]\n- Must be a combination of at least one lowercase letter, one uppercase letter, one digit and one special character")

        letters_only_pattern = r'^[a-zA-Z]+$'

        if not re.match(letters_only_pattern, self.first_name.value):
            raise ValueError("Invalid first name: Only letters allowed")

        if not re.match(letters_only_pattern, self.last_name.value):
            raise ValueError("Invalid last name: Only letters allowed")

    def add_admin(self):
        self.validate_input()

        cursor.execute("SELECT * FROM users WHERE LOWER(username) = ?", (self.username.value.lower(),))
        username = cursor.fetchone()

        if username:
            raise ValueError("Username already exists")

        cursor.execute("SELECT * FROM users WHERE first_name = ? and last_name = ?", (self.first_name.value, self.last_name.value))
        profile = cursor.fetchone()

        if profile:
            raise ValueError("Profile already exists")

        hashed_password = bcrypt.hashpw(self.password.value.encode('utf-8'), bcrypt.gensalt())
        registration_date = datetime.now()

        cursor.execute('INSERT INTO users (username, password, role, first_name, last_name, temporary, expiration, registration_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        (self.username.value, hashed_password.decode('utf-8'), self.role, self.first_name.value, self.last_name.value, 0, None, registration_date))

        conn.commit()

    def clear_fields(self):
        for widget in self._widgets__:
            if isinstance(widget, npyscreen.TitleText):
                widget.value = ""

    def on_ok(self):
        try:
            self.add_admin() 
            npyscreen.notify_confirm(f"Added admin: {self.first_name.value} {self.last_name.value}", title="Success", wrap=True)
            
            self.clear_fields()

        except ValueError as e:
            npyscreen.notify_confirm(str(e), title="Error", wrap=True)

    def on_cancel(self):
        self.clear_fields()
        self.parentApp.switchFormPrevious()

class ModifyAdminForm(npyscreen.ActionForm):
    def create(self):
        self.username = self.add(npyscreen.TitleText, name='Username:')
        self.role = "SYSTEM ADMIN"

        self.add(npyscreen.FixedText, value="New value for username:", rely=4)
        self.modified_username = self.add(npyscreen.TitleText, name='Username:', rely=5)

        self.add(npyscreen.FixedText, value="New values for profile:", rely=7)

        self.modified_first_name = self.add(npyscreen.TitleText, name='First Name:', rely=8)
        self.modified_last_name = self.add(npyscreen.TitleText, name='Last Name:')

        self.add(npyscreen.FixedText, value="Use Ok to modify admin or Cancel to go back", rely=12)

    def validate_input(self):
        username_pattern = r'^(?=[a-zA-Z_])(?!.*(_)\1)(?!.*[a-zA-Z0-9_.\'&]{11,})([a-zA-Z0-9_.\'&]{8,10})$'

        if not re.match(username_pattern, self.username.value):
            raise ValueError("Invalid credentials")

        if not re.match(username_pattern, self.modified_username.value):
            raise ValueError("Username:\n- Must have min 8 and max 10 characters\n- Must start with a letter or underscores\n- Can contain letters (a-z), numbers (0-9), underscores (_), apostrophes ('), and periods (.)")

        letters_only_pattern = r'^[a-zA-Z]*$'

        if not re.match(letters_only_pattern, self.modified_first_name.value):
            raise ValueError("Invalid first name: Only letters allowed")

        if not re.match(letters_only_pattern, self.modified_last_name.value):
            raise ValueError("Invalid last name: Only letters allowed")

    def fetch_admin(self):
        self.validate_input()

        cursor.execute("SELECT * FROM users WHERE LOWER(username) = ? and role = ?", (self.username.value.lower(), self.role))
        admin = cursor.fetchone()

        if not admin:
            raise ValueError("Admin not found")

        return admin

    def values_to_modify(self):
        modify = False

        if self.modified_username.value != "":
            modify = True

        if self.modified_first_name.value != "":
            modify = True

        if self.modified_last_name.value != "":
            modify = True

        return modify

    def modify_admin(self):
        admin = self.fetch_admin()

        if self.values_to_modify() == False:
            raise ValueError("No values to modify")

        if self.modified_username.value != "":
            cursor.execute("UPDATE users SET username = ? WHERE LOWER(username) = ? and role = ?", (self.modified_username.value, admin[1].lower(), self.role))
            conn.commit()

        if self.modified_first_name.value != "":
            cursor.execute("UPDATE users SET first_name = ? WHERE LOWER(username) = ? and role = ?", (self.modified_first_name.value, admin[1].lower(), self.role))
            conn.commit()

        if self.modified_last_name.value != "":     
            cursor.execute("UPDATE users SET last_name = ? WHERE LOWER(username) = ? and role = ?", (self.modified_last_name.value, admin[1].lower(), self.role))
            conn.commit()

    def clear_fields(self):
        for widget in self._widgets__:
            if isinstance(widget, npyscreen.TitleText):
                widget.value = ""

    def on_ok(self):
        try:
            self.modify_admin()
            npyscreen.notify_confirm("Modified admin successfully", title="Success", wrap=True)
            
            self.clear_fields()
        
        except ValueError as e:
            npyscreen.notify_confirm(str(e), title="Error", wrap=True)

    def on_cancel(self):
        self.clear_fields()
        self.parentApp.switchFormPrevious()

class DeleteAdminForm(npyscreen.ActionForm):
    def create(self):
        self.username = self.add(npyscreen.TitleText, name='Username:')
        self.role = "SYSTEM ADMIN"

        self.user_info = self.add(npyscreen.MultiLineEdit, editable=False, rely=6)

        self.add(npyscreen.FixedText, value="Use Ok to search or Cancel to go back", rely=4)

        self.add(npyscreen.ButtonPress, name="Delete admin", when_pressed_function=self.delete_admin, rely=10, relx=0)

    def validate_input(self):
        username_pattern = r'^(?=[a-zA-Z_])(?!.*(_)\1)(?!.*[a-zA-Z0-9_.\'&]{11,})([a-zA-Z0-9_.\'&]{8,10})$'

        if not re.match(username_pattern, self.username.value):
            raise ValueError("Invalid credentials")

    def fetch_admin(self):
        self.validate_input()

        cursor.execute("SELECT * FROM users WHERE LOWER(username) = ? and role = ?", (self.username.value.lower(), self.role))

        admin = cursor.fetchone()

        return admin

    def delete_admin(self):
        try:
            admin = self.fetch_admin()

            if not admin:
                raise ValueError("No admin to delete")

            confirmed = npyscreen.notify_ok_cancel(f"Are you sure you want to delete admin: {admin[4]} {admin[5]}", wrap=True)
            
            if confirmed:
                cursor.execute("DELETE FROM users WHERE LOWER(username) = ? and role = ?", (admin[1].lower(), self.role))
                conn.commit()

                self.user_info.value = ""

        except ValueError as e:
            npyscreen.notify_confirm(str(e), title="Error", wrap=True)

    def on_ok(self): 
        try:
            admin = self.fetch_admin()
    
            if admin:
                self.user_info.value = f"\nFirst Name: {admin[4]}\nLast Name: {admin[5]}"
            else:
                self.user_info.value = "\nNo admin found"

        except ValueError as e:
            npyscreen.notify_confirm(str(e), title="Error", wrap=True)

    def on_cancel(self):
        for widget in self._widgets__:
            if isinstance(widget, npyscreen.TitleText):
                widget.value = ""

        self.user_info.value = ""

        self.parentApp.switchFormPrevious()

class UpdateAdminsPasswordForm(npyscreen.ActionForm):
    def create(self):
        self.username = self.add(npyscreen.TitleText, name='Username:')
        self.password = self.add(npyscreen.TitlePassword, name='Password:')
        self.role = "SYSTEM ADMIN"

        self.add(npyscreen.FixedText, value="Fill in a new password", rely=5)
        self.modified_password = self.add(npyscreen.TitlePassword, name='Password:')

        self.add(npyscreen.FixedText, value="Use Ok to update password or Cancel to go back", rely=10)

    def validate_input(self):
        username_pattern = r'^(?=[a-zA-Z_])(?!.*(_)\1)(?!.*[a-zA-Z0-9_.\'&]{11,})([a-zA-Z0-9_.\'&]{8,10})$'

        if not re.match(username_pattern, self.username.value):
            raise ValueError("Invalid credentials")

        password_pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[~!@#$%&amp;_\-+=`|\\(){}[\]:;'<>,.?/]).{12,30}$"

        if not re.match(password_pattern, self.password.value):
            raise ValueError("Invalid credentials")
    
        if not re.match(password_pattern, self.modified_password.value):
            raise ValueError("New password:\n- Must have min 12 and max 30 characters\n- Can contain letters, numbers, and special characters [~!@#$%&_-+=`|\(){}[]:;'<>,.?/]\n- Must be a combination of at least one lowercase letter, one uppercase letter, one digit and one special character")

    def fetch_admin(self):
        self.validate_input()

        cursor.execute("SELECT * FROM users WHERE LOWER(username) = ? and role = ?", (self.username.value.lower(), self.role))

        admin = cursor.fetchone()

        if not admin:
            raise ValueError("Admin not found")

        if not bcrypt.checkpw(self.password.value.encode('utf-8'), admin[2].encode('utf8')):
            raise ValueError("Invalid credentials")

        return admin

    def modify_password(self):
        admin = self.fetch_admin()

        if bcrypt.checkpw(self.modified_password.value.encode('utf-8'), admin[2].encode('utf8')):
            raise ValueError("Password cannot be the same as your previous password")

        hashed_password = bcrypt.hashpw(self.modified_password.value.encode('utf-8'), bcrypt.gensalt())

        cursor.execute("UPDATE users SET password = ?, temporary = ?, expiration = ? WHERE LOWER(username) = ? and role = ?", (hashed_password.decode('utf-8'), 0, None, admin[1].lower(), self.role))
        conn.commit()

    def clear_fields(self):
        for widget in self._widgets__:
            if isinstance(widget, npyscreen.TitleText):
                widget.value = ""

    def on_ok(self): 
        try:
            self.modify_password()
            npyscreen.notify_confirm("Updated password succesfully", title="Success", wrap=True)

            self.clear_fields()

        except ValueError as e:
            npyscreen.notify_confirm(str(e), title="Error", wrap=True)

    def on_cancel(self):
        self.clear_fields()
        self.parentApp.switchFormPrevious()

class ResetAdminsPasswordForm(npyscreen.ActionForm):
    def create(self):
        self.username = self.add(npyscreen.TitleText, name='Username:')
        self.role = "SYSTEM ADMIN"

        self.add(npyscreen.FixedText, value="Fill in a temporary password", rely=5)
        self.modified_password = self.add(npyscreen.TitlePassword, name='Password:')

        self.add(npyscreen.FixedText, value="Use Ok to reset password or Cancel to go back", rely=10)

    def validate_input(self):
        username_pattern = r'^(?=[a-zA-Z_])(?!.*(_)\1)(?!.*[a-zA-Z0-9_.\'&]{11,})([a-zA-Z0-9_.\'&]{8,10})$'

        if not re.match(username_pattern, self.username.value):
            raise ValueError("Invalid credentials")

        password_pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[~!@#$%&amp;_\-+=`|\\(){}[\]:;'<>,.?/]).{12,30}$"

        if not re.match(password_pattern, self.modified_password.value):
            raise ValueError("Temporary password:\n- Must have min 12 and max 30 characters\n- Can contain letters, numbers, and special characters [~!@#$%&_-+=`|\(){}[]:;'<>,.?/]\n- Must be a combination of at least one lowercase letter, one uppercase letter, one digit and one special character")

    def fetch_admin(self):
        self.validate_input()

        cursor.execute("SELECT * FROM users WHERE LOWER(username) = ? and role = ?", (self.username.value.lower(), self.role))

        admin = cursor.fetchone()

        if not admin:
            raise ValueError("Admin not found")

        return admin

    def reset_password(self):
        admin = self.fetch_admin()

        if bcrypt.checkpw(self.modified_password.value.encode('utf-8'), admin[2].encode('utf8')):
            raise ValueError("Password cannot be the same as your previous password")

        expire_date =  datetime.now() + timedelta(minutes=1)
        hashed_password = bcrypt.hashpw(self.modified_password.value.encode('utf-8'), bcrypt.gensalt())

        cursor.execute("UPDATE users SET password = ?, temporary = ?, expiration = ?, failed_attempts = ? WHERE LOWER(username) = ? and role = ?", (hashed_password.decode('utf-8'), 1, expire_date, 0, admin[1].lower(), self.role))
        conn.commit()

    def clear_fields(self):
        for widget in self._widgets__:
            if isinstance(widget, npyscreen.TitleText):
                widget.value = ""

    def on_ok(self): 
        try:
            self.reset_password()
            npyscreen.notify_confirm("Password reset succesfully. Password is valid for 1 minute", title="Success", wrap=True)

            self.clear_fields()

        except ValueError as e:
            npyscreen.notify_confirm(str(e), title="Error", wrap=True)

    def on_cancel(self):
        self.clear_fields()
        self.parentApp.switchFormPrevious()


# --------------------------------------------------------- Consultant ----------------------------------------------------------------

class UsersMenu(npyscreen.FormBaseNew):
    def create(self):
        self.add(npyscreen.ButtonPress, name="List users", when_pressed_function=self.render_new_consultant_screen)
        self.add(npyscreen.ButtonPress, name="Back to main", when_pressed_function=self.switch_back_to_main_menu, rely=7, relx=2)

    def render_new_consultant_screen(self):
        self.parentApp.switchForm("NEW CONSULTANT")

    def switch_back_to_main_menu(self):
        self.parentApp.switchForm("MAIN")

class UserOverviewScreen(npyscreen.Form):
    def create(self):
        self.add(npyscreen.FixedText, value="Firstname                 Lastname                 Username              Role")
        self.log_widget = self.add(npyscreen.MultiLineAction, values=[], max_height=15, scroll_exit=True, color='GREEN')


    def beforeEditing(self):
        cursor.execute('SELECT * FROM users')
        users = cursor.fetchall()
        
        self.log_widget.values.clear()
        self.log_widget.values.append(f"{'':<25} {'':<24} {'':<21} {'':<14}")

        for user in users:
            # decrypted_data = self.decrypt_data(line).decode()
            self.log_widget.values.append(f"{user[4]:<25} {user[5]:<24} {user[1]:<21} {user[3]:<14}")

        # self.log_widget.values.clear()

        # for idx, line in enumerate(lines):
        #     decrypted_data = self.decrypt_data(line).decode()
        #     data = decrypted_data.strip().split(",")
        #     self.log_widget.values.append(f"{idx+1:<6} {data[0]:<11} {data[1]:<10} {data[2]:<14} {data[3]:<27} {data[4]:<24} {data[5]:<10}")

    def decrypt_data(self, string_to_decrypt):
        with open('key_file.key', 'rb') as key_file:
            key = key_file.read()

        fernet = Fernet(key)
        decrypted_data = fernet.decrypt(base64.b64decode(string_to_decrypt).decode())

        return decrypted_data

    def afterEditing(self):
        self.parentApp.switchFormPrevious()

    def has_cancel_button(self):
        return False




# class BackupScreen(npyscreen.Form):
#     def create(self):
#         self.backup_location = self.add(npyscreen.TitleText, name='Enter Backup Location:', value='backup.db')

#     def on_ok(self):
#         try:
#             shutil.copyfile('original.db', self.backup_location.value)
#         except FileNotFoundError:
#             raise ValueError("Location not found. Please provide a valid backup location.")

#     # def afterEditing(self):
    #     self.parentApp.switchForm("MAIN")

class BackupScreen(npyscreen.ActionForm):
    def create(self):
        self.backup_location = self.add(npyscreen.TitleText, name='Destination:')
        self.add(npyscreen.FixedText, value="Use Ok to create backup and Cancel to go back", rely=5, relx=2)

    def validate_input(self):
        letters_only_pattern = r'^[a-zA-Z]+$'

        # if not re.match(letters_only_pattern, self.backup_location.value):
        #     raise ValueError("Invalid first name: Only letters allowed")
        
        if not os.path.exists(self.backup_location.value):
            raise ValueError("Invalid destination: path does not exists")
            # os.path.abspath(

    def on_ok(self):
        try:
            self.validate_input()
            
            if not os.path.exists('log.txt') or not os.path.exists('unique_mail.db'):
                raise ValueError("Error: Files 'log.txt' or 'unique_mail.db' not found.")

            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            backup_filename = f"backup_{timestamp}.zip"

            with zipfile.ZipFile(backup_filename, 'w') as zipf:
                zipf.write('log.txt')
                zipf.write('unique_mail.db')

            os.rename(backup_filename, os.path.join(self.backup_location.value, backup_filename))

            npyscreen.notify_confirm(f"Created backup succesfully", title="Success", wrap=True)
        except ValueError as e:
            npyscreen.notify_confirm(str(e), title="Error", wrap=True)

    def on_cancel(self):
        for widget in self._widgets__:
            if isinstance(widget, npyscreen.TitleText):
                widget.value = ""

        self.parentApp.switchFormPrevious()

class RestoreFiles(npyscreen.ActionForm):
    def create(self):
        self.backup_location = self.add(npyscreen.TitleText, name='Backup dir:')
        self.backup_file = self.add(npyscreen.TitleText, name='Backup file:')

        self.add(npyscreen.FixedText, value="# Backup dir: The directory where to store a backup of the current files", rely=5, relx=2)
        self.add(npyscreen.FixedText, value="# Backup file: The backup file (zip) to restore", rely=6, relx=2)
        self.add(npyscreen.FixedText, value="Use Ok to create member and Cancel to go back", rely=8, relx=2)

    def validate_input(self):
        letters_only_pattern = r'^[a-zA-Z]+$'

        if not re.match(letters_only_pattern, self.backup_location.value):
            raise ValueError("Invalid first name: Only letters allowed")
        
        if not os.path.exists(self.backup_location.value):
            raise ValueError("Invalid directory: Directory does not exists")
            # os.path.abspath(
        
        if not os.path.exists(self.backup_file.value):
            raise ValueError("Invalid File: File does not exists")

    def on_ok(self):
        try:
            self.validate_input()

            response = npyscreen.notify_ok_cancel("Are you sure you want to restore your data", title="Success", wrap=True)
            
            if response == True:
                if not os.path.exists('log.txt') or not os.path.exists('unique_mail.db'):
                    raise ValueError("Error: Files 'log.txt' or 'unique_mail.db' not found.")

                timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                backup_filename = f"backup_{timestamp}.zip"

                with zipfile.ZipFile(backup_filename, 'w') as zipf:
                    zipf.write('log.txt')
                    zipf.write('unique_mail.db')

                os.rename(backup_filename, os.path.join(self.backup_location.value, backup_filename))

                with zipfile.ZipFile(self.backup_file.value, 'r') as zip_ref:
                    zip_ref.extractall(".")

                npyscreen.notify_confirm(f"Created backup succesfully", title="Success", wrap=True)
        except ValueError as e:
            npyscreen.notify_confirm(str(e), title="Error", wrap=True)

    def on_cancel(self):
        for widget in self._widgets__:
            if isinstance(widget, npyscreen.TitleText):
                widget.value = ""

        self.parentApp.switchFormPrevious()

# ---------------------------------------------------------- SYSTEM ACTIONS ----------------------------------------------------------

class BackupScreen(npyscreen.ActionForm):
    def create(self):
        self.backup_location = self.add(npyscreen.TitleText, name='Destination:')
        self.add(npyscreen.FixedText, value="Use Ok to create backup and Cancel to go back", rely=5, relx=2)

    def validate_input(self):
        letters_only_pattern = r'^[a-zA-Z]+$'

        # if not re.match(letters_only_pattern, self.backup_location.value):
        #     raise ValueError("Invalid first name: Only letters allowed")
        
        if not os.path.exists(self.backup_location.value):
            raise ValueError("Invalid destination: path does not exists")
            # os.path.abspath(

    def on_ok(self):
        try:
            self.validate_input()
            
            if not os.path.exists('log.txt') or not os.path.exists('unique_mail.db'):
                raise ValueError("Error: Files 'log.txt' or 'unique_mail.db' not found.")

            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            backup_filename = f"backup_{timestamp}.zip"

            with zipfile.ZipFile(backup_filename, 'w') as zipf:
                zipf.write('log.txt')
                zipf.write('unique_mail.db')

            os.rename(backup_filename, os.path.join(self.backup_location.value, backup_filename))

            npyscreen.notify_confirm(f"Created backup succesfully", title="Success", wrap=True)
        except ValueError as e:
            npyscreen.notify_confirm(str(e), title="Error", wrap=True)

    def on_cancel(self):
        for widget in self._widgets__:
            if isinstance(widget, npyscreen.TitleText):
                widget.value = ""

        self.parentApp.switchFormPrevious()

class RestoreScreen(npyscreen.ActionForm):
    def create(self):
        self.backup_location = self.add(npyscreen.TitleText, name='Backup dir:')
        self.backup_file = self.add(npyscreen.TitleText, name='Backup file:')

        self.add(npyscreen.FixedText, value="# Backup dir: The directory where to store a backup of the current files", rely=5, relx=2)
        self.add(npyscreen.FixedText, value="# Backup file: The backup file (zip) to restore", rely=6, relx=2)
        self.add(npyscreen.FixedText, value="Use Ok to create member and Cancel to go back", rely=8, relx=2)

    def validate_input(self):
        # letters_only_pattern = r'^[a-zA-Z]+$'

        # if not re.match(letters_only_pattern, self.backup_location.value):
        #     raise ValueError("Invalid first name: Only letters allowed")
        
        if not os.path.exists(self.backup_location.value):
            raise ValueError("Invalid directory: Directory does not exists")
            # os.path.abspath(
        
        if not os.path.exists(self.backup_file.value):
            raise ValueError("Invalid File: File does not exists")

    def on_ok(self):
        try:
            self.validate_input()

            response = npyscreen.notify_ok_cancel("Are you sure you want to restore your data", title="Success", wrap=True)
            
            if response == True:
                if not os.path.exists('log.txt') or not os.path.exists('unique_mail.db'):
                    raise ValueError("Error: Files 'log.txt' or 'unique_mail.db' not found.")

                timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                backup_filename = f"backup_{timestamp}.zip"

                with zipfile.ZipFile(backup_filename, 'w') as zipf:
                    zipf.write('log.txt')
                    zipf.write('unique_mail.db')

                os.rename(backup_filename, os.path.join(self.backup_location.value, backup_filename))

                with zipfile.ZipFile(self.backup_file.value, 'r') as zip_ref:
                    zip_ref.extractall(".")

                npyscreen.notify_confirm(f"Created backup succesfully", title="Success", wrap=True)
        except ValueError as e:
            npyscreen.notify_confirm(str(e), title="Error", wrap=True)

    def on_cancel(self):
        for widget in self._widgets__:
            if isinstance(widget, npyscreen.TitleText):
                widget.value = ""

        self.parentApp.switchFormPrevious()

class LogScreen(npyscreen.Form):
    def create(self):
        self.add(npyscreen.TitleText, name="NO.    Date         Time       Username       Description of Activity    Additional Information    Suspicious")
        self.log_widget = self.add(npyscreen.MultiLineAction, values=[], max_height=15, scroll_exit=True)

    def beforeEditing(self):
        with open(log_path, "r") as file:
            lines = file.readlines()

        self.log_widget.values.clear()

        for idx, line in enumerate(lines):
            decrypted_data = self.decrypt_data(line).decode()
            data = decrypted_data.strip().split(",")
            self.log_widget.values.append(f"{idx+1:<6} {data[0]:<11} {data[1]:<10} {data[2]:<14} {data[3]:<27} {data[4]:<24} {data[5]:<10}")

    def decrypt_data(self, string_to_decrypt):
        with open(key_path, 'rb') as key_file:
            key = key_file.read()

        fernet = Fernet(key)
        decrypted_data = fernet.decrypt(base64.b64decode(string_to_decrypt).decode())

        return decrypted_data

    def afterEditing(self):
        self.parentApp.switchFormPrevious()

    def has_cancel_button(self):
        return False

# ---------------------------------------------------------- Menus -------------------------------------------------------------------

class MembersActions(npyscreen.FormBaseNew):
    def beforeEditing(self):
        cursor.execute("SELECT * FROM active_user;")
        user = cursor.fetchone()

        self.add(npyscreen.MultiLineEdit, editable=False, value=f"Username: {user[1]}, Role: {user[2]}", rely = 2, relx= 4)

    def create(self):
        self.add(npyscreen.ButtonPress, name="New member", when_pressed_function=self.render_new_consultant_screen, rely = 4)
        self.add(npyscreen.ButtonPress, name="Modify member", when_pressed_function=self.render_modify_consultant_screen)
        self.add(npyscreen.ButtonPress, name="Delete member", when_pressed_function=self.render_delete_consultant_screen)
        self.add(npyscreen.ButtonPress, name="Search member", when_pressed_function=self.render_reset_password_screen)

        self.add(npyscreen.ButtonPress, name="Back to main", when_pressed_function=self.switch_back_to_main_menu, rely=10, relx=2)

    def render_new_consultant_screen(self):
        self.parentApp.switchForm("NEW MEMBER")

    def render_modify_consultant_screen(self):
        self.parentApp.switchForm("MODIFY MEMBER")

    def render_delete_consultant_screen(self):
        self.parentApp.switchForm("DELETE MEMBER")

    def render_reset_password_screen(self):
        self.parentApp.switchForm("SEARCH MEMBER")

    def switch_back_to_main_menu(self):
        self.parentApp.switchFormPrevious()

class ConsultantsActions(npyscreen.FormBaseNew):
    def beforeEditing(self):
        cursor.execute("SELECT * FROM active_user;")
        user = cursor.fetchone()

        self.add(npyscreen.MultiLineEdit, editable=False, value=f"Username: {user[1]}, Role: {user[2]}", rely = 2, relx= 4)

    def create(self):
        self.add(npyscreen.ButtonPress, name="New consultant", when_pressed_function=self.render_new_consultant_screen, rely = 4)
        self.add(npyscreen.ButtonPress, name="Modify consultant", when_pressed_function=self.render_modify_consultant_screen)
        self.add(npyscreen.ButtonPress, name="Delete consultant", when_pressed_function=self.render_delete_consultant_screen)
        self.add(npyscreen.ButtonPress, name="Reset password", when_pressed_function=self.render_reset_password_screen)
        self.add(npyscreen.ButtonPress, name="Back to main", when_pressed_function=self.switch_back_to_main_menu, rely=10, relx=2)

    def render_new_consultant_screen(self):
        self.parentApp.switchForm("NEW CONSULTANT")

    def render_modify_consultant_screen(self):
        self.parentApp.switchForm("MODIFY CONSULTANT")

    def render_delete_consultant_screen(self):
        self.parentApp.switchForm("DELETE CONSULTANT")

    def render_reset_password_screen(self):
        self.parentApp.switchForm("RESET CONSULTANT PASSWORD")

    def switch_back_to_main_menu(self):
        self.parentApp.switchFormPrevious()

class ConsultantsMenu(npyscreen.FormBaseNew):
    def beforeEditing(self):
        cursor.execute("SELECT * FROM active_user;")
        user = cursor.fetchone()

        self.add(npyscreen.MultiLineEdit, editable=False, value=f"Username: {user[1]}, Role: {user[2]}", rely = 2, relx= 4)

    def create(self):
        self.add(npyscreen.ButtonPress, name="Add member", when_pressed_function=self.render_add_member_screen, rely= 4)
        self.add(npyscreen.ButtonPress, name="Modify member", when_pressed_function=self.render_modify_member_screen)
        self.add(npyscreen.ButtonPress, name="Search member", when_pressed_function=self.render_search_member_screen)
        self.add(npyscreen.ButtonPress, name="Update password", when_pressed_function=self.render_update_consultants_password_screen)

        self.add(npyscreen.ButtonPress, name="Logout", when_pressed_function=self.switch_back_to_main_menu, rely=10, relx=2)

    def render_add_member_screen(self):
        self.parentApp.switchForm("NEW MEMBER")

    def render_modify_member_screen(self):
        self.parentApp.switchForm("MODIFY MEMBER")

    def render_search_member_screen(self):
        self.parentApp.switchForm("SEARCH MEMBER")

    def render_update_consultants_password_screen(self):
        self.parentApp.switchForm("UPDATE CONSULTANT PASSWORD")

    def switch_back_to_main_menu(self):
        cursor.execute('DELETE FROM active_user;')
        conn.commit()

        self.parentApp.switchForm("MAIN")

class SystemAdminsActions(npyscreen.FormBaseNew):
    def beforeEditing(self):
        cursor.execute("SELECT * FROM active_user;")
        user = cursor.fetchone()

        self.add(npyscreen.MultiLineEdit, editable=False, value=f"Username: {user[1]}, Role: {user[2]}", rely = 2, relx= 4)

    def create(self):
        self.add(npyscreen.ButtonPress, name="New admin", when_pressed_function=self.render_new_admin_screen, rely=4)
        self.add(npyscreen.ButtonPress, name="Modify admin", when_pressed_function=self.render_modify_admin_screen)
        self.add(npyscreen.ButtonPress, name="Delete admin", when_pressed_function=self.render_delete_admnin_screen)
        self.add(npyscreen.ButtonPress, name="Reset password", when_pressed_function=self.render_reset_password_screen)
        self.add(npyscreen.ButtonPress, name="Back to main", when_pressed_function=self.switch_back_to_main_menu, rely=10, relx=2)

    def render_new_admin_screen(self):
        self.parentApp.switchForm("NEW ADMIN")

    def render_modify_admin_screen(self):
        self.parentApp.switchForm("MODIFY ADMIN")

    def render_delete_admnin_screen(self):
        self.parentApp.switchForm("DELETE ADMIN")

    def render_reset_password_screen(self):
        self.parentApp.switchForm("RESET ADMIN PASSWORD")

    def switch_back_to_main_menu(self):
        self.parentApp.switchFormPrevious()

class SystemAdminsMenu(npyscreen.FormBaseNew):
    def beforeEditing(self):
        cursor.execute("SELECT * FROM active_user;")
        user = cursor.fetchone()

        self.add(npyscreen.MultiLineEdit, editable=False, value=f"Username: {user[1]}, Role: {user[2]}", rely = 2, relx= 4)

    def create(self):
        self.add(npyscreen.ButtonPress, name="Members", when_pressed_function=self.render_members_screen, rely= 4)
        self.add(npyscreen.ButtonPress, name="Consultants", when_pressed_function=self.render_consultants_screen)
        self.add(npyscreen.ButtonPress, name="Update password", when_pressed_function=self.render_update_system_admins_password_screen)
        self.add(npyscreen.ButtonPress, name="System", when_pressed_function=self.render_system_actions_screen)

        self.add(npyscreen.ButtonPress, name="Logout", when_pressed_function=self.switch_back_to_main_menu, rely=10)

    def render_members_screen(self):
        self.parentApp.switchForm("MEMBERS ACTIONS")

    def render_consultants_screen(self):
        self.parentApp.switchForm("CONSULTANTS ACTIONS")

    def render_update_system_admins_password_screen(self):
        self.parentApp.switchForm("UPDATE SYSTEM ADMINS PASSWORD")

    def render_system_actions_screen(self):
        self.parentApp.switchForm("SYSTEM ACTIONS")

    def switch_back_to_main_menu(self):
        cursor.execute('DELETE FROM active_user;')
        conn.commit()

        self.parentApp.switchForm("MAIN")

class SystemActions(npyscreen.FormBaseNew):
    def beforeEditing(self):
        cursor.execute("SELECT * FROM active_user;")
        user = cursor.fetchone()

        self.add(npyscreen.MultiLineEdit, editable=False, value=f"Username: {user[1]}, Role: {user[2]}", rely = 2, relx= 4)

    def create(self):
        self.add(npyscreen.ButtonPress, name="Users", when_pressed_function=self.render_users_screen, rely= 4)
        self.add(npyscreen.ButtonPress, name="Restore", when_pressed_function=self.render_restore_screen)
        self.add(npyscreen.ButtonPress, name="Backup", when_pressed_function=self.render_backup_screen)
        self.add(npyscreen.ButtonPress, name="Logs", when_pressed_function=self.render_logs_screen)

        self.add(npyscreen.ButtonPress, name="Back to main", when_pressed_function=self.switch_back_to_main_menu, rely=10)

    def render_users_screen(self):
        self.parentApp.switchForm("LIST USERS")

    def render_restore_screen(self):
        self.parentApp.switchForm("RESTORE")

    def render_backup_screen(self):
        self.parentApp.switchForm("BACKUP")

    def render_logs_screen(self):
        self.parentApp.switchForm("LOGS")

    def switch_back_to_main_menu(self):
        self.parentApp.switchFormPrevious()

class SuperAdminsMenu(npyscreen.FormBaseNew):
    def beforeEditing(self):
        cursor.execute("SELECT * FROM active_user;")
        user = cursor.fetchone()

        self.add(npyscreen.MultiLineEdit, editable=False, value=f"Username: {user[1]}, Role: {user[2]}", rely = 2, relx= 4)

    def create(self):
        self.add(npyscreen.ButtonPress, name="Members", when_pressed_function=self.render_members_screen, rely= 4)
        self.add(npyscreen.ButtonPress, name="Consultants", when_pressed_function=self.render_consultants_screen)
        self.add(npyscreen.ButtonPress, name="System admins", when_pressed_function=self.render_system_admnins_screen)
        self.add(npyscreen.ButtonPress, name="System", when_pressed_function=self.render_system_actions_screen)

        self.add(npyscreen.ButtonPress, name="Logout", when_pressed_function=self.switch_back_to_main_menu, rely=10)

    def render_members_screen(self):
        self.parentApp.switchForm("MEMBERS ACTIONS")

    def render_consultants_screen(self):
        self.parentApp.switchForm("CONSULTANTS ACTIONS")

    def render_system_admnins_screen(self):
        self.parentApp.switchForm("SYSTEM ADMINS ACTIONS")

    def render_system_actions_screen(self):
        self.parentApp.switchForm("SYSTEM ACTIONS")

    def switch_back_to_main_menu(self):
        cursor.execute('DELETE FROM active_user;')
        conn.commit()

        self.parentApp.switchForm("MAIN")

# ---------------------------------------------------------- Menus -------------------------------------------------------------------

class App(npyscreen.NPSAppManaged):
    def onStart(self):
        # Menus
        self.addForm("MAIN", LoginForm, name="Login")
        self.addForm("CONSULTANTS MENU", ConsultantsMenu, name="Consultants menu")
        self.addForm("SYSTEM ADMINS MENU", SystemAdminsMenu, name="System admins menu")
        self.addForm("SUPER ADMINS MENU", SuperAdminsMenu, name="Super admins menu")
        self.addForm("USERS LIST", UsersMenu, name="Users list")

        # Actions
        self.addForm("MEMBERS ACTIONS", MembersActions, name="Consultants actions")
        self.addForm("CONSULTANTS ACTIONS", ConsultantsActions, name="Consultants actions")
        self.addForm("SYSTEM ADMINS ACTIONS", SystemAdminsActions, name="Admins actions")
        self.addForm("SYSTEM ACTIONS", SystemActions, name="System actions")

        #Forms
        self.addForm('NEW MEMBER', AddMemberForm, name='New member')
        self.addForm('MODIFY MEMBER', ModifyMemberForm, name='Modify member')
        self.addForm('DELETE MEMBER', DeleteMemberForm, name='Delete member')
        self.addForm('SEARCH MEMBER', SearchMemberForm, name='Search member')

        self.addForm('NEW CONSULTANT', AddConsultantForm, name='New consultant')
        self.addForm('MODIFY CONSULTANT', ModifyConsultantForm, name='Modify consultant')
        self.addForm('DELETE CONSULTANT', DeleteConsultantForm, name='Delete consultant')
        self.addForm('UPDATE CONSULTANT PASSWORD', UpdateConsultantPasswordForm, name='Update consultant password')
        self.addForm('RESET CONSULTANT PASSWORD', ResetConsultantPasswordForm, name='Reset consultant password')

        self.addForm('NEW ADMIN', AddAdminForm, name='New admin')
        self.addForm('MODIFY ADMIN', ModifyAdminForm, name='Modify admin')
        self.addForm('DELETE ADMIN', DeleteAdminForm, name='Delete admin')
        self.addForm('UPDATE SYSTEM ADMINS PASSWORD', UpdateAdminsPasswordForm, name='Update admin password')
        self.addForm('RESET ADMIN PASSWORD', ResetAdminsPasswordForm, name='Reset admin password')

        # Screens
        self.addForm('LIST USERS', UserOverviewScreen, name='List users')
        self.addForm('RESTORE', RestoreScreen, name='Restore')
        self.addForm('BACKUP', BackupScreen, name='Backup')
        self.addForm('LOGS', LogScreen, name='Logs')

if __name__ == '__main__':
    if not os.path.exists(data_directory):
        os.makedirs(data_directory)

    db_path = os.path.join(data_directory, db_name)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute(
        '''CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL,
                first_name TEXT NOT NULL,
                last_name TEXT NOT NULL,
                temporary INTEGER NOT NULL,
                expiration DATETIME DEFAULT NULL,
                registration_date DATETIME NOT NULL,
                failed_attempts INTEGER DEFAULT 0
        )'''
    )

    cursor.execute(
        '''CREATE TABLE IF NOT EXISTS members (
                id INTEGER PRIMARY KEY,
                first_name TEXT NOT NULL,
                last_name TEXT NOT NULL,
                age INTEGER NOT NULL,
                gender TEXT NOT NULL,
                weight INTEGER NOT NULL,
                street_name TEXT NOT NULL,
                house_number INTEGER NOT NULL,
                zip_code TEXT NOT NULL,
                city TEXT NOT NULL,
                email_address TEXT NOT NULL,
                mobile_phone TEXT NOT NULL
        )'''
    )

    cursor.execute(
        '''CREATE TABLE IF NOT EXISTS active_user (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                role TEXT NOT NULL
        )'''
    )

    cursor.execute("SELECT * FROM users WHERE username = ? and role = ?", ("super_admin", "SUPER ADMIN"))
    super_Admin = cursor.fetchone()

    if not super_Admin:
        hashed_password = bcrypt.hashpw("Admin_123?".encode('utf-8'), bcrypt.gensalt())
        registration_date = datetime.now()

        cursor.execute('INSERT INTO users (username, password, role, first_name, last_name, temporary, expiration, registration_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        ("super_admin", hashed_password.decode('utf-8'), "SUPER ADMIN", "", "", 0, None, registration_date))

    cursor.execute('DELETE FROM active_user;')
    conn.commit()

    if not os.path.exists(log_path):
        with open(log_path, "w") as file:
            pass
    
    key = Fernet.generate_key()

    if not os.path.exists(key_path):
        with open(key_path, 'wb') as key_file:
            key_file.write(key)

    app = App()
    app.run()