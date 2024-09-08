# model.py
import mysql.connector
import secrets
import jwt
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
import base64
import os

# Load encryption key from environment variable or secure storage
key_file = 'encryption_key.key'

# Define the path to the key file
key_file_upload = 'secret_key.key'

def generate_key():
    return Fernet.generate_key()

def save_key(key):
    with open(key_file_upload, 'wb') as key_file:
        key_file.write(key)

if not os.path.exists(key_file_upload):
    key = generate_key()
    save_key(key)
    print("New secret key generated and saved.")
else:
    print("Secret key already exists.")

# Load the existing encryption key or generate a new one for encryption
def load_or_generate_key():
    if os.path.exists(key_file):
        with open(key_file, 'rb') as f:
            key = f.read()
    else:
        key = Fernet.generate_key()
        with open(key_file, 'wb') as f:
            f.write(key)
        os.chmod(key_file, 0o600)
    return key

encryption_key = load_or_generate_key()
fernet = Fernet(encryption_key)


# Database connection function
# Establish and return a connection to the database.
def get_db_connection():
    return mysql.connector.connect(
        host='localhost',         # Database host
        user='root',              # Database user
        password='root',          # Database password
        database='flask_auth_db'  # Database name
    )

# Function to fetch a user by UserEmail
def get_user_by_UserEmail(UserEmail):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE UserEmail = %s", (UserEmail,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    return user

# Function to save a new user
def save_user(UserEmail, User_Role, hashed_password):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (UserEmail,User_Role, password) VALUES (%s,%s,%s)", (UserEmail, User_Role, hashed_password))
    conn.commit()
    cursor.close()
    conn.close()

# Function to generate a JWT token
def generate_jwt_token(UserEmail, jwt_secret):
    payload = {
        'user': UserEmail,
        'exp': datetime.utcnow() + timedelta(minutes=30)  # Token expires in 30 minutes
    }
    token = jwt.encode(payload, jwt_secret, algorithm='HS256')
    return token

# # Function to decode a JWT token
# def decode_jwt_token(token, jwt_secret):
#     try:
#         decoded = jwt.decode(token, jwt_secret, algorithms=['HS256'])
#         return decoded['user']
#     except jwt.ExpiredSignatureError:
#         print("Token has expired")
#         return None  # Token has expired
#     except jwt.InvalidTokenError:
#         print("Invalid token")
#         return None  # Invalid token

def decode_jwt_token(token, jwt_secret):
    try:
        decoded = jwt.decode(token, jwt_secret, algorithms=['HS256'])
        return decoded['user']
        
    except jwt.ExpiredSignatureError:
        print("Token has expired")
        return None  # Token has expired
    except jwt.InvalidTokenError:
        print("Invalid token")
        return None  # Invalid token


# Function to generate a random verification code
def generate_verification_code():
    return secrets.token_hex(3).upper()  # Generates a 6-character alphanumeric code

# Function to send verification code via email
def send_verification_email(to_email, code):
    from_email = "prcaretest@gmail.com"
    from_password = "rmtoagnrrqvjnzne"

    subject = "Your Verification Code"
    body = f"Your verification code is: {code}"

    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(from_email, from_password)
    text = msg.as_string()
    server.sendmail(from_email, to_email, text)
    server.quit()

# Function to save checkup details with encryption
def save_checkup_details(patient_nic, email, appointment_date, appointment_time, test_type):
    conn = get_db_connection()
    cursor = conn.cursor()

    encrypted_nic = encrypt_data(patient_nic)
    encrypted_email = encrypt_data(email)
    encrypted_date = encrypt_data(appointment_date)
    encrypted_time = encrypt_data(appointment_time)
    encrypted_type = encrypt_data(test_type)

    cursor.execute('''
        INSERT INTO regular_checkups (patient_nic, email, appointment_date, appointment_time, test_type, submitted_at)
        VALUES (%s, %s, %s, %s, %s, %s)
    ''', (encrypted_nic, encrypted_email, encrypted_date, encrypted_time, encrypted_type, datetime.utcnow()))

    conn.commit()
    cursor.close()
    conn.close()

# Encrypt the data using Fernet symmetric encryption
def encrypt_data(data):
    return fernet.encrypt(data.encode())

# Decrypt the encrypted data using Fernet symmetric encryption.
def decrypt_data(encrypted_data):
    return fernet.decrypt(encrypted_data).decode()


# Function to save doctor details with encryption
def save_doctor_details(user_email, medical_no, specialization, grad_year, experience_years,workplace,work_address):
    conn = get_db_connection()
    cursor = conn.cursor()

    encrypted_email = encrypt_data(user_email)
    encrypted_medical_no = encrypt_data(medical_no)
    encrypted_specialization = encrypt_data(specialization)
    encrypted_grad_year = encrypt_data(grad_year)
    encrypted_experience_years = encrypt_data(experience_years)
    encrypted_workplace = encrypt_data(workplace)
    encrypted_work_address = encrypt_data(work_address)

    cursor.execute('''
        INSERT INTO doctors (user_email, medical_no, specialization, grad_year, experience_years, workplace, work_address, submitted_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    ''', (encrypted_email, encrypted_medical_no, encrypted_specialization, encrypted_grad_year, encrypted_experience_years,encrypted_workplace, encrypted_work_address, datetime.utcnow()))

    conn.commit()
    cursor.close()
    conn.close()


def send_successful_password_reset_email(user_email):
    smtp_server = 'smtp.example.com'  # Replace with your SMTP server
    smtp_port = 587  # Typically 587 for TLS
    smtp_user = 'prcaretest@gmail.com'  # Replace with your SMTP email
    smtp_password = 'rmtoagnrrqvjnzne'  # Replace with your SMTP password

    subject = 'Password Reset Successful'
    body = '''
    Dear User,

    Your password has been successfully reset. If you did not request this change, please contact our support team immediately.

    Best regards,
    Your Company Name
    '''

    msg = MIMEMultipart()
    msg['From'] = smtp_user
    msg['To'] = user_email
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()  # Upgrade the connection to a secure encrypted SSL/TLS connection
            server.login(smtp_user, smtp_password)
            server.sendmail(msg['From'], msg['To'], msg.as_string())
        print("Email sent successfully.")
    except Exception as e:
        print(f"Error sending email: {e}")


def send_welcome_email(user_email):
    smtp_server = 'smtp.example.com'  # Replace with your SMTP server
    smtp_port = 587  # Typically 587 for TLS
    smtp_user = 'your_email@example.com'  # Replace with your SMTP email
    smtp_password = 'your_password'  # Replace with your SMTP password

    subject = 'Welcome to Our Service!'
    body = f'''
    Dear User,

    Welcome to our service! We're excited to have you on board.

    Your registration was successful. You can now log in to your account and start using our features.

    If you have any questions or need assistance, feel free to contact our support team.

    Best regards,
    Your Company Name
    '''

    msg = MIMEMultipart()
    msg['From'] = smtp_user
    msg['To'] = user_email
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()  # Upgrade the connection to a secure encrypted SSL/TLS connection
            server.login(smtp_user, smtp_password)
            server.sendmail(msg['From'], msg['To'], msg.as_string())
        print("Welcome email sent successfully.")
    except Exception as e:
        print(f"Error sending welcome email: {e}")


# Function to initialize the database
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create the users table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        UserEmail VARCHAR(255) PRIMARY KEY  NOT NULL,
        password VARCHAR(255) NOT NULL,
        user_role VARCHAR(255) NOT NULL DEFAULT 'user',
        verification_code VARCHAR(6),  -- Column to store the verification code
        is_verified BOOLEAN DEFAULT FALSE,  -- Column to track if the user is verified
        code_expires_at DATETIME,  -- Column to store the expiration time of the verification code
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP  -- Timestamp of when the user was created
    )
    ''')

    # Create the regular_checkups table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS regular_checkups (
        patient_nic VARCHAR(255) NOT NULL PRIMARY KEY,
        email VARCHAR(255) NOT NULL,
        appointment_date VARCHAR(255) NOT NULL,
        appointment_time VARCHAR(255) NOT NULL,
        test_type VARCHAR(255) NOT NULL,
        submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    # Create the doctors table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS doctors (
        user_email VARCHAR(255) NOT NULL PRIMARY KEY,
        medical_no VARCHAR(255) NOT NULL,
        specialization VARCHAR(255) NOT NULL,
        grad_year VARCHAR(255) NOT NULL,
        experience_years VARCHAR(255) NOT NULL,
        workplace VARCHAR(255) NOT NULL,
        work_address VARCHAR(255) NOT NULL,
        submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    # Create the user_sessions table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS user_sessions  (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id VARCHAR(255) NOT NULL,
        login_time DATETIME NOT NULL,
        logout_time DATETIME,
        FOREIGN KEY (user_id) REFERENCES users(UserEmail),
        submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP           
    )
    ''')

    # Create the user_actions table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS user_actions   (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    action_type VARCHAR(255) NOT NULL,
    action_time DATETIME NOT NULL,
    details TEXT,
    FOREIGN KEY (user_id) REFERENCES users(UserEmail),
    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP           
    )
    ''')


  # Create the database_audit  table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS database_audit    (
    id INT AUTO_INCREMENT PRIMARY KEY,
    table_name VARCHAR(255) NOT NULL,
    record_id INT NOT NULL,
    change_type ENUM('INSERT', 'UPDATE', 'DELETE') NOT NULL,
    change_time DATETIME NOT NULL,
    changed_by VARCHAR(255) NOT NULL,
    old_values TEXT,
    new_values TEXT,
    FOREIGN KEY (changed_by) REFERENCES users(UserEmail),
    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP           
    )
    ''')

# Create the bookings table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS appointment_bookings (
    booking_id INT AUTO_INCREMENT PRIMARY KEY,
    user_email VARCHAR(255) NOT NULL,
    patient_nic VARCHAR(255) NOT NULL,
    preferred_date DATE NOT NULL,
    preferred_time TIME NOT NULL,
    doctor_email VARCHAR(255) NOT NULL,
    specialization VARCHAR(255) NOT NULL,
    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')


    conn.commit()
    cursor.close()
    conn.close()