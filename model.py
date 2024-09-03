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

# Function to fetch a user by username
def get_user_by_username(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    return user

# Function to save a new user
def save_user(username, User_Role, hashed_password):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (username,User_Role, password) VALUES (%s,%s,%s)", (username, User_Role, hashed_password))
    conn.commit()
    cursor.close()
    conn.close()

# Function to generate a JWT token
def generate_jwt_token(username, jwt_secret):
    payload = {
        'user': username,
        'exp': datetime.utcnow() + timedelta(hours=1)  # Token expires in 1 hour
    }
    token = jwt.encode(payload, jwt_secret, algorithm='HS256')
    return token

# Function to decode a JWT token
def decode_jwt_token(token, jwt_secret):
    try:
        decoded = jwt.decode(token, jwt_secret, algorithms=['HS256'])
        return decoded['user']
    except jwt.ExpiredSignatureError:
        return None  # Token has expired
    except jwt.InvalidTokenError:
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


# Function to initialize the database
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create the users table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
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

    conn.commit()
    cursor.close()
    conn.close()