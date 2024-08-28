# model.py

import mysql.connector
import secrets
import jwt
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta

# Database connection function
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

# Initialize the database (create table if not exists)
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        user_role VARCHAR(50) NOT NULL DEFAULT 'user',
        verification_code VARCHAR(6),  -- Column to store the verification code
        is_verified BOOLEAN DEFAULT FALSE,  -- Column to track if the user is verified
        code_expires_at DATETIME,  -- Column to store the expiration time of the verification code
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP  -- Timestamp of when the user was created
    )
    ''')
    conn.commit()
    cursor.close()
    conn.close()
