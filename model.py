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
        'exp': datetime.utcnow() + timedelta(minutes=2)  # Token expires in 2 minutes
    }
    token = jwt.encode(payload, jwt_secret, algorithm='HS256')
    return token


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

def send_welcome_email(to_email):
    from_email = "prcaretest@gmail.com"
    from_password = "rmtoagnrrqvjnzne"  # environment variable in production

    subject = 'Welcome to PRCARE Solutions!'
    # Customized HTML body with styling
    body = f'''
    <html>
    <body style="font-family: Arial, sans-serif; line-height: 1.6;">
        <div style="max-width: 600px; margin: auto; padding: 20px; text-align: left;">
            <h2 style="color: #333;">Welcome to PRCARE Solutions!</h2>
            <p>Dear User,</p>
            <p>We are excited to welcome you to PRCARE Solutions! Your registration was successful, and you can now log in to your account to explore all the features we offer.</p>
            <p>Here are some steps to help you get started:</p>
            <ul>
                <li>Explore our <strong>dashboard</strong> for managing your health services.</li>
                <li>Update your <strong>profile information</strong> to ensure we have the most accurate data.</li>
                <li>Check out our <strong>support center</strong> if you have any questions or need assistance.</li>
            </ul>
            <p>If you have any issues or need support, don't hesitate to reach out to our team at <a href="mailto:prcaretest@gmail.com">support@prcaresolutions.com</a>.</p>
            <p>We are thrilled to have you with us and look forward to serving you!</p>
            <p>Best regards,<br><strong>The PRCARE Solutions Team</strong></p>
            <hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;">
            <p style="font-size: 12px; color: #555;">This email was sent to {to_email}. If you did not sign up for this service, please ignore this email.</p>
        </div>
    </body>
    </html>
    '''

    msg = MIMEMultipart("alternative")
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject

    # Attach the HTML body
    msg.attach(MIMEText(body, 'html'))

    # Send the email
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(from_email, from_password)
    text = msg.as_string()
    server.sendmail(from_email, to_email, text)
    server.quit()



#Account verification - registration process
def send_verification_email(to_email, code):
    from_email = "prcaretest@gmail.com"
    from_password = "rmtoagnrrqvjnzne"  # Replace with environment variable in production

    subject = "Account Verification Code"
    # Updated HTML body with styling similar to the image
    body = f"""
    <html>
    <body style="font-family: Arial, sans-serif; line-height: 1.6;">
        <div style="max-width: 600px; margin: auto; border: 1px solid #ddd; padding: 20px; text-align: center;">
            <img src="https://cdn4.iconfinder.com/data/icons/social-messaging-ui-color-and-shapes-1/177800/01-1024.png" width="100" alt="logo">
            <h2 style="font-size: 24px; margin-bottom: 20px;">Verify your PRCARE account</h2>
            <p style="font-size: 16px;">PRCARE received a request to use <strong>{to_email}</strong> as a Account verification email for PRCARE Account.</p>
            <p style="font-size: 16px;">Use this code to finish account verification process :</p>
            <p style="font-size: 32px; font-weight: bold; margin: 20px 0;">{code}</p>
            <p style="font-size: 16px;">This code will expire in 5 minutes.</p>
            <hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;">
            <p style="font-size: 14px; color: #555;">If you don’t recognize <strong>{from_email}</strong>, you can safely ignore this email.</p>
            <p style="font-size: 14px; color: #555;">Please contact us through this <strong>{from_email}</strong> for more details.</p>
            <p style="font-size: 14px; color: #555;">Thanks for helping us keep your account secure.</p>
            <p style="font-size: 14px; color: #555;"><strong>Best regards,</strong><br>The PRCARE Team</p>
        </div>
    </body>
    </html>
    """

    msg = MIMEMultipart("alternative")
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject

    # Attach the HTML body
    msg.attach(MIMEText(body, 'html'))

    # Send the email
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(from_email, from_password)
    text = msg.as_string()
    server.sendmail(from_email, to_email, text)
    server.quit()

#Account verification - Recovery process
def send_recovery_code(to_email, code):
    from_email = "prcaretest@gmail.com"
    from_password = "rmtoagnrrqvjnzne"  # environment variable in production

    subject = "Account Recovery Code"
    # Updated HTML body with styling similar to the image
    body = f"""
    <html>
    <body style="font-family: Arial, sans-serif; line-height: 1.6;">
        <div style="max-width: 600px; margin: auto; border: 1px solid #ddd; padding: 20px; text-align: center;">
            <img src="https://cdn4.iconfinder.com/data/icons/social-messaging-ui-color-and-shapes-1/177800/01-1024.png" width="100" alt="logo">
            <h2 style="font-size: 24px; margin-bottom: 20px;">Verify your PRCARE account</h2>
            <p style="font-size: 16px;">PRCARE received a request to use <strong>{to_email}</strong> as a Account verification email for PRCARE Account.</p>
            <p style="font-size: 16px;">Use this code to finish account verification process :</p>
            <p style="font-size: 32px; font-weight: bold; margin: 20px 0;">{code}</p>
            <p style="font-size: 16px;">This code will expire in 5 minutes.</p>
            <hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;">
            <p style="font-size: 14px; color: #555;">If you don’t recognize <strong>{from_email}</strong>, you can safely ignore this email.</p>
            <p style="font-size: 14px; color: #555;">Please contact us through this <strong>{from_email}</strong> for more details.</p>
            <p style="font-size: 14px; color: #555;">Thanks for helping us keep your account secure.</p>
            <p style="font-size: 14px; color: #555;"><strong>Best regards,</strong><br>The PRCARE Team</p>
        </div>
    </body>
    </html>
    """

    msg = MIMEMultipart("alternative")
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject

    # Attach the HTML body
    msg.attach(MIMEText(body, 'html'))

    # Send the email
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(from_email, from_password)
    text = msg.as_string()
    server.sendmail(from_email, to_email, text)
    server.quit()

#Password reset succesful email
def send_successful_password_reset_email(to_email):
    from_email = "prcaretest@gmail.com"
    from_password = "rmtoagnrrqvjnzne"  # Replace with environment variable in production

    subject = "Password Reset Successful"
    body = f"""
    <html>
    <body style="font-family: Arial, sans-serif; line-height: 1.6;">
        <div style="max-width: 600px; margin: auto; padding: 20px; text-align: left;">
            <h2 style="color: #333;">Your Password Has Been Reset</h2>
            <p>Dear User,</p>
            <p>We wanted to let you know that your password has been successfully reset. You can now use your new password to log in to your account.</p>
            <p>If you did not request this change or believe an unauthorized person has accessed your account, please contact our support team immediately at <a href="mailto:prcaretest@gmail.com">support@prcaresolutions.com</a>.</p>
            <p>For your security, we recommend changing your password regularly and ensuring it is unique to our service.</p>
            <p>Thank you for choosing PRCARE Solutions. We're here to help if you have any further questions or concerns.</p>
            <p>Best regards,<br><strong>The PRCARE Solutions Team</strong></p>
            <hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;">
            <p style="font-size: 12px; color: #555;">This email was sent to you because of a password reset request. If you did not make this request, please contact support immediately.</p>
        </div>
    </body>
    </html>
    """

    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject

     # Attach the HTML body
    msg.attach(MIMEText(body, 'html'))

    # Send the email
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
    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP           
    )
    ''')

# Create the bookings table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS appointment_bookings (
    booking_id INT AUTO_INCREMENT PRIMARY KEY,
    user_email VARCHAR(255) NOT NULL,
    patient_nic VARCHAR(255) NOT NULL,
    preferred_date VARCHAR(255) NOT NULL,
    preferred_time VARCHAR(255) NOT NULL,
    doctor_email VARCHAR(255) NOT NULL,
    specialization VARCHAR(255) NOT NULL,
    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')


    conn.commit()
    cursor.close()
    conn.close()