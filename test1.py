#send the verification code and verify the account 
from flask import Flask,request,jsonify, request, session, redirect, url_for, flash, render_template
import mysql.connector
import secrets
import jwt
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import requests

# Author: Yasiru
# Contact: https://linktr.ee/yasiruchamuditha for more information.

# Create a secret key for session management
secret = secrets.token_urlsafe(32)
# Replace with your reCAPTCHA secret key
RECAPTCHA_SECRET_KEY = '6LdyBisqAAAAAFMn8RKKJU3yxIxggaX6kVk1fi5G'  

# Initialize the Flask app
app = Flask(__name__)
app.secret_key = secret
jwt_secret = secrets.token_urlsafe(32)  # Secret key for JWT

# Database connection function
def get_db_connection():
    return mysql.connector.connect(
        host='localhost',  # Change this to your database host
        user='root',  # Change this to your database user
        password='root',  # Change this to your database password
        database='flask_auth_db'  # Change this to your database name
    )

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
def generate_jwt_token(username):
    payload = {
        'user': username,
        'exp': datetime.utcnow() + timedelta(hours=1)  # Token expires in 1 hour
    }
    token = jwt.encode(payload, jwt_secret, algorithm='HS256')
    return token

# Function to decode a JWT token
def decode_jwt_token(token):
    try:
        decoded = jwt.decode(token, jwt_secret, algorithms=['HS256'])
        return decoded['user']
    except jwt.ExpiredSignatureError:
        return None  # Token has expired
    except jwt.InvalidTokenError:
        return None  # Invalid token

# Route to load the index page (which also serves as the home page after login)
@app.route("/")
def index():
    if 'jwt_token' in session:
        user = decode_jwt_token(session['jwt_token'])
        if user:
            return render_template('index.html', logged_in=True, user=user)
    return render_template('index.html', logged_in=False)

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

# Route to handle user registration
@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['txtUSerEmail']
        User_Role = request.form['User_Role']
        password = request.form['txtPassword']
        confirm_password = request.form['txtConfirm_Password']

        # Check if passwords match
        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for('register'))

        # Check if username already exists
        if get_user_by_username(username):
            flash("Username already taken!", "danger")
            return redirect(url_for('register'))

        # Hash the password and store the user in the database
        hashed_password = generate_password_hash(password)
        
        # Generate verification code
        verification_code = generate_verification_code()
        code_expires_at = datetime.utcnow() + timedelta(minutes=10)  # Code expires in 10 minutes

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, User_Role, password, verification_code, code_expires_at) VALUES (%s, %s, %s, %s, %s)", 
                       (username, User_Role, hashed_password, verification_code, code_expires_at))
        conn.commit()
        cursor.close()
        conn.close()

        # Send verification email
        send_verification_email(username, verification_code)

        flash("Registration successful! A verification code has been sent to your email.", "success")
        return render_template('verification.html')
    return render_template('register.html')

# Route to handle account verification
@app.route("/verify", methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':
        username = request.form['txtUSerEmail']
        verification_code = request.form['txtVerificationCode']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT verification_code, code_expires_at FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if user is None:
            flash("Invalid email!", "danger")
            return redirect(url_for('verify'))

        stored_code, code_expires_at = user

        if datetime.utcnow() > code_expires_at:
            flash("Verification code expired. Please register again.", "danger")
            cursor.close()
            conn.close()
            return redirect(url_for('register'))

        if stored_code != verification_code:
            flash("Invalid verification code!", "danger")
            return redirect(url_for('verify'))

        cursor.execute("UPDATE users SET is_verified = TRUE WHERE username = %s", (username,))
        conn.commit()
        cursor.close()
        conn.close()

        flash("Account verified successfully! Please log in.", "success")
        return redirect(url_for('login'))
    return render_template('verify.html')


# Route to handle user login
# @app.route("/login", methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         username = request.form['txtUSerEmail']
#         password = request.form['txtPassword']

#         # Retrieve the user from the database
#         conn = get_db_connection()
#         cursor = conn.cursor()
#         cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
#         user = cursor.fetchone()
#         cursor.close()
#         conn.close()

#         if user is None:
#             flash("Username not found!", "danger")
#             return redirect(url_for('login'))

#         # Check if user is verified
#         is_verified = user[4]
#         if not is_verified:
#             flash("Account not verified! Please check your email.", "danger")
#             return redirect(url_for('verify'))

#         # Verify the password
#         hashed_password = user[2]  # Password is in the third column
#         if not check_password_hash(hashed_password, password):
#             flash("Incorrect password!", "danger")
#             return redirect(url_for('login'))

#         # If login is successful, generate a JWT token
#         token = generate_jwt_token(username)
#         session['jwt_token'] = token
#         flash("Login successful!", "success")
#         return redirect(url_for('index'))
#     return render_template('login.html')

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        recaptcha_response = request.form.get('g-recaptcha-response')
        payload = {
            'secret': RECAPTCHA_SECRET_KEY,
            'response': recaptcha_response
        }
        response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=payload)
        result = response.json()

        if not result.get('success'):
            flash("reCAPTCHA verification failed. Please try again.", "danger")
            return redirect(url_for('login'))

        username = request.form['txtUSerEmail']
        password = request.form['txtPassword']

        # Retrieve the user from the database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user is None:
            flash("Username not found!", "danger")
            return redirect(url_for('login'))

        # Check if user is verified
        is_verified = user[4]  # Assuming 'is_verified' is in the fifth column
        if not is_verified:
            flash("Account not verified! Please check your email.", "danger")
            return redirect(url_for('verify'))

        # Verify the password
        hashed_password = user[2]  # Assuming hashed password is in the third column
        if not check_password_hash(hashed_password, password):
            flash("Incorrect password!", "danger")
            return redirect(url_for('login'))

        # If login is successful, generate a JWT token
        token = generate_jwt_token(username)
        session['jwt_token'] = token
        flash("Login successful!", "success")
        return redirect(url_for('index'))

    return render_template('login.html')

# Route to handle user forgot_password
@app.route("/forgot_password", methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['txtUSerEmail']

        # Check if the user exists
        user = get_user_by_username(username)
        if user is None:
            flash("Email not found!", "danger")
            return redirect(url_for('forgot_password'))

        # Generate a new verification code
        verification_code = generate_verification_code()
        code_expires_at = datetime.utcnow() + timedelta(minutes=10)  # Code expires in 10 minutes

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET verification_code = %s, code_expires_at = %s WHERE username = %s",
                       (verification_code, code_expires_at, username))
        conn.commit()
        cursor.close()
        conn.close()

        # Send the verification code via email
        send_verification_email(username, verification_code)

        flash("A verification code has been sent to your email.", "success")
        return redirect(url_for('verify_code', email=username))

    return render_template('forgot_password.html')

#Route to handle user verify_code
@app.route("/verify_code", methods=['GET', 'POST'])
def verify_code():
    if request.method == 'POST':
        username = request.form['txtUSerEmail']
        verification_code = request.form['txtVerificationCode']

        # Fetch the user and check the verification code
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT verification_code, code_expires_at FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if user is None:
            flash("Invalid email!", "danger")
            return redirect(url_for('verify_code', email=username))

        stored_code, code_expires_at = user

        if datetime.utcnow() > code_expires_at:
            flash("Verification code expired. Please try again.", "danger")
            cursor.close()
            conn.close()
            return redirect(url_for('forgot_password'))

        if stored_code != verification_code:
            flash("Invalid verification code!", "danger")
            return redirect(url_for('verify_code', email=username))

        # If the code is correct, store the username in the session and redirect to the reset password page
        session['verified_user'] = username
        flash("Verification successful! You can now reset your password.", "success")
        cursor.close()
        conn.close()
        return redirect(url_for('reset_password'))

    # If it's a GET request, render the verify_code page with the email pre-filled
    email = request.args.get('email')
    return render_template('verify_code.html', email=email)



#Route to handle user reset_password
@app.route("/reset_password", methods=['GET', 'POST'])
def reset_password():
    if 'verified_user' not in session:
        flash("You need to verify your account first.", "danger")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form['txtPassword']
        confirm_password = request.form['txtConfirm_Password']

        # Check if passwords match
        if new_password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for('reset_password'))

        username = session['verified_user']
        hashed_password = generate_password_hash(new_password)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password = %s WHERE username = %s", (hashed_password, username))
        conn.commit()
        cursor.close()
        conn.close()

        session.pop('verified_user', None)  # Clear the session
        flash("Password reset successfully! Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html')



# Route to log out and end the session
@app.route('/logout')
def logout():
    session.pop('jwt_token', None)  # Remove JWT token from session
    flash("Logged out successfully.", "info")
    return redirect(url_for('index'))

if __name__ == "__main__":
    init_db()  # Initialize the database and create tables
    app.run(debug=True)


# CREATE DATABASE IF NOT EXISTS flask_auth_db;

# USE flask_auth_db;

# CREATE TABLE IF NOT EXISTS users (
#     id INT AUTO_INCREMENT PRIMARY KEY,
#     username VARCHAR(255) UNIQUE NOT NULL,
#     password VARCHAR(255) NOT NULL,
#     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
# );
