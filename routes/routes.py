from flask import request, session, redirect, url_for, flash, render_template
from models.model import get_user_by_username, save_user, update_user_verification_code, update_user_password
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import jwt
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
import requests

# Replace with your reCAPTCHA secret key
RECAPTCHA_SECRET_KEY = '6LdyBisqAAAAAFMn8RKKJU3yxIxggaX6kVk1fi5G'
jwt_secret = secrets.token_urlsafe(32)  # Secret key for JWT

def register_routes(app):
    # Route to load the index page
    @app.route("/")
    def index():
        if 'jwt_token' in session:
            user = decode_jwt_token(session['jwt_token'])
            if user:
                return render_template('index.html', logged_in=True, user=user)
        return render_template('index.html', logged_in=False)

    # Route to handle user registration
    @app.route("/register", methods=['GET', 'POST'])
    def register():
        if request.method == 'POST':
            username = request.form['txtUSerEmail']
            user_role = request.form['User_Role']
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
            save_user(username, user_role, hashed_password)

            # Generate verification code and save it
            verification_code = generate_verification_code()
            code_expires_at = datetime.utcnow() + timedelta(minutes=10)
            update_user_verification_code(username, verification_code, code_expires_at)

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

            user = get_user_by_username(username)
            if user is None:
                flash("Invalid email!", "danger")
                return redirect(url_for('verify'))

            stored_code, code_expires_at = user[4], user[6]

            if datetime.utcnow() > code_expires_at:
                flash("Verification code expired. Please register again.", "danger")
                return redirect(url_for('register'))

            if stored_code != verification_code:
                flash("Invalid verification code!", "danger")
                return redirect(url_for('verify'))

            update_user_verification_code(username, None, None)
            flash("Account verified successfully! Please log in.", "success")
            return redirect(url_for('login'))
        return render_template('verify.html')

    # Route to handle user login
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

            user = get_user_by_username(username)
            if user is None:
                flash("Username not found!", "danger")
                return redirect(url_for('login'))

            is_verified = user[5]
            if not is_verified:
                flash("Account not verified! Please check your email.", "danger")
                return redirect(url_for('verify'))

            hashed_password = user[2]
            if not check_password_hash(hashed_password, password):
                flash("Incorrect password!", "danger")
                return redirect(url_for('login'))

            token = generate_jwt_token(username)
            session['jwt_token'] = token
            flash("Login successful!", "success")
            return redirect(url_for('index'))

        return render_template('login.html')

    # Route to handle forgot_password
    @app.route("/forgot_password", methods=['GET', 'POST'])
    def forgot_password():
        if request.method == 'POST':
            username = request.form['txtUSerEmail']
            user = get_user_by_username(username)
            if user is None:
                flash("Email not found!", "danger")
                return redirect(url_for('forgot_password'))

            verification_code = generate_verification_code()
            code_expires_at = datetime.utcnow() + timedelta(minutes=10)
            update_user_verification_code(username, verification_code, code_expires_at)

            send_verification_email(username, verification_code)
            flash("A verification code has been sent to your email.", "success")
            return redirect(url_for('verify_code', email=username))

        return render_template('forgot_password.html')

    # Route to handle verify_code
    @app.route("/verify_code", methods=['GET', 'POST'])
    def verify_code():
        if request.method == 'POST':
            username = request.form['email']
            verification_code = request.form['txtVerificationCode']

            user = get_user_by_username(username)
            if user is None:
                flash("Invalid email!", "danger")
                return redirect(url_for('verify_code', email=username))

            stored_code, code_expires_at = user[4], user[6]

            if datetime.utcnow() > code_expires_at:
                flash("Verification code expired. Please request a new one.", "danger")
                return redirect(url_for('forgot_password'))

            if stored_code != verification_code:
                flash("Invalid verification code!", "danger")
                return redirect(url_for('verify_code', email=username))

            flash("Verification code verified successfully! You can now reset your password.", "success")
            return redirect(url_for('reset_password', email=username))

        email = request.args.get('email')
        return render_template('verify_code.html', email=email)

    # Route to handle reset_password
    @app.route("/reset_password", methods=['GET', 'POST'])
    def reset_password():
        if request.method == 'POST':
            username = request.form['email']
            password = request.form['txtPassword']
            confirm_password = request.form['txtConfirm_Password']

            if password != confirm_password:
                flash("Passwords do not match!", "danger")
                return redirect(url_for('reset_password', email=username))

            hashed_password = generate_password_hash(password)
            update_user_password(username, hashed_password)
            flash("Password reset successfully! Please log in.", "success")
            return redirect(url_for('login'))

        email = request.args.get('email')
        return render_template('reset_password.html', email=email)

    # Function to generate a verification code
    def generate_verification_code():
        return secrets.token_hex(3).upper()

    # Function to send a verification email
    def send_verification_email(email, verification_code):
        sender_email = "your_email@example.com"
        sender_password = "your_email_password"
        receiver_email = email
        subject = "Your Verification Code"

        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = receiver_email
        msg['Subject'] = subject

        body = f"Your verification code is: {verification_code}"
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        text = msg.as_string()
        server.sendmail(sender_email, receiver_email, text)
        server.quit()

    # Function to generate a JWT token
    def generate_jwt_token(username):
        payload = {
            'username': username,
            'exp': datetime.utcnow() + timedelta(hours=1)  # Token expires in 1 hour
        }
        return jwt.encode(payload, jwt_secret, algorithm='HS256')

    # Function to decode a JWT token
    def decode_jwt_token(token):
        try:
            payload = jwt.decode(token, jwt_secret, algorithms=['HS256'])
            return payload['username']
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
