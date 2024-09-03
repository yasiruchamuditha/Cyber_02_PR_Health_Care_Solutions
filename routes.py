# routes.py

from flask import Flask, request, jsonify, session, redirect, url_for, flash, render_template
from model import (
    decrypt_data, get_db_connection, get_user_by_username, save_checkup_details, save_user,
    generate_jwt_token, decode_jwt_token, generate_verification_code,
    send_verification_email, init_db
)

from datetime import datetime, timedelta
import requests
import secrets
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import os

# Initialize Flask app
app = Flask(__name__)
# Ensure this is in the correct file
app.secret_key = secrets.token_urlsafe(32)  

# Secret key for JWT
jwt_secret = secrets.token_urlsafe(32)
# Secret key for RECAPTCHA  
RECAPTCHA_SECRET_KEY = '6LdyBisqAAAAAFMn8RKKJU3yxIxggaX6kVk1fi5G'  

# Function to load the secret key from a file
def load_secret_key():
    key_file_upload = 'secret_key.key'
    if os.path.exists(key_file_upload):
        with open(key_file_upload, 'rb') as key_file:
            return key_file.read()
    else:
        raise FileNotFoundError("Secret key file not found.")

# Set up the upload folder and allowed extensions
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = load_secret_key()  # Load secret key from file

# Function to check if the uploaded file is allowed
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Route to upload prescription
@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # If the user does not select a file, the browser submits an empty file
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            flash('File successfully uploaded')
            return redirect(url_for('services'))
    return render_template('upload.html')


# Routes
# Index routes.Render the homepage. Check if user is logged in.
@app.route("/")
def index():
    if 'jwt_token' in session:
        user = decode_jwt_token(session['jwt_token'], jwt_secret)
        if user:
            return render_template('index.html', logged_in=True, user=user)
    return render_template('index.html', logged_in=False)

# Render the home page. Check if user is logged in.
@app.route("/home")
def home():
    if 'jwt_token' in session:
        user = decode_jwt_token(session['jwt_token'], jwt_secret)
        if user:
            return render_template('index.html', logged_in=True, user=user)
    return render_template('Login.html', logged_in=False)

# Render the services page. Check if user is logged in.
@app.route("/services")
def services():
    if 'jwt_token' in session:
        user = decode_jwt_token(session['jwt_token'], jwt_secret)
        if user:
            return render_template('Services.html', logged_in=True, user=user)
    return render_template('Login.html', logged_in=False)

# Handle regular checkup form in service page.
@app.route("/regular_checkup")
def s_regularCheckup():
    if 'jwt_token' in session:
        user = decode_jwt_token(session['jwt_token'], jwt_secret)
        if user:
            return render_template('regular_checkup.html', logged_in=True, user=user)
    return render_template('Login.html', logged_in=False)

# Handle prescriptions form in service page.
@app.route('/prescriptions')
def display_prescriptions():
    # List all files in the uploads directory
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template('prescriptions.html', files=files)

# Handle user registration
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


# Handle user verification under registration function
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

# Handle user login
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
        token = generate_jwt_token(username, jwt_secret)
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

# Route to handle user verify_code in user account verification
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


# Route to handle user reset_password
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

# Handle user logout
@app.route('/logout')
def logout():
    session.pop('jwt_token', None)
    flash("You have been logged out.", "success")
    return redirect(url_for('index'))

# Handle regular checkup form and insert regular checkup data with encryption.
@app.route("/regular_checkup", methods=['GET', 'POST'])
def regular_checkup():
    # Check if user is logged in
    if 'jwt_token' not in session:
        flash("You need to log in to access this page.", "warning")
        return redirect(url_for('login'))

    if request.method == 'POST':
        patient_nic = request.form['txtPatient_NIC']
        email = request.form['txtEmail']
        appointment_date = request.form['txtAppointment_Date']
        appointment_time = request.form['txtAppointment_Time']
        test_type = request.form['txtTest_Type']

        # Save the checkup details in the database
        save_checkup_details(patient_nic, email, appointment_date, appointment_time, test_type)

        flash("Your checkup details have been submitted successfully!", "success")
        return redirect(url_for('regular_checkup'))

    return render_template('regular_checkup.html')


@app.route('/checkup/<int:checkup_id>', methods=['GET'])
def get_checkup_details(checkup_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM regular_checkups WHERE id = %s", (checkup_id,))
    result = cursor.fetchone()
    
    if not result:
        return jsonify({"error": "Checkup details not found"}), 404

    # Decrypt the data
    decrypted_data = {
        'patient_nic': decrypt_data(result[1]),
        'email': decrypt_data(result[2]),
        'appointment_date': decrypt_data(result[3]),
        'appointment_time': decrypt_data(result[4]),
        'test_type': decrypt_data(result[5]),
        'submitted_at': result[6]
    }

    cursor.close()
    conn.close()

    return jsonify(decrypted_data), 200

# Handle regular checkup card view and select regular checkup data with decryption.
@app.route('/checkups')
def display_checkups():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)  # Fetch data as dictionaries
    cursor.execute("SELECT * FROM regular_checkups")
    checkups = cursor.fetchall()
    cursor.close()
    conn.close()

    # Decrypt the data before passing it to the template
    for checkup in checkups:
        checkup['patient_nic'] = decrypt_data(checkup['patient_nic'])
        checkup['email'] = decrypt_data(checkup['email'])
        checkup['appointment_date'] = decrypt_data(checkup['appointment_date'])
        checkup['appointment_time'] = decrypt_data(checkup['appointment_time'])
        checkup['test_type'] = decrypt_data(checkup['test_type'])

    return render_template('checkups.html', checkups=checkups)


