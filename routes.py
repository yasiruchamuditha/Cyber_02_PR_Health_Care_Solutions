# routes.py

from flask import Flask, request, jsonify, session, redirect, url_for, flash, render_template
from model import (
    decrypt_data, encrypt_data, get_db_connection, get_user_by_UserEmail, save_checkup_details, save_user,
    generate_jwt_token, decode_jwt_token, generate_verification_code, send_recovery_code, send_successful_password_reset_email,
    send_verification_email,save_doctor_details, send_welcome_email
)

from datetime import datetime, timedelta # Import the datetime class from the datetime module    
import requests # Import the requests module
import secrets # Import the secrets module
from werkzeug.utils import secure_filename # Import the secure_filename function from the werkzeug.utils module
from werkzeug.security import generate_password_hash, check_password_hash # Import the generate_password_hash and check_password_hash functions from the werkzeug.security module
import os # Import the os module
import jwt # Import the jwt module

# Initialize Flask app
app = Flask(__name__)
# Ensure this is in the correct file
app.secret_key = secrets.token_urlsafe(32)  

# Secret key for JWT
jwt_secret = secrets.token_urlsafe(32)
# Secret key for RECAPTCHA  
RECAPTCHA_SECRET_KEY = 'RECAPTCHA_SECRET_KEY'  

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

# Function to create user-specific directory
def create_user_folder(user_email):
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], user_email)
    if not os.path.exists(user_folder):
        os.makedirs(user_folder)
    return user_folder

# Function to add timestamp to filename
def add_timestamp_to_filename(filename):
    # Get current date and time
    current_time = datetime.now().strftime('%Y%m%d_%H%M%S')
    # Split the file name and extension
    name, ext = os.path.splitext(filename)
    # Create new filename with timestamp
    return f"{name}_{current_time}{ext}"


# Routes
# Route to upload prescription
@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    # Check if the user is logged in
    if 'jwt_token' not in session:
        flash("You need to log in to upload a prescription.", "warning")
        return redirect(url_for('login'))
    
    user_email = session['user_email']  # Get the logged-in user's email from the session
    
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        
        file = request.files['file']
        
        # If the user does not select a file, the browser submits an empty file
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
        
        # Check if the file is allowed (correct extension)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filename_with_timestamp = add_timestamp_to_filename(filename)
            # Save the file to the specified upload folder
            #file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            # Create a folder for the user based on their email
            user_folder = create_user_folder(user_email)
            # Save the file in the user's folder
            #file_path = os.path.join(user_folder, filename)
            # Save the file in the user's folder with the new filename
            file_path = os.path.join(user_folder, filename_with_timestamp)
            file.save(file_path)
            flash('File successfully uploaded', 'success')
            return redirect(url_for('services'))
        else:
            flash('Invalid file format. Please upload a valid image file.', 'danger')
            return redirect(request.url)
    
    return render_template('upload.html')


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
    flash("You need to log in to book a checkup.", "warning")    
    return render_template('Login.html', logged_in=False)

# Handle prescriptions form in service page.
@app.route('/prescriptions')
def display_prescriptions():
    # Check if the user is logged in
    if 'user_email' not in session:
        flash("You need to log in to view prescriptions.", "warning")
        return redirect(url_for('login'))
    # List all files in the uploads directory
    #files = os.listdir(app.config['UPLOAD_FOLDER'])
    #return render_template('prescriptions.html', files=files)
    # Get the logged-in user's email from the JWT token
    user_email = session['user_email']  # Get the logged-in user's email from the session
    
    # Create a folder path for the user
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], user_email)

    # Ensure the user's folder exists
    if os.path.exists(user_folder):
        # List all files in the user's folder and get their creation times
        files = []
        for filename in os.listdir(user_folder):
            file_path = os.path.join(user_folder, filename)
            if os.path.isfile(file_path):
                # Get the file's modification time
                timestamp = os.path.getmtime(file_path)
                # Convert to a readable date format
                upload_time = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                files.append({'name': filename, 'upload_time': upload_time})
    else:
        files = []  # If no folder, assume no files uploaded yet

    # Pass the files to the template for display
    return render_template('prescriptions.html', files=files)

# Handle user registration
@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        UserEmail = request.form['txtUserEmail']
        User_Role = request.form['User_Role']
        password = request.form['txtPassword']
        confirm_password = request.form['txtConfirm_Password']

        # Check if passwords match
        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for('register'))

        # Check if USer Email already exists
        if get_user_by_UserEmail(UserEmail):
            flash("User Email already taken!", "danger")
            return redirect(url_for('register'))

        # Hash the password and store the user in the database
        hashed_password = generate_password_hash(password)
        
        # Generate verification code
        verification_code = generate_verification_code()
        code_expires_at = datetime.utcnow() + timedelta(minutes=5)  # Code expires in 5 minutes

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (UserEmail, User_Role, password, verification_code, code_expires_at) VALUES (%s, %s, %s, %s, %s)", 
                       (UserEmail, User_Role, hashed_password, verification_code, code_expires_at))
        conn.commit()
        cursor.close()
        conn.close()

        # Send verification email
        send_verification_email(UserEmail, verification_code)

        flash("Registration successful! A verification code has been sent to your email.", "success")
        return render_template('verification.html')
    return render_template('register.html')


# Handle user verification under registration function
@app.route("/verify", methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':
        UserEmail = request.form['txtUserEmail']
        verification_code = request.form['txtVerificationCode']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT verification_code, code_expires_at FROM users WHERE UserEmail = %s", (UserEmail,))
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

        cursor.execute("UPDATE users SET is_verified = TRUE WHERE UserEmail = %s", (UserEmail,))
        conn.commit()
        cursor.close()
        conn.close()

        flash("Account verified successfully! Please log in.", "success")
        send_welcome_email(UserEmail)
        return redirect(url_for('login'))
    return render_template('verification.html')


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

        UserEmail = request.form['txtUserEmail']
        password = request.form['txtPassword']

        # Retrieve the user from the database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE UserEmail = %s", (UserEmail,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user is None:
            flash("UserEmail not found!", "danger")
            return redirect(url_for('login'))

        # Check if user is verified
        is_verified = user[4]  # Assuming 'is_verified' is in the fifth column
        if not is_verified:
            flash("Account not verified! Please check your email.", "danger")
            # Generate a new verification code
            verification_code = generate_verification_code()
            code_expires_at = datetime.utcnow() + timedelta(minutes=10)  # Code expires in 10 minutes
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET verification_code = %s, code_expires_at = %s WHERE UserEmail = %s", (verification_code, code_expires_at, UserEmail))
            conn.commit()
            cursor.close()
            conn.close()
            # Send verification email
            send_verification_email(UserEmail, verification_code)
            return redirect(url_for('verify'))

        # Verify the password
        hashed_password = user[1]  # Assuming hashed password is in the second column
        if not check_password_hash(hashed_password, password):
            flash("Incorrect password!", "danger")
            return redirect(url_for('login'))
        
        # Determine the user's role
        user_role  = user[2]  # Assuming 'role' is in the third column

        # If login is successful, generate a JWT token
        token = generate_jwt_token(UserEmail, jwt_secret)
        session['jwt_token'] = token
        session['user_role'] = user_role  
        session['user_email'] = UserEmail
        
        # Record the login session
        record_user_login(UserEmail)

        flash("Login successful!", "success")
        #return redirect(url_for('index'))
        if user_role == 'admin':
            return redirect(url_for('admin_dashboard'))  # Redirect to admin dashboard
        else:
            return redirect(url_for('index'))  # Redirect to regular user index

    return render_template('login.html')


# Route to handle user forgot_password
@app.route("/forgot_password", methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        UserEmail = request.form['txtUserEmail']

        # Check if the user exists
        user = get_user_by_UserEmail(UserEmail)
        if user is None:
            flash("Email not found!", "danger")
            return redirect(url_for('forgot_password'))

        # Generate a new verification code
        verification_code = generate_verification_code()
        code_expires_at = datetime.utcnow() + timedelta(minutes=10)  # Code expires in 10 minutes

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET verification_code = %s, code_expires_at = %s WHERE UserEmail = %s",
                       (verification_code, code_expires_at, UserEmail))
        conn.commit()
        cursor.close()
        conn.close()

        # Send the verification code via email
        #send_verification_email(UserEmail, verification_code)
        send_recovery_code(UserEmail, verification_code)

        flash("A verification code has been sent to your email.", "success")
        return redirect(url_for('verify_code', email=UserEmail))

    return render_template('forgot_password.html')

# Route to handle user verify_code in user account verification
@app.route("/verify_code", methods=['GET', 'POST'])
def verify_code():
    if request.method == 'POST':
        UserEmail = request.form['txtUserEmail']
        verification_code = request.form['txtVerificationCode']

        # Fetch the user and check the verification code
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT verification_code, code_expires_at FROM users WHERE UserEmail = %s", (UserEmail,))
        user = cursor.fetchone()

        if user is None:
            flash("Invalid email!", "danger")
            return redirect(url_for('verify_code', email=UserEmail))

        stored_code, code_expires_at = user

        if datetime.utcnow() > code_expires_at:
            flash("Verification code expired. Please try again.", "danger")
            cursor.close()
            conn.close()
            return redirect(url_for('forgot_password'))

        if stored_code != verification_code:
            flash("Invalid verification code!", "danger")
            return redirect(url_for('verify_code', email=UserEmail))

        # If the code is correct, store the username in the session and redirect to the reset password page
        session['verified_user'] = UserEmail
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

        UserEmail = session['verified_user']
        hashed_password = generate_password_hash(new_password)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password = %s WHERE UserEmail = %s", (hashed_password, UserEmail))
        conn.commit()
        cursor.close()
        conn.close()

        session.pop('verified_user', None)  # Clear the session
        flash("Password reset successfully! Please log in.", "success")
        # Send success email
        send_successful_password_reset_email(UserEmail)
        return redirect(url_for('login'))

    return render_template('reset_password.html')


# Handle user logout
@app.route('/logout')
def logout():
    user_email = session.get('user_email')

    if user_email:
        # Record the logout session
        record_user_logout(user_email)
        # Track logout action
        track_user_action(user_email, 'logout')
    
    # Clear the session
    session.pop('jwt_token', None)
    session.pop('user_email', None)  # Also remove the user email from the session
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

        # Track checkup submission
        user_email = session.get('user_email')
        #track_user_action(user_email, f"submitted checkup for patient {patient_nic}")


        flash("Your checkup details have been submitted successfully!", "success")
        return render_template('services.html')

    return render_template('regular_checkup.html')

# Handle regular checkup card view and select regular checkup data with decryption.
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

# # Handle regular checkup card view and select regular checkup data with decryption.
@app.route('/checkups')
def display_checkups():
    # Check if user is logged in
    if 'jwt_token' not in session:
        flash("You need to log in to access this page.", "warning")
        return redirect(url_for('login'))
    # Get the logged-in user's email from the session
    user_email = session.get('user_email')
    #print("User email from session: ", user_email)

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)  # Fetch data as dictionaries
    cursor.execute("SELECT * FROM regular_checkups")
    checkups = cursor.fetchall()
    cursor.close()
    conn.close()

    # Decrypt data and filter based on user's email
    filtered_checkups = []
    for checkup in checkups:
        # Decrypt data
        checkup['patient_nic'] = decrypt_data(checkup['patient_nic'])
        checkup['email'] = decrypt_data(checkup['email'])
        checkup['appointment_date'] = decrypt_data(checkup['appointment_date'])
        checkup['appointment_time'] = decrypt_data(checkup['appointment_time'])
        checkup['test_type'] = decrypt_data(checkup['test_type'])
        
        # Filter based on user's email
        if checkup['email'] == user_email:
            filtered_checkups.append(checkup)

    return render_template('checkups.html', checkups=filtered_checkups)


# Handle doctor registration form and insert doctor registration data with encryption.
@app.route("/register_doctor", methods=['GET', 'POST'])
def register_doctor():
    # Check if user is logged in
    if 'jwt_token' not in session:
        flash("You need to log in to access this page.", "warning")
        return redirect(url_for('login'))

    if request.method == 'POST':
        user_email = request.form['txtUserEmail']
        medical_no = request.form['txtMedicalNo']
        specialization = request.form['Specialization']
        grad_year = request.form['txtGYears']
        experience_years = request.form['txtEYears']
        workplace = request.form['txtWorkplace']
        work_address = request.form['txtWorkAddress']

        # Save the doctor details in the database
        save_doctor_details(user_email, medical_no, specialization, grad_year, experience_years, workplace, work_address)

        flash("Your checkup details have been submitted successfully!", "success")
        return redirect(url_for('admin_dashboard'))

    return render_template('register_doctor.html')

# Route to display the users in table view
@app.route('/admin/users')
def user_management():
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    cursor.close()
    connection.close()
    return render_template('user_management.html', users=users)

# Route to delete a user based on their email (primary key)
@app.route('/admin/users/delete/<UserEmail>', methods=['POST'])
def delete_user(UserEmail):
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("DELETE FROM users WHERE UserEmail = %s", (UserEmail,))
    connection.commit()
    cursor.close()
    connection.close()
    flash('User deleted successfully!')
    return redirect(url_for('user_management'))

# Route to update a user
@app.route('/admin/users/update/<UserEmail>', methods=['GET', 'POST'])
def update_user(UserEmail):
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    if request.method == 'POST':
        user_role = request.form['user_role']
        is_verified = request.form['is_verified']

        cursor.execute("""
            UPDATE users 
            SET user_role = %s, is_verified = %s 
            WHERE UserEmail = %s
        """, (user_role, is_verified, UserEmail))
        connection.commit()
        flash('User updated successfully!')
        return redirect(url_for('user_management'))

    cursor.execute("SELECT * FROM users WHERE UserEmail = %s", (UserEmail,))
    user = cursor.fetchone()
    cursor.close()
    connection.close()
    return render_template('update_user.html', user=user)

# Route to handle admin dashboard route in login method
@app.route("/admin_dashboard")
def admin_dashboard():
    if 'jwt_token' not in session or session['user_role'] != 'admin':
        flash("Access denied. Admins only.", "danger")
        return redirect(url_for('login'))
    return render_template('admin_dashboard.html')


# Doctor Management
@app.route("/doctor_registration")
def doctor_registration():
    if 'jwt_token' not in session or session['user_role'] != 'admin':
        flash("Access denied. Admins only. Please Logging to the system.", "danger")
        return redirect(url_for('login'))
    return render_template('doctor_registration.html')


# Appointment Management
@app.route("/appointment_management_dashboard")
def appointment_management_dashboard():
    if 'jwt_token' not in session or session['user_role'] != 'admin':
        flash("Access denied. Admins only. Please Logging to the system.", "danger")
        return redirect(url_for('login'))
    return render_template('appointment_management_dashboard.html')

# Logs
@app.route("/logs")
def logs():
    if 'jwt_token' not in session or session['user_role'] != 'admin':
        flash("Access denied. Admins only. Please Logging to the system.", "danger")
        return redirect(url_for('login'))
    return render_template('logs.html')


# Route to display the doctors in table view
@app.route('/admin/doctors')
def doctor_management():
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    
    # Fetch encrypted data from the database
    cursor.execute("SELECT * FROM doctors")
    doctors = cursor.fetchall()
    
    # Decrypt sensitive fields
    for doctor in doctors:
        doctor['user_email'] = decrypt_data(doctor['user_email'])
        doctor['medical_no'] = decrypt_data(doctor['medical_no'])
        doctor['workplace'] = decrypt_data(doctor['workplace'])
        doctor['specialization'] = decrypt_data(doctor['specialization'])
    
    cursor.close()
    connection.close()
    
    # Render the template with decrypted data
    return render_template('doctor_management.html', doctors=doctors)


# Route to delete a doctor based on their email (primary key)
@app.route('/admin/doctors/delete/<user_email>', methods=['POST'])
def delete_doctors(user_email):
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("DELETE FROM doctors WHERE user_email = %s", (user_email,))
    connection.commit()
    cursor.close()
    connection.close()
    flash('Doctor deleted successfully!')
    return redirect(url_for('doctor_management'))


# Route to display the checkups in table view
@app.route('/admin/checkups')
def checkup_management():
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    
    # Fetch encrypted data from the database
    cursor.execute("SELECT * FROM regular_checkups")
    checkups = cursor.fetchall()
    
    # Decrypt sensitive fields
    for checkup in checkups:
        checkup['patient_nic'] = decrypt_data(checkup['patient_nic'])  # Corrected here
        checkup['email'] = decrypt_data(checkup['email'])
        checkup['appointment_date'] = decrypt_data(checkup['appointment_date'])
        checkup['appointment_time'] = decrypt_data(checkup['appointment_time'])
        checkup['test_type'] = decrypt_data(checkup['test_type'])
    
    cursor.close()
    connection.close()
    
    # Render the template with decrypted data
    return render_template('checkup_management.html', checkups=checkups)


# Route to delete a checkups based on their patient_nic (primary key)
@app.route('/admin/checkups/delete/<patient_nic>', methods=['POST'])
def delete_checkups(patient_nic):
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("DELETE FROM regular_checkups WHERE patient_nic = %s", (patient_nic,))
    connection.commit()
    cursor.close()
    connection.close()
    flash('checkups data deleted successfully!')
    return redirect(url_for('checkup_management'))



# Route to display the bookings in table view
@app.route('/book_doctor', methods=['GET', 'POST'])
def book_doctor():
    # Check if the user is logged in
    if 'jwt_token' not in session:
        flash("You need to log in to System.", "warning")
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Handle form submission
        user_email = session.get('user_email')
        patient_nic = request.form['patient_nic']
        preferred_date = request.form['preferred_date']
        preferred_time = request.form['preferred_time']
        doctor_email = request.form['doctor_email']
        specialization = request.form['specialization']
        
        # Encrypt sensitive data
        encrypted_user_email = encrypt_data(user_email)
        encrypted_patient_nic = encrypt_data(patient_nic)
        encrypted_preferred_date = encrypt_data(preferred_date)
        encrypted_preferred_time = encrypt_data(preferred_time)
        encrypted_doctor_email = encrypt_data(doctor_email)
        encrypted_specialization = encrypt_data(specialization)
        
        # Insert booking into the database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
        INSERT INTO appointment_bookings (user_email, patient_nic, preferred_date, preferred_time, doctor_email, specialization)
        VALUES (%s, %s, %s, %s, %s, %s)
        ''', (encrypted_user_email, encrypted_patient_nic, encrypted_preferred_date, encrypted_preferred_time, encrypted_doctor_email, encrypted_specialization))
        conn.commit()
        cursor.close()
        conn.close()
        
        flash("Booking successfully created!", "success")
        return redirect(url_for('index'))
    
    # Fetch and decrypt doctor data for the form
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute('SELECT * FROM doctors')
    doctors = cursor.fetchall()
    cursor.close()
    conn.close()
    
    # Decrypt doctor data
    for doctor in doctors:
        doctor['user_email'] = decrypt_data(doctor['user_email'])
        doctor['specialization'] = decrypt_data(doctor['specialization'])
    
    return render_template('book_doctor.html', doctors=doctors)



# # Handle doctor appoinment card view and select  doctor appoinment data with decryption.
@app.route('/appoinments')
def display_appoinments():
    # Check if user is logged in
    if 'jwt_token' not in session:
        flash("You need to log in to access this page.", "warning")
        return redirect(url_for('login'))
    # Get the logged-in user's email from the session
    user_email = session.get('user_email')
    #print("User email from session: ", user_email)

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)  # Fetch data as dictionaries
    cursor.execute("SELECT * FROM appointment_bookings")
    appoinments = cursor.fetchall()
    cursor.close()
    conn.close()

    # Decrypt data and filter based on user's email
    filtered_appoinments = []
    for appoinment in appoinments:
        # Decrypt data
        appoinment['patient_nic'] = decrypt_data(appoinment['patient_nic'])
        appoinment['user_email'] = decrypt_data(appoinment['user_email'])
        appoinment['preferred_date'] = decrypt_data(appoinment['preferred_date'])
        appoinment['preferred_time'] = decrypt_data(appoinment['preferred_time'])
        appoinment['specialization'] = decrypt_data(appoinment['specialization'])
        
        # Filter based on user's email
        if appoinment['user_email'] == user_email:
            filtered_appoinments.append(appoinment)

    return render_template('appoinment.html', appoinments=filtered_appoinments)



# Route to display the bookings in table view
def record_user_login(user_email):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
    INSERT INTO user_sessions (user_id, login_time)
    VALUES (%s, %s)
    ''', (user_email, datetime.utcnow()))
    conn.commit()
    cursor.close()
    conn.close()

# Route to display the bookings in table view
def record_user_logout(user_email):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
    UPDATE user_sessions
    SET logout_time = %s
    WHERE user_id = %s AND logout_time IS NULL
    ''', (datetime.utcnow(), user_email))
    conn.commit()
    cursor.close()
    conn.close()


# Route to display the appointments in table view
@app.route('/admin/appointments')
def appointment_management():
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    
    # Fetch encrypted data from the database
    cursor.execute("SELECT * FROM appointment_bookings")
    appointments = cursor.fetchall()
    
    # Decrypt sensitive fields
    for appointment in appointments:
        appointment['patient_nic'] = decrypt_data(appointment['patient_nic'])  # Corrected here
        appointment['user_email'] = decrypt_data(appointment['user_email'])
        appointment['preferred_date'] = decrypt_data(appointment['preferred_date'])
        appointment['preferred_time'] = decrypt_data(appointment['preferred_time'])
        appointment['doctor_email'] = decrypt_data(appointment['doctor_email'])
        appointment['specialization'] = decrypt_data(appointment['specialization'])
    
    cursor.close()
    connection.close()
    
    # Render the template with decrypted data
    return render_template('appointment_management.html', appointments=appointments)

# Route to delete an appointment based on its booking_id (primary key)
@app.route('/admin/appointments/delete/<int:booking_id>', methods=['POST'])
def delete_appointments(booking_id):
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("DELETE FROM appointment_bookings WHERE booking_id = %s", (booking_id,))
    connection.commit()
    cursor.close()
    connection.close()
    flash('Appointment booking deleted successfully!')
    return redirect(url_for('appointment_management'))


# Route to display the user sessions in table view
def track_user_session(user_id, login_time, logout_time=None):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        INSERT INTO user_sessions (user_id, login_time, logout_time)
        VALUES (%s, %s, %s)
    ''', (user_id, login_time, logout_time))

    conn.commit()
    cursor.close()
    conn.close()

# Route to display the user actions in table view
def track_user_action(user_id, action_type, action_time, details=None):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        INSERT INTO user_actions (user_id, action_type, action_time, details)
        VALUES (%s, %s, %s, %s)
    ''', (user_id, action_type, action_time, details))

    conn.commit()
    cursor.close()
    conn.close()

# Route to display the user actions in table view
def audit_database_change(table_name, record_id, change_type, change_time, changed_by, old_values=None, new_values=None):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        INSERT INTO database_audit (table_name, record_id, change_type, change_time, changed_by, old_values, new_values)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    ''', (table_name, record_id, change_type, change_time, changed_by, old_values, new_values))

    conn.commit()
    cursor.close()
    conn.close()
