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
app.secret_key = secrets.token_urlsafe(32)  # Ensure this is in the correct file

# Initialize the database
jwt_secret = secrets.token_urlsafe(32)  # Secret key for JWT
RECAPTCHA_SECRET_KEY = '6LdyBisqAAAAAFMn8RKKJU3yxIxggaX6kVk1fi5G'  

# Routes
@app.route("/")
def index():
    """Render the homepage. Check if user is logged in."""
    if 'jwt_token' in session:
        user = decode_jwt_token(session['jwt_token'], jwt_secret)
        if user:
            return render_template('index.html', logged_in=True, user=user)
    return render_template('index.html', logged_in=False)

@app.route("/home")
def home():
    """Render the home page. Check if user is logged in."""
    if 'jwt_token' in session:
        user = decode_jwt_token(session['jwt_token'], jwt_secret)
        if user:
            return render_template('index.html', logged_in=True, user=user)
    return render_template('Login.html', logged_in=False)

@app.route("/services")
def services():
    """Render the services page. Check if user is logged in."""
    if 'jwt_token' in session:
        user = decode_jwt_token(session['jwt_token'], jwt_secret)
        if user:
            return render_template('Services.html', logged_in=True, user=user)
    return render_template('Login.html', logged_in=False)

@app.route("/regular_checkup", methods=['GET', 'POST'])
def regular_checkup():
    """Handle regular checkup form submissions and render the form."""
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
    """Retrieve and return checkup details by ID."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT * FROM regular_checkups WHERE id = %s
    ''', (checkup_id,))

    result = cursor.fetchone()
    if result:
        decrypted_data = {
            'patient_nic': decrypt_data(result[1]),
            'email': decrypt_data(result[2]),
            'appointment_date': decrypt_data(result[3]),
            'appointment_time': decrypt_data(result[4]),
            'test_type': decrypt_data(result[5]),
            'submitted_at': result[6]
        }
    else:
        decrypted_data = {}

    cursor.close()
    conn.close()
    
    return jsonify(decrypted_data)

if __name__ == "__main__":
    init_db()  # Initialize the database on startup
    app.run(debug=True)
