# #save the data in database using encryption method,not working and need to modified
# from flask import Flask, request, redirect, url_for, flash, render_template
# import mysql.connector
# from cryptography.fernet import Fernet
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
# import secrets

# # Author: Yasiru
# # Contact: https://linktr.ee/yasiruchamuditha for more information.

# # Generate a key for encryption and decryption
# # You must store this key securely. In production, you may use a secure key management service.
# key = Fernet.generate_key()
# cipher_suite = Fernet(key)

# # Create a secret key for session management
# secret = secrets.token_urlsafe(32)

# # Initialize the Flask app
# app = Flask(__name__)
# app.secret_key = secret

# # Database connection function
# def get_db_connection():
#     return mysql.connector.connect(
#         host='localhost',
#         user='root',
#         password='root',
#         database='secure_db'
#     )

# # Initialize the database (create table if not exists)
# def init_db():
#     conn = get_db_connection()
#     cursor = conn.cursor()
#     cursor.execute('''
#     CREATE TABLE IF NOT EXISTS users (
#         id INT AUTO_INCREMENT PRIMARY KEY,
#         username VARCHAR(255) UNIQUE NOT NULL,
#         password BLOB NOT NULL,
#         encrypted_data BLOB NOT NULL,
#         created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
#     )
#     ''')
#     conn.commit()
#     cursor.close()
#     conn.close()

# # Function to save a new user with encrypted data
# def save_user(username, password, sensitive_data):
#     conn = get_db_connection()
#     cursor = conn.cursor()
    
#     # Hash the password
#     hashed_password = generate_password_hash(password)
    
#     # Encrypt the sensitive data
#     encrypted_data = cipher_suite.encrypt(sensitive_data.encode('utf-8'))
    
#     cursor.execute("INSERT INTO users (username, password, encrypted_data) VALUES (%s, %s, %s)", 
#                    (username, hashed_password, encrypted_data))
#     conn.commit()
#     cursor.close()
#     conn.close()

# # Function to retrieve and decrypt sensitive data
# def get_user_sensitive_data(username):
#     conn = get_db_connection()
#     cursor = conn.cursor()
#     cursor.execute("SELECT encrypted_data FROM users WHERE username = %s", (username,))
#     encrypted_data = cursor.fetchone()[0]
#     cursor.close()
#     conn.close()
    
#     # Decrypt the data
#     decrypted_data = cipher_suite.decrypt(encrypted_data).decode('utf-8')
#     return decrypted_data

# # Route to load the register page and handle registration
# @app.route("/register", methods=['GET', 'POST'])
# def register():
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']
#         sensitive_data = request.form['sensitive_data']

#         # Check if username already exists
#         conn = get_db_connection()
#         cursor = conn.cursor()
#         cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
#         user = cursor.fetchone()
#         if user:
#             flash("Username already taken!", "danger")
#             return redirect(url_for('register'))
        
#         # Save the user with encrypted data
#         save_user(username, password, sensitive_data)

#         flash("Registration successful!", "success")
#         return redirect(url_for('login'))
#     return render_template('register.html')

# # Route to load the login page and handle login
# @app.route("/login", methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']

#         # Retrieve the user from the database
#         conn = get_db_connection()
#         cursor = conn.cursor()
#         cursor.execute("SELECT password FROM users WHERE username = %s", (username,))
#         user = cursor.fetchone()
#         cursor.close()
#         conn.close()

#         if user is None or not check_password_hash(user[0], password):
#             flash("Invalid username or password!", "danger")
#             return redirect(url_for('login'))

#         # On successful login, retrieve and decrypt sensitive data
#         sensitive_data = get_user_sensitive_data(username)
#         flash(f"Login successful! Your sensitive data: {sensitive_data}", "success")
#         return redirect(url_for('index'))
#     return render_template('login.html')

# # Route to load the index page (which serves as the home page after login)
# @app.route("/")
# def index():
#     return render_template('index.html')

# if __name__ == "__main__":
#     init_db()  # Initialize the database and create tables
#     app.run(debug=True)
