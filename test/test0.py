## working fine.Register,login funtion working fine.Simple structure
# from flask import Flask, jsonify, request, session, redirect, url_for, flash, render_template
# import mysql.connector
# import secrets
# import jwt
# from werkzeug.security import generate_password_hash, check_password_hash
# from datetime import datetime, timedelta

# # Author: Yasiru
# # Contact: https://linktr.ee/yasiruchamuditha for more information.

# # Create a secret key for session management
# secret = secrets.token_urlsafe(32)

# # Initialize the Flask app
# app = Flask(__name__)
# app.secret_key = secret
# jwt_secret = secrets.token_urlsafe(32)  # Secret key for JWT

# # Database connection function
# def get_db_connection():
#     return mysql.connector.connect(
#         host='localhost',  # Change this to your database host
#         user='root',  # Change this to your database user
#         password='root',  # Change this to your database password
#         database='flask_auth_db'  # Change this to your database name
#     )

# # Initialize the database (create table if not exists)
# def init_db():
#     conn = get_db_connection()
#     cursor = conn.cursor()
#     cursor.execute('''
#     CREATE TABLE IF NOT EXISTS users (
#         id INT AUTO_INCREMENT PRIMARY KEY,
#         username VARCHAR(255) UNIQUE NOT NULL,
#         password VARCHAR(255) NOT NULL,
#         user_role VARCHAR(50) NOT NULL DEFAULT 'user',
#         created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
#     )
#     ''')
#     conn.commit()
#     cursor.close()
#     conn.close()

# # Function to fetch a user by username
# def get_user_by_username(username):
#     conn = get_db_connection()
#     cursor = conn.cursor()
#     cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
#     user = cursor.fetchone()
#     cursor.close()
#     conn.close()
#     return user

# # Function to save a new user
# def save_user(username, User_Role, hashed_password):
#     conn = get_db_connection()
#     cursor = conn.cursor()
#     cursor.execute("INSERT INTO users (username,User_Role, password) VALUES (%s,%s,%s)", (username, User_Role, hashed_password))
#     conn.commit()
#     cursor.close()
#     conn.close()

# # Function to generate a JWT token
# def generate_jwt_token(username):
#     payload = {
#         'user': username,
#         'exp': datetime.utcnow() + timedelta(hours=1)  # Token expires in 1 hour
#     }
#     token = jwt.encode(payload, jwt_secret, algorithm='HS256')
#     return token

# # Function to decode a JWT token
# def decode_jwt_token(token):
#     try:
#         decoded = jwt.decode(token, jwt_secret, algorithms=['HS256'])
#         return decoded['user']
#     except jwt.ExpiredSignatureError:
#         return None  # Token has expired
#     except jwt.InvalidTokenError:
#         return None  # Invalid token

# # Route to load the index page (which also serves as the home page after login)
# @app.route("/")
# def index():
#     if 'jwt_token' in session:
#         user = decode_jwt_token(session['jwt_token'])
#         if user:
#             return render_template('index.html', logged_in=True, user=user)
#     return render_template('index.html', logged_in=False)

# # Route to load the register page
# @app.route("/register", methods=['GET', 'POST'])
# def register():
#     if request.method == 'POST':
#         username = request.form['txtUSerEmail']
#         User_Role = request.form['User_Role']
#         password = request.form['txtPassword']
#         confirm_password = request.form['txtConfirm_Password']

#         # Check if passwords match
#         if password != confirm_password:
#             flash("Passwords do not match!", "danger")
#             return redirect(url_for('register'))

#         # Check if username already exists
#         if get_user_by_username(username):
#             flash("Username already taken!", "danger")
#             return redirect(url_for('register'))

#         # Hash the password and store the user in the database
#         hashed_password = generate_password_hash(password)
#         save_user(username, User_Role, hashed_password)

#         flash("Registration successful! Please log in.", "success")
#         return redirect(url_for('login'))
#     return render_template('register.html')

# # Route to load the login page
# @app.route("/login", methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         username = request.form['txtUSerEmail']
#         password = request.form['txtPassword']

#         # Retrieve the user from the database
#         user = get_user_by_username(username)
#         if user is None:
#             flash("Username not found!", "danger")
#             return redirect(url_for('login'))

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

# # Route to log out and end the session
# @app.route('/logout')
# def logout():
#     session.pop('jwt_token', None)  # Remove JWT token from session
#     flash("Logged out successfully.", "info")
#     return redirect(url_for('index'))

# if __name__ == "__main__":
#     init_db()  # Initialize the database and create tables
#     app.run(debug=True)


# # CREATE DATABASE IF NOT EXISTS flask_auth_db;

# # USE flask_auth_db;

# # CREATE TABLE IF NOT EXISTS users (
# #     id INT AUTO_INCREMENT PRIMARY KEY,
# #     username VARCHAR(255) UNIQUE NOT NULL,
# #     password VARCHAR(255) NOT NULL,
# #     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
# # );
