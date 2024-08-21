import mysql.connector
from datetime import datetime, timedelta
import secrets

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
        verification_code VARCHAR(6),
        is_verified BOOLEAN DEFAULT FALSE,
        code_expires_at DATETIME,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
def save_user(username, user_role, hashed_password):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (username, user_role, password) VALUES (%s, %s, %s)", (username, user_role, hashed_password))
    conn.commit()
    cursor.close()
    conn.close()

# Function to update a user
def update_user_verification_code(username, verification_code, code_expires_at):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET verification_code = %s, code_expires_at = %s WHERE username = %s",
                   (verification_code, code_expires_at, username))
    conn.commit()
    cursor.close()
    conn.close()

def update_user_password(username, hashed_password):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET password = %s WHERE username = %s", (hashed_password, username))
    conn.commit()
    cursor.close()
    conn.close()
