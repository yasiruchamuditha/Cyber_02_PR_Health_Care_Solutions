from flask import Flask, request, jsonify
import smtplib
import re
import random
import string
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

app = Flask(__name__)

def generate_random_code(length=8):
    # Generate a random code of specified length
    letters_and_digits = string.ascii_letters + string.digits
    return ''.join(random.choice(letters_and_digits) for i in range(length))

def extract_email_from_html(html_content):
    # Extract the sender's email address from the HTML content
    match = re.search(r'[\w\.-]+@[\w\.-]+', html_content)
    return match.group(0) if match else None

def send_email(subject, recipient_email, html_template):
    # Define the sender's email credentials
    sender_email = "your_email@example.com"
    sender_password = "your_password"

    # Extract the sender email from the HTML template
    extracted_email = extract_email_from_html(html_template)

    if extracted_email:
        print(f"Extracted Sender Email: {extracted_email}")
    else:
        print("No email address found in the HTML template.")

    # Generate a random code
    random_code = generate_random_code()

    # Create the email
    message = MIMEMultipart("alternative")
    message["Subject"] = subject
    message["From"] = sender_email
    message["To"] = recipient_email

    # Insert the random code into the HTML template
    html_content = html_template.replace("{code}", random_code)

    # Attach the HTML content to the email
    part = MIMEText(html_content, "html")
    message.attach(part)

    # Send the email
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, recipient_email, message.as_string())

    print(f"Email sent to {recipient_email} with the random code: {random_code}")
    return random_code

@app.route('/send_code', methods=['POST'])
def send_code():
    data = request.json
    subject = data.get('subject')
    recipient_email = data.get('recipient_email')
    html_template = data.get('html_template')

    if not subject or not recipient_email or not html_template:
        return jsonify({"error": "Missing required fields"}), 400

    random_code = send_email(subject, recipient_email, html_template)
    
    return jsonify({"message": f"Email sent to {recipient_email} with the random code", "code": random_code})

if __name__ == '__main__':
    app.run(debug=True)
