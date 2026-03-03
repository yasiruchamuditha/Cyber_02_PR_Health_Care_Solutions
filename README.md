# PR Healthcare Solutions

Today the world is moving fast towards the digital age and the security of the system is considered an essential factor in digital systems. This report mainly focuses on the design and implementation of PR Healthcare Solutions, which is the leading healthcare company in the industry. This system is concerned with patient information and data related to health with proper data regulations.

## Overview

PR Healthcare Solutions is a medium-sized health management system that provides services to patients and healthcare workers by managing patients' health records, appointments, prescriptions, and checkups. On the administration side, this system mainly focuses on patients, doctor appointments, and checkup management through a proper admin panel.

## Cyber Security Measures

This report details how the system design and implementation overcome cybersecurity issues and the main cybersecurity mechanisms used in this system. The following cybersecurity measures are mainly focused on in this project:

- **Authentications**: Ensuring that only authorized users can access the system.
- **Authorizations**: Granting permissions to users based on their roles.
- **Secure Data Storage**: Storing data securely to prevent unauthorized access.
- **Secure Data Retrieval**: Ensuring data retrieval processes are secure and protected from breaches.

## Key Features

### Patient Health Record Management
- Efficiently stores and retrieves patient health data.
- Ensures secure data storage with encryption mechanisms.

### Appointment Management
- Schedules and manages patient appointments with healthcare professionals.
- Provides real-time updates and notifications for patients and doctors.

### Prescription and Checkup Management
- Tracks and updates patient prescriptions and checkup details.
- Offers easy access to records for continuity of care.

### Admin Panel
- Allows administrators to manage user roles and permissions.
- Provides control over doctor appointments, patient data, and system configurations.

## Technologies Used
- **Frontend**: HTML, CSS, JavaScript
- **Template Engine**: Jinja2 (Flask)
- **Backend**: Python, Flask
- **Database**: MySQL
- **Encryption**: Fernet symmetric encryption (via the `cryptography` library) for securing sensitive patient data such as NIC numbers, emails, and appointment details.
- **Authentication**: JWT (JSON Web Tokens via PyJWT) for session management.
- **Communication Protocols**: HTTPS for secure data transfer.

## System Requirements
- **Server**: Linux/Windows server
- **Frontend**: Any modern web browser (Google Chrome, Mozilla Firefox, Microsoft Edge).
- **Backend**: Python 3.x
- **Database**: MySQL

## Installation

### Clone the Repository
```bash
git clone https://github.com/yasiruchamuditha/Cyber_02_PR_Health_Care_Solutions.git
cd Cyber_02_PR_Health_Care_Solutions
```

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Setup the Database
Create a MySQL database named `flask_auth_db` and update the connection details in `model.py` if needed:
```python
host='localhost'
user='root'
password='your-db-password'
database='flask_auth_db'
```
The application will automatically create the required tables on first run.

### Run the Application
```bash
python flask_app.py
```

## Usage
- **Login/Register**: Access the system through a secure login page.
- **Dashboard**: Navigate through patient data, appointments, and checkups.
- **Admin Panel**: Manage user roles, permissions, and system settings.

## Author
- **Yasiru Chamuditha** - [GitHub Profile](https://github.com/yasiruchamuditha)

## Contribution
Contributions are welcome! To contribute:
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/your-feature`).
3. Commit your changes (`git commit -m 'Add your feature'`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a pull request.

## License
This project is licensed under the MIT License.

## Conclusion

PR Healthcare Solutions ensures secure data management with secure data storage and provides access to authorized personnel, making it a reliable and secure health management system in the digital age.
