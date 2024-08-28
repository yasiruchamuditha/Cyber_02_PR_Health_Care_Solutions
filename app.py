# app.py

from routes import app  # Import the app instance from routes.py
from model import init_db  # Import the init_db function from model.py

# Initialize the database
init_db()

if __name__ == "__main__":
    app.run(debug=True)
