from flask import Flask
import secrets
from routes.routes import register_routes

# Initialize the Flask app
app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(32)

# Initialize the database when the app starts
with app.app_context():
    from models.model import init_db
    init_db()

# Register the routes
register_routes(app)

if __name__ == "__main__":
    app.run(debug=True)
