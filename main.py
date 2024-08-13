# from flask import Flask, flash, render_template, url_for, request, session
# import secrets 

# # @author Yasiru
# # contact me: https://linktr.ee/yasiruchamuditha for more information.

# #create secreat key
# secret = secrets.token_urlsafe(32)

# app = Flask(__name__)
# app.secret_key = secret

# #route for load index page
# @app.route("/")
# def index():
#     return render_template('index.html')

# #route for load home page
# @app.route("/home")
# def home():
#     return render_template('index.html')

# #route for load register page
# @app.route("/register")
# def register():
#     return render_template('Register.html')

# #route for load login page
# @app.route("/login")
# def login():
#     return render_template('Login.html')

# @app.route('/logout')
# # @login_required
# def logout():
#     # logout_user()
#     return render_template('Login.html')



      

# if __name__=="__main__":
#     app.run(debug=True)