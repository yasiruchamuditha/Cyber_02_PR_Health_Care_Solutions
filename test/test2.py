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

        username = request.form['txtUSerEmail']
        password = request.form['txtPassword']

        # Retrieve the user from the database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user is None:
            flash("Username not found!", "danger")
            return redirect(url_for('login'))

        # Check if user is verified
        is_verified = user[4]  # Assuming 'is_verified' is in the fifth column
        if not is_verified:
            flash("Account not verified! Please check your email.", "danger")
            return redirect(url_for('verify'))

        # Verify the password
        hashed_password = user[2]  # Assuming hashed password is in the third column
        if not check_password_hash(hashed_password, password):
            flash("Incorrect password!", "danger")
            return redirect(url_for('login'))

        # If login is successful, generate a JWT token
        token = generate_jwt_token(username)
        session['jwt_token'] = token
        flash("Login successful!", "success")
        return redirect(url_for('index'))

    return render_template('login.html')