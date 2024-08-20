# Route to handle user forgot_password
@app.route("/forgot_password", methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['txtUSerEmail']

        # Check if the user exists
        user = get_user_by_username(username)
        if user is None:
            flash("Email not found!", "danger")
            return redirect(url_for('forgot_password'))

        # Generate a new verification code
        verification_code = generate_verification_code()
        code_expires_at = datetime.utcnow() + timedelta(minutes=10)  # Code expires in 10 minutes

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET verification_code = %s, code_expires_at = %s WHERE username = %s",
                       (verification_code, code_expires_at, username))
        conn.commit()
        cursor.close()
        conn.close()

        # Send the verification code via email
        send_verification_email(username, verification_code)

        flash("A verification code has been sent to your email.", "success")
        return redirect(url_for('verify_code', email=username))

    return render_template('forgot_password.html')