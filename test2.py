import os
from datetime import datetime
from werkzeug.utils import secure_filename
from flask import flash, redirect, render_template, request, session, url_for

# Set up the upload folder and allowed extensions
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = load_secret_key()  # Load secret key from file

# Function to check if the uploaded file is allowed
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Route to upload prescription
@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    # Check if the user is logged in
    if 'jwt_token' not in session:
        flash("You need to log in to upload a prescription.", "warning")
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        
        file = request.files['file']
        
        # If the user does not select a file, the browser submits an empty file
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
        
        # Check if the file is allowed (correct extension)
        if file and allowed_file(file.filename):
            # Secure the filename and append the current date and time
            filename = secure_filename(file.filename)
            current_time = datetime.now().strftime("%Y%m%d%H%M%S")
            filename = f"{filename.rsplit('.', 1)[0]}_{current_time}.{filename.rsplit('.', 1)[1]}"
            
            # Save the file to the specified upload folder
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            flash('File successfully uploaded', 'success')
            return redirect(url_for('services'))
        else:
            flash('Invalid file format. Please upload a valid image file.', 'danger')
            return redirect(request.url)
    
    return render_template('upload.html')
