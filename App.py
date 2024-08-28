import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///updates.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['APK_UPLOAD_FOLDER'] = 'static/apk_files'
app.config['DIRECTORY_FOLDER'] = 'static/directories'
db = SQLAlchemy(app)

# Ensure the upload folders exist
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])
if not os.path.exists(app.config['APK_UPLOAD_FOLDER']):
    os.makedirs(app.config['APK_UPLOAD_FOLDER'])
if not os.path.exists(app.config['DIRECTORY_FOLDER']):
    os.makedirs(app.config['DIRECTORY_FOLDER'])

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)

class Update(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    filename = db.Column(db.String(100), nullable=True)

with app.app_context():
    db.create_all()

@app.route('/')
def index():
    updates = Update.query.all()
    return render_template('Index.html', updates=updates)

@app.route('/submit', methods=['POST'])
def submit():
    content = request.form['update']
    file = request.files['file']

    filename = None
    if file:
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

    new_update = Update(content=content, filename=filename)
    db.session.add(new_update)
    db.session.commit()

    flash('Update added successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/delete_update/<int:update_id>')
def delete_update(update_id):
    update_to_delete = Update.query.get_or_404(update_id)
    db.session.delete(update_to_delete)
    db.session.commit()
    flash('Update deleted successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/manage_directories', methods=['GET', 'POST'])
def manage_directories():
    if request.method == 'POST':
        directory_name = request.form['directory_name']
        directory_path = os.path.join(app.config['DIRECTORY_FOLDER'], directory_name)

        if not os.path.exists(directory_path):
            os.makedirs(directory_path)
            flash(f'Directory "{directory_name}" created successfully!', 'success')
        else:
            flash(f'Directory "{directory_name}" already exists!', 'danger')

    directories = os.listdir(app.config['DIRECTORY_FOLDER'])
    return render_template('manage_directories.html', directories=directories)

@app.route('/delete_directory/<directory_name>')
def delete_directory(directory_name):
    directory_path = os.path.join(app.config['DIRECTORY_FOLDER'], directory_name)

    if os.path.exists(directory_path):
        os.rmdir(directory_path)
        flash(f'Directory "{directory_name}" deleted successfully!', 'success')
    else:
        flash(f'Directory "{directory_name}" does not exist!', 'danger')

    return redirect(url_for('manage_directories'))

@app.route('/manage_apk_files')
def manage_apk_files():
    apk_files = os.listdir(app.config['APK_UPLOAD_FOLDER'])
    return render_template('manage_apk_files.html', apk_files=apk_files)

@app.route('/upload_apk', methods=['POST'])
def upload_apk():
    file = request.files['file']

    if file and file.filename.endswith('.apk'):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['APK_UPLOAD_FOLDER'], filename)
        file.save(file_path)
        flash(f'APK file "{filename}" uploaded successfully!', 'success')
    else:
        flash('Invalid file type. Please upload a .apk file.', 'danger')

    return redirect(url_for('manage_apk_files'))

@app.route('/delete_apk/<filename>')
def delete_apk(filename):
    file_path = os.path.join(app.config['APK_UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        flash(f'APK file "{filename}" deleted successfully!', 'success')
    else:
        flash(f'APK file "{filename}" does not exist!', 'danger')
    return redirect(url_for('manage_apk_files'))

@app.route('/update_apk/<filename>', methods=['POST'])
def update_apk(filename):
    file_path = os.path.join(app.config['APK_UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        os.remove(file_path)  # Remove the old file
        file = request.files['file']
        if file and file.filename.endswith('.apk'):
            new_filename = secure_filename(file.filename)
            new_file_path = os.path.join(app.config['APK_UPLOAD_FOLDER'], new_filename)
            file.save(new_file_path)
            flash(f'APK file "{filename}" updated successfully!', 'success')
        else:
            flash('Invalid file type. Please upload a .apk file.', 'danger')
    else:
        flash(f'APK file "{filename}" does not exist!', 'danger')

    return redirect(url_for('manage_apk_files'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['logged_in'] = True
            session['user_id'] = user.id
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Signup successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
