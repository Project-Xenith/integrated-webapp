from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
import os
import secrets
from PIL import Image

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.example.com'  # Configure your email server
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'your_email@example.com'
app.config['MAIL_PASSWORD'] = 'your_email_password'

db = SQLAlchemy(app)
mail = Mail(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_reset_token(self, expires_sec=1800):
        return secrets.token_hex(16)

    @staticmethod
    def verify_reset_token(token):
        user = User.query.filter_by(email=email).first()
        if user:
            return user
        return None

# Initialize the database and create tables
with app.app_context():
    db.create_all()

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Code for implementing image steganography
UPLOAD_FOLDER = 'uploads'
OUTPUT_FOLDER = 'output'

# Set upload folder for Flask app
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure the upload and output directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

def hide_image(secret_image_path, cover_image_path, output_image_path):
    # Open the secret image
    secret_image = Image.open(secret_image_path)
    secret_pixels = secret_image.load()
    secret_width, secret_height = secret_image.size

    # Open the cover image
    cover_image = Image.open(cover_image_path)
    cover_pixels = cover_image.load()
    cover_width, cover_height = cover_image.size

    # Make sure the cover image is large enough to hide the secret image
    if secret_width > cover_width or secret_height > cover_height:
        print("Error: Secret image dimensions exceed cover image dimensions")
        return

    # Embed the secret image into the cover image
    for x in range(secret_width):
        for y in range(secret_height):
            cover_pixel = cover_pixels[x, y]
            secret_pixel = secret_pixels[x, y]

            # Modify the LSBs of the cover pixel to contain the secret image
            new_red = cover_pixel[0] & 0b11111110 | (secret_pixel[0] >> 7)
            new_green = cover_pixel[1] & 0b11111110 | (secret_pixel[1] >> 7)
            new_blue = cover_pixel[2] & 0b11111110 | (secret_pixel[2] >> 7)

            cover_pixels[x, y] = (new_red, new_green, new_blue)

    # Save the resulting image
    cover_image.save(output_image_path)
    print("Image hidden successfully at:", output_image_path)

def reveal_image(image_path):
    # Open the stego-image
    stego_image = Image.open(image_path)
    stego_pixels = stego_image.load()
    width, height = stego_image.size

    # Create a new image to reveal the hidden image
    revealed_image = Image.new("RGB", (width, height))
    revealed_pixels = revealed_image.load()

    # Extract the hidden image
    for x in range(width):
        for y in range(height):
            stego_pixel = stego_pixels[x, y]
            red = (stego_pixel[0] & 1) << 7
            green = (stego_pixel[1] & 1) << 7
            blue = (stego_pixel[2] & 1) << 7
            revealed_pixels[x, y] = (red, green, blue)

    # Save the revealed image
    revealed_image_path = os.path.join(OUTPUT_FOLDER, "revealed_image.png")
    revealed_image.save(revealed_image_path)
    print("Revealed image saved at:", revealed_image_path)


@app.route('/')
@login_required
def index():
    return render_template('new_index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    # url_for('login') = the html file which the login function return i.e., login_signup.html
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists.')
            return redirect(url_for('signup'))
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template(url_for('login'))
    # return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid username or password.')
    return render_template('login_signup.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            token = user.get_reset_token()
            msg = Message('Password Reset Request', sender='noreply@example.com', recipients=[user.email])
            msg.body = f'''To reset your password, visit the following link:
{url_for('reset_password', token=token, _external=True)}

If you did not make this request, simply ignore this email and no changes will be made.
'''
            mail.send(msg)
            flash('An email has been sent with instructions to reset your password.')
            return redirect(url_for('login'))
        else:
            flash('No account found with that email.')
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.verify_reset_token(token)
    if user is None:
        flash('Invalid or expired token.')
        return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        password = request.form.get('password')
        user.set_password(password)
        db.session.commit()
        flash('Your password has been reset.')
        return redirect(url_for('login'))
    return render_template('reset_password.html')

# Add image hiding functionality here

@app.route('/hide', methods=['GET', 'POST'])
def hide():
    if 'secret_image' not in request.files or 'cover_image' not in request.files:
        return redirect(request.url)
    secret_image = request.files['secret_image']
    cover_image = request.files['cover_image']
    secret_image_path = os.path.join(app.config['UPLOAD_FOLDER'], secret_image.filename)
    cover_image_path = os.path.join(app.config['UPLOAD_FOLDER'], cover_image.filename)
    secret_image.save(secret_image_path)
    cover_image.save(cover_image_path)

    hide_image(secret_image_path, cover_image_path, os.path.join(OUTPUT_FOLDER, "output.png"))

    return redirect('/')

@app.route('/reveal', methods=['POST'])
def reveal():
    print('reveal is working')
    if 'output_image' not in request.files:
        return redirect(request.url)
    output_image = request.files['output_image']
    output_image_path = os.path.join(app.config['UPLOAD_FOLDER'], output_image.filename)
    output_image.save(output_image_path)

    reveal_image(output_image_path)

    return redirect('/')

@app.route('/download_output')
def download_output():
    output_image_path = os.path.join(OUTPUT_FOLDER, "output.png")
    return send_file(output_image_path, as_attachment=True)

@app.route('/download_revealed')
def download_revealed():
    revealed_image_path = os.path.join(OUTPUT_FOLDER, "revealed_image.png")
    return send_file(revealed_image_path, as_attachment=True)


if __name__ == '__main__':
    app.run(debug=True)
