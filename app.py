# Import necessary libraries
from flask import Flask, request, jsonify, render_template, g, send_file
import bcrypt
import jwt
from datetime import datetime, timedelta, timezone
from pymongo import MongoClient
import os
from functools import wraps
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
import pyotp
import qrcode
import io
import re

# Load environment variables from .env file
load_dotenv()

# --- Initial Configuration ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-super-secret-key-for-auth-tokens'
app.config['ACTION_TOKEN_SECRET_KEY'] = 'a-separate-secret-key-for-action-tokens'

# --- Email Configuration ---
EMAIL_SENDER = os.environ.get('EMAIL_USER')
EMAIL_PASSWORD = os.environ.get('EMAIL_PASS')

# --- MongoDB Configuration (Robust Method) ---
MONGO_URI = os.environ.get('MONGO_URI', "mongodb://localhost:27017/")

def get_db():
    if 'db' not in g:
        try:
            g.client = MongoClient(MONGO_URI)
            g.db = g.client['auth_system_db']
        except Exception as e:
            print(f"CRITICAL: Could not connect to MongoDB: {e}")
            raise e
    return g.db

@app.teardown_appcontext
def close_db(error):
    client = g.pop('client', None)
    if client is not None:
        client.close()

with app.app_context():
    try:
        db = get_db()
        db.users.create_index("username", unique=True)
        db.users.create_index("email", unique=True)
    except Exception:
        pass

# --- Helper Functions ---
def send_email(recipient_email, subject, body):
    if not EMAIL_SENDER or not EMAIL_PASSWORD: return False
    msg = MIMEMultipart()
    msg['From'], msg['To'], msg['Subject'] = f"System Security <{EMAIL_SENDER}>", recipient_email, subject
    msg.attach(MIMEText(body, 'plain'))
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(EMAIL_SENDER, EMAIL_PASSWORD)
        server.sendmail(EMAIL_SENDER, recipient_email, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False

def generate_action_token(email, action, expires_in_minutes=60):
    payload = {'email': email, 'action': action, 'exp': datetime.now(timezone.utc) + timedelta(minutes=expires_in_minutes)}
    return jwt.encode(payload, app.config['ACTION_TOKEN_SECRET_KEY'], algorithm='HS256')

# --- Decorator for Protected Routes ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers and request.headers['Authorization'].startswith('Bearer '):
            token = request.headers['Authorization'].split(' ')[1]
        if not token: return jsonify({'message': 'Authentication token is missing'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            db = get_db()
            g.current_user = db.users.find_one({'username': data['sub']})
            if not g.current_user: raise Exception()
        except Exception:
            return jsonify({'message': 'Authentication token is invalid or expired'}), 401
        return f(*args, **kwargs)
    return decorated

# --- HTML Page Routes ---
@app.route('/')
def home(): return render_template('home.html')
@app.route('/login')
def login_page(): return render_template('login.html')
@app.route('/register')
def register_page(): return render_template('register.html')
@app.route('/dashboard')
def dashboard_page(): return render_template('dashboard.html')
@app.route('/token-login')
def token_login_page(): return render_template('token_login.html')

# --- API Endpoints ---
@app.route('/api/register', methods=['POST'])
def register():
    db = get_db()
    data = request.get_json()
    username, email, password = data.get('username'), data.get('email'), data.get('password')
    if not all([username, email, password]): return jsonify({'message': 'All fields are required'}), 400
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email): return jsonify({'message': 'Invalid email format'}), 400
    if db.users.find_one({'$or': [{'username': username}, {'email': email}]}):
        return jsonify({'message': 'Username or email already exists'}), 409

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    db.users.insert_one({"username": username, "email": email, "password_hash": hashed_password, "is_verified": False, "mfa_enabled": False, "mfa_secret": None})
    
    verification_token = generate_action_token(email, 'verify_email')
    verification_link = f"http://127.0.0.1:5000/api/verify-email?token={verification_token}"
    send_email(email, "Verify Your Account", f"Please click the link to verify your account: {verification_link}")
    return jsonify({'message': 'Registration successful! Please check your email to verify your account.'}), 201

@app.route('/api/verify-email', methods=['GET'])
def verify_email():
    db = get_db()
    token = request.args.get('token')
    
    title = "Verification Failed"
    message = "The verification link is invalid or has expired. Please try registering again."

    if token:
        try:
            payload = jwt.decode(token, app.config['ACTION_TOKEN_SECRET_KEY'], algorithms=['HS256'])
            if payload.get('action') == 'verify_email':
                result = db.users.update_one({'email': payload['email']}, {'$set': {'is_verified': True}})
                if result.matched_count > 0:
                    title = "Email Verified!"
                    message = "Your account has been successfully verified. You can now log in."
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            pass
            
    return render_template('status.html', title=title, message=message)

def issue_auth_token(username):
    payload = {'sub': username, 'exp': datetime.now(timezone.utc) + timedelta(hours=1)}
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

@app.route('/api/login/step1', methods=['POST'])
def login_step1():
    db = get_db()
    data = request.get_json()
    user = db.users.find_one({'username': data.get('username')})
    if not user or not bcrypt.checkpw(data.get('password').encode('utf-8'), user['password_hash']):
        return jsonify({'message': 'Invalid username or password'}), 401
    if not user.get('is_verified'): return jsonify({'message': 'Account not verified. Please check your email.'}), 403

    if user.get('mfa_enabled'):
        return jsonify({'mfa_required': True, 'username': user['username']})
    else:
        token = issue_auth_token(user['username'])
        return jsonify({'mfa_required': False, 'token': token})

@app.route('/api/login/step2', methods=['POST'])
def login_step2():
    db = get_db()
    data = request.get_json()
    username, mfa_code = data.get('username'), data.get('mfa_code')
    user = db.users.find_one({'username': username})
    if not user: return jsonify({'message': 'User not found'}), 404
    
    totp = pyotp.TOTP(user['mfa_secret'])
    if totp.verify(mfa_code):
        token = issue_auth_token(user['username'])
        return jsonify({'token': token})
    else:
        return jsonify({'message': 'Invalid authenticator code'}), 401

@app.route('/api/mfa/setup', methods=['POST'])
@token_required
def mfa_setup():
    db = get_db()
    user = g.current_user
    if user.get('mfa_enabled'): return jsonify({'message': 'MFA is already enabled'}), 400
    mfa_secret = pyotp.random_base32()
    db.users.update_one({'username': user['username']}, {'$set': {'mfa_secret': mfa_secret}})
    totp_uri = pyotp.totp.TOTP(mfa_secret).provisioning_uri(name=user['email'], issuer_name='SecureApp')
    img = qrcode.make(totp_uri)
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0)
    return send_file(buf, mimetype='image/png')

@app.route('/api/mfa/verify', methods=['POST'])
@token_required
def mfa_verify():
    db = get_db()
    user = g.current_user
    mfa_code = request.json.get('mfa_code')
    totp = pyotp.TOTP(user['mfa_secret'])
    if totp.verify(mfa_code):
        db.users.update_one({'username': user['username']}, {'$set': {'mfa_enabled': True}})
        return jsonify({'message': 'MFA enabled successfully!'})
    else:
        return jsonify({'message': 'Invalid code. MFA setup failed.'}), 400

@app.route('/api/request-reset', methods=['POST'])
def request_password_reset():
    db = get_db()
    email = request.json.get('email')
    user = db.users.find_one({'email': email})
    if user:
        reset_token = generate_action_token(email, 'reset_password', 15)
        reset_link = f"http://127.0.0.1:5000/login?reset_token={reset_token}"
        send_email(email, "Password Reset Request", f"Click here to reset your password: {reset_link}")
    return jsonify({'message': 'If an account with that email exists, a reset link has been sent.'})

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    db = get_db()
    data = request.get_json()
    token, new_password = data.get('token'), data.get('newPassword')
    try:
        payload = jwt.decode(token, app.config['ACTION_TOKEN_SECRET_KEY'], algorithms=['HS256'])
        if payload.get('action') != 'reset_password': raise Exception()
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        db.users.update_one({'email': payload['email']}, {'$set': {'password_hash': hashed_password}})
        return jsonify({'message': 'Password has been reset successfully.'})
    except Exception:
        return jsonify({'message': 'The reset link is invalid or has expired.'}), 401

@app.route('/api/dashboard-data')
@token_required
def dashboard_data():
    user = g.current_user
    # Get the token from the header to decode its expiration
    token = request.headers['Authorization'].split(' ')[1]
    token_data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    
    return jsonify({
        'message': f"Welcome, {user['username']}!",
        'data': f"This is protected data for your account.",
        'mfa_enabled': user.get('mfa_enabled'),
        'token_exp': token_data['exp'] # Add expiration timestamp to the response
    })

if __name__ == '__main__':
    app.run(debug=True)

