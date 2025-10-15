# Import necessary libraries
from flask import Flask, request, jsonify, render_template, g
import bcrypt
import jwt
from datetime import datetime, timedelta, timezone
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, OperationFailure
import os
from functools import wraps # Required for creating decorators

# --- Initial Configuration ---

app = Flask(__name__)
# IMPORTANT: Use two different secret keys in a real application
app.config['SECRET_KEY'] = 'your-super-secret-key-for-access-tokens'
app.config['REFRESH_SECRET_KEY'] = 'another-super-secret-key-for-refresh-tokens'

# --- MongoDB Configuration ---
MONGO_URI = os.environ.get('MONGO_URI', "mongodb://localhost:27017/")

def get_db():
    if 'db' not in g:
        try:
            g.client = MongoClient(MONGO_URI)
            g.client.admin.command('ismaster')
            g.db = g.client['auth_system_db']
            print("MongoDB connection successful.")
        except ConnectionFailure as e:
            print(f"Could not connect to MongoDB: {e}")
            raise e
    return g.db

@app.teardown_appcontext
def teardown_db(exception):
    client = g.pop('client', None)
    if client is not None:
        client.close()
        print("MongoDB connection closed.")

# Ensure unique username index on startup
try:
    with app.app_context():
        db = get_db()
        db.users.create_index("username", unique=True)
        print("Username index ensured.")
except Exception as e:
    print(f"Info: Index creation skipped (likely already exists): {e}")
    pass

# --- Decorators for Role-Based Access ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        db = get_db()
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'message': 'Access token is missing or invalid'}), 401
        token = auth_header.split(' ')[1]
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            g.current_user = db.users.find_one({'username': data['sub']})
            if not g.current_user:
                 return jsonify({'message': 'User not found'}), 404
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Access token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Access token is invalid'}), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    @token_required
    def decorated(*args, **kwargs):
        if g.current_user.get('role') != 'admin':
            return jsonify({'message': 'Admins only! Access denied.'}), 403
        return f(*args, **kwargs)
    return decorated

# --- HTML Page Routes ---
@app.route('/')
def home(): return render_template('home.html')
@app.route('/login')
def login_page(): return render_template('login.html')
@app.route('/register')
def register_page(): return render_template('register.html')
@app.route('/profile')
def profile_page(): return render_template('profile.html')

# --- API Endpoints ---
@app.route('/api/auth/register', methods=['POST'])
def register():
    db = get_db()
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400
    if len(password.encode('utf-8')) > 72:
        return jsonify({'message': 'Password is too long'}), 400
    if db.users.find_one({'username': username}):
        return jsonify({'message': 'Username already exists'}), 409

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    # Assign a default role of 'user' to new registrations
    db.users.insert_one({"username": username, "password_hash": hashed_password, "role": "user"})
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    db = get_db()
    data = request.get_json()
    user = db.users.find_one({'username': data.get('username')})

    if not user or not bcrypt.checkpw(data.get('password').encode('utf-8'), user['password_hash']):
        return jsonify({'message': 'Invalid credentials'}), 401

    # Create short-lived access token
    access_payload = {
        'sub': user['username'],
        'role': user.get('role', 'user'), # Include role in the token
        'iat': datetime.now(timezone.utc),
        'exp': datetime.now(timezone.utc) + timedelta(minutes=15) # Short-lived
    }
    access_token = jwt.encode(access_payload, app.config['SECRET_KEY'], algorithm='HS256')

    # Create long-lived refresh token
    refresh_payload = {
        'sub': user['username'],
        'iat': datetime.now(timezone.utc),
        'exp': datetime.now(timezone.utc) + timedelta(days=7) # Long-lived
    }
    refresh_token = jwt.encode(refresh_payload, app.config['REFRESH_SECRET_KEY'], algorithm='HS256')

    return jsonify({'accessToken': access_token, 'refreshToken': refresh_token})

@app.route('/api/auth/refresh', methods=['POST'])
def refresh():
    data = request.get_json()
    refresh_token = data.get('refreshToken')
    if not refresh_token:
        return jsonify({'message': 'Refresh token is missing'}), 400

    try:
        payload = jwt.decode(refresh_token, app.config['REFRESH_SECRET_KEY'], algorithms=['HS256'])
        db = get_db()
        user = db.users.find_one({'username': payload['sub']})
        if not user:
            return jsonify({'message': 'User not found'}), 404
        
        # Issue a new access token
        access_payload = {
            'sub': user['username'],
            'role': user.get('role', 'user'),
            'iat': datetime.now(timezone.utc),
            'exp': datetime.now(timezone.utc) + timedelta(minutes=15)
        }
        access_token = jwt.encode(access_payload, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'accessToken': access_token})

    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Refresh token has expired. Please log in again.'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Refresh token is invalid.'}), 401

@app.route('/api/profile')
@token_required
def api_profile():
    # The user object is attached to 'g' by the decorator
    user = g.current_user
    return jsonify({
        'message': f"Welcome {user['username']}!",
        'data': 'This is your user profile data.',
        'role': user.get('role', 'user')
    })

@app.route('/api/admin/data')
@admin_required
def admin_data():
    return jsonify({
        'message': 'Welcome Admin!',
        'data': 'This is top-secret data only visible to administrators.'
    })

if __name__ == '__main__':
    app.run(debug=True)

