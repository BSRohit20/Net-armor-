import os
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash, Response
import secrets
import string
import re
import requests
import base64
import tempfile
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import json
from datetime import datetime
import hashlib
import urllib.parse
from functools import wraps
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
# --- Analytics & Security ---
from security_utils import SecurityManager, ActivityLogger, AnalyticsEngine, rate_limit, jwt_required

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# Detect if running in production (deployment platform)
IS_PRODUCTION = os.environ.get('RAILWAY_ENVIRONMENT') or os.environ.get('RENDER') or os.environ.get('PORT')

# Google OAuth Configuration
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', '')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', '')

# Check if Google OAuth is properly configured
GOOGLE_OAUTH_ENABLED = bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and 
                           GOOGLE_CLIENT_ID != 'your-google-client-id-here' and
                           GOOGLE_CLIENT_SECRET != 'your-google-client-secret-here')

# OAuth 2.0 client configuration for Google (only if enabled)
client_config = None
if GOOGLE_OAUTH_ENABLED:
    # Get the base URL for OAuth redirects
    base_url = os.environ.get('BASE_URL', 'http://localhost:5000')
    if base_url.endswith('/'):
        base_url = base_url[:-1]
    
    client_config = {
        "web": {
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [f"{base_url}/auth/google/callback"]
        }
    }

# In-memory storage for production, file storage for development
if IS_PRODUCTION:
    # Use in-memory storage for production deployments
    community_posts = []
    user_passwords = []
    users_data = []
    
    # File paths won't be used in production
    POSTS_FILE = None
    PASSWORDS_FILE = None
    USERS_FILE = None
else:
    # Use file storage for development
    POSTS_FILE = 'community_posts.json'
    PASSWORDS_FILE = 'passwords.json'
    USERS_FILE = 'users.json'
    
    # Initialize in-memory storage as None for development
    community_posts = None
    user_passwords = None
    users_data = None

def load_posts():
    """Load community posts from file or memory"""
    global community_posts
    if IS_PRODUCTION:
        return community_posts if community_posts is not None else []
    else:
        if os.path.exists(POSTS_FILE):
            try:
                with open(POSTS_FILE, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return []
        return []

def save_posts(posts):
    """Save community posts to file or memory"""
    global community_posts
    if IS_PRODUCTION:
        community_posts = posts
    else:
        try:
            with open(POSTS_FILE, 'w') as f:
                json.dump(posts, f, indent=2)
        except IOError:
            # If file write fails, store in memory as fallback
            community_posts = posts

def load_passwords():
    """Load saved passwords from file or memory"""
    global user_passwords
    if IS_PRODUCTION:
        return user_passwords if user_passwords is not None else []
    else:
        if os.path.exists(PASSWORDS_FILE):
            try:
                with open(PASSWORDS_FILE, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return []
        return []

def save_passwords(passwords):
    """Save passwords to file or memory"""
    global user_passwords
    if IS_PRODUCTION:
        user_passwords = passwords
    else:
        try:
            with open(PASSWORDS_FILE, 'w') as f:
                json.dump(passwords, f, indent=2)
        except IOError:
            # If file write fails, store in memory as fallback
            user_passwords = passwords

def load_users():
    """Load users from file or memory"""
    global users_data
    if IS_PRODUCTION:
        return users_data if users_data is not None else []
    else:
        if os.path.exists(USERS_FILE):
            try:
                with open(USERS_FILE, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return []
        return []

def save_users(users):
    """Save users to file or memory"""
    global users_data
    if IS_PRODUCTION:
        users_data = users
    else:
        try:
            with open(USERS_FILE, 'w') as f:
                json.dump(users, f, indent=2)
        except IOError:
            # If file write fails, store in memory as fallback
            users_data = users

def hash_password(password):
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, hashed_password):
    """Verify password against hash"""
    return hash_password(password) == hashed_password

def login_required(f):
    """Decorator to require login for protected routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# === SECURITY & ANALYTICS INITIALIZATION ===
# Initialize security components after app creation
security_manager = SecurityManager(app)
activity_logger = ActivityLogger()
analytics_engine = AnalyticsEngine()

# === ROUTES ===

@app.route('/')
def index():
    """Main homepage"""
    try:
        return render_template('index.html')
    except Exception as e:
        app.logger.error(f"Error in index route: {str(e)}")
        return f"<h1>NET ARMOR Security Toolkit</h1><p>Welcome to NET ARMOR! The application is starting up.</p><p>Error: {str(e)}</p>", 500

@app.route('/login')
def login():
    """Login page"""
    return render_template('login.html', google_oauth_enabled=GOOGLE_OAUTH_ENABLED)

@app.route('/register')
def register():
    """Registration page"""
    return render_template('register.html', google_oauth_enabled=GOOGLE_OAUTH_ENABLED)

@app.route('/api/register', methods=['POST'])
def api_register():
    """API endpoint for user registration"""
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    email = data.get('email', '').strip()
    
    if not username or not password or not email:
        return jsonify({'success': False, 'message': 'All fields are required'})
    
    # Validate email format (enhanced)
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        return jsonify({'success': False, 'message': 'Please enter a valid email address'})
    
    # Additional email validation checks
    if len(email) > 254:  # Maximum email length according to RFC
        return jsonify({'success': False, 'message': 'Email address is too long'})
    
    # Check for common invalid patterns
    if '..' in email or email.startswith('.') or email.endswith('.'):
        return jsonify({'success': False, 'message': 'Invalid email format'})
    
    # Validate email domain (optional DNS check)
    try:
        domain = email.split('@')[1]
        # Check if domain has valid format
        if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain):
            return jsonify({'success': False, 'message': 'Invalid email domain'})
        
        # Optional: Check if domain exists (DNS lookup)
        # Uncomment the following lines if you want to verify domain exists
        # import socket
        # try:
        #     socket.gethostbyname(domain)
        # except socket.gaierror:
        #     return jsonify({'success': False, 'message': 'Email domain does not exist'})
        
    except IndexError:
        return jsonify({'success': False, 'message': 'Invalid email format'})
    
    # Check password strength
    if len(password) < 6:
        return jsonify({'success': False, 'message': 'Password must be at least 6 characters long'})
    
    users = load_users()
    
    # Check if username or email already exists
    for user in users:
        if user['username'].lower() == username.lower():
            return jsonify({'success': False, 'message': 'Username already exists'})
        if user['email'].lower() == email.lower():
            return jsonify({'success': False, 'message': 'Email already exists'})
    
    # Create new user
    new_user = {
        'id': len(users) + 1,
        'username': username,
        'email': email,
        'password': hash_password(password),
        'created_at': datetime.now().isoformat()
    }
    
    users.append(new_user)
    save_users(users)
    
    return jsonify({'success': True, 'message': 'Registration successful! Please login.'})

@app.route('/api/login', methods=['POST'])
def api_login():
    """API endpoint for user login"""
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    
    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password are required'})
    
    users = load_users()
    
    # Find user by username or email
    user = None
    for u in users:
        if u['username'].lower() == username.lower() or u['email'].lower() == username.lower():
            user = u
            break
    
    if not user:
        return jsonify({'success': False, 'message': 'Invalid username/email or password'})
    
    if not verify_password(password, user['password']):
        return jsonify({'success': False, 'message': 'Invalid username/email or password'})
    
    # Set session
    session['user_id'] = user['id']
    session['username'] = user['username']
    session['email'] = user['email']
    
    return jsonify({'success': True, 'message': 'Login successful!', 'redirect': url_for('dashboard')})

@app.route('/logout')
def logout():
    """Logout user"""
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/auth/google')
def google_login():
    """Initiate Google OAuth login"""
    if not GOOGLE_OAUTH_ENABLED:
        flash('Google OAuth is not configured. Please use regular login or contact administrator.', 'warning')
        return redirect(url_for('login'))
    
    try:
        # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow steps.
        flow = Flow.from_client_config(
            client_config,
            scopes=['openid', 'email', 'profile']
        )
        flow.redirect_uri = url_for('google_callback', _external=True)
        
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true'
        )
        
        # Store the state so the callback can verify the auth server response.
        session['state'] = state
        
        return redirect(authorization_url)
    except Exception as e:
        flash(f'Google authentication failed: {str(e)}', 'danger')
        return redirect(url_for('login'))

@app.route('/auth/google/callback')
def google_callback():
    """Handle Google OAuth callback"""
    if not GOOGLE_OAUTH_ENABLED:
        flash('Google OAuth is not configured.', 'danger')
        return redirect(url_for('login'))
    
    try:
        # Verify the state parameter
        if 'state' not in session or request.args.get('state') != session['state']:
            flash('Invalid state parameter. Please try again.', 'danger')
            return redirect(url_for('login'))
        
        # Create flow instance
        flow = Flow.from_client_config(
            client_config,
            scopes=['openid', 'email', 'profile'],
            state=session['state']
        )
        flow.redirect_uri = url_for('google_callback', _external=True)
        
        # Use the authorization server's response to fetch the OAuth 2.0 tokens.
        authorization_response = request.url
        flow.fetch_token(authorization_response=authorization_response)
        
        # Get user info from Google
        credentials = flow.credentials
        request_session = google_requests.Request()
        
        # Verify the token and get user info
        id_info = id_token.verify_oauth2_token(
            credentials.id_token, request_session, GOOGLE_CLIENT_ID
        )
        
        # Extract user information
        google_id = id_info.get('sub')
        email = id_info.get('email')
        name = id_info.get('name')
        picture = id_info.get('picture')
        
        if not email:
            flash('Unable to get email from Google account.', 'danger')
            return redirect(url_for('login'))
        
        # Load existing users
        users = load_users()
        
        # Check if user exists (by email or google_id)
        existing_user = None
        for user in users:
            if user.get('email') == email or user.get('google_id') == google_id:
                existing_user = user
                break
        
        if existing_user:
            # Update existing user with Google info
            existing_user['google_id'] = google_id
            existing_user['picture'] = picture
            if not existing_user.get('email'):
                existing_user['email'] = email
            if not existing_user.get('full_name'):
                existing_user['full_name'] = name
        else:
            # Create new user from Google account
            new_user = {
                'id': len(users) + 1,
                'username': email.split('@')[0],  # Use part before @ as username
                'email': email,
                'full_name': name,
                'google_id': google_id,
                'picture': picture,
                'password': '',  # No password needed for Google users
                'created_at': datetime.now().isoformat(),
                'login_method': 'google'
            }
            users.append(new_user)
            existing_user = new_user
        
        # Save updated users
        save_users(users)
        
        # Create session
        session['user_id'] = existing_user['id']
        session['username'] = existing_user['username']
        session['email'] = existing_user['email']
        session['full_name'] = existing_user.get('full_name', '')
        session['picture'] = existing_user.get('picture', '')
        session['login_method'] = 'google'
        
        flash(f'Welcome, {existing_user.get("full_name", existing_user["username"])}!', 'success')
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        flash(f'Google authentication failed: {str(e)}', 'danger')
        return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard (protected route)"""
    return render_template('dashboard.html', username=session.get('username'))

@app.route('/community')
def community():
    """Community posts page"""
    posts = load_posts()
    return render_template('community.html', posts=posts)

@app.route('/api/create_post', methods=['POST'])
def create_post():
    """API endpoint to create a new community post"""
    data = request.json
    name = data.get('name', '').strip()
    post_content = data.get('post', '').strip()
    
    if not name or not post_content:
        return jsonify({'success': False, 'message': 'Please enter both name and post content'})
    
    posts = load_posts()
    new_post = {
        'id': len(posts) + 1,
        'name': name,
        'content': post_content,
        'timestamp': datetime.now().isoformat()
    }
    posts.append(new_post)
    save_posts(posts)
    
    return jsonify({'success': True, 'message': 'Post created successfully'})

@app.route('/api/get_posts')
def get_posts():
    """API endpoint to get all community posts"""
    posts = load_posts()
    return jsonify(posts)

@app.route('/toolkit')
def toolkit():
    """Toolkit main page"""
    return render_template('toolkit.html')

@app.route('/password-manager')
def password_manager():
    """Password manager page"""
    passwords = load_passwords()
    return render_template('password_manager.html', passwords=passwords)

@app.route('/api/save_password', methods=['POST'])
def save_password():
    """API endpoint to save a password"""
    data = request.json
    website = data.get('website', '').strip()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    
    if not website or not username or not password:
        return jsonify({'success': False, 'message': 'All fields are required'})
    
    passwords = load_passwords()
    new_password = {
        'id': len(passwords) + 1,
        'website': website,
        'username': username,
        'password': password,
        'timestamp': datetime.now().isoformat()
    }
    passwords.append(new_password)
    save_passwords(passwords)
    
    return jsonify({'success': True, 'message': 'Password saved successfully'})

@app.route('/api/get_passwords')
def get_passwords():
    """API endpoint to get all saved passwords"""
    passwords = load_passwords()
    return jsonify(passwords)

@app.route('/password-generator')
def password_generator():
    """Password generator page"""
    return render_template('password_generator.html')

@app.route('/api/generate_password', methods=['POST'])
@rate_limit(max_requests=30, window=60)  # 30 password generations per minute
def generate_password():
    """API endpoint to generate a password"""
    try:
        data = request.json
        length = int(data.get('length', 12))
        include_uppercase = data.get('uppercase', True)
        include_lowercase = data.get('lowercase', True)
        include_digits = data.get('digits', True)
        include_special = data.get('special', True)
        
        user_id = session.get('user_id', 'anonymous')
        
        if length < 4 or length > 128:
            activity_logger.log_activity(
                user_id=user_id,
                action='password_generation',
                tool='password_generator',
                ip_address=request.remote_addr,
                status='failed',
                details=f'Invalid length: {length}'
            )
            return jsonify({'success': False, 'message': 'Password length must be between 4 and 128 characters'})
        
        characters = ''
        if include_lowercase:
            characters += string.ascii_lowercase
        if include_uppercase:
            characters += string.ascii_uppercase
        if include_digits:
            characters += string.digits
        if include_special:
            characters += '!@#$%^&*()_+-=[]{}|;:,.<>?'
        
        if not characters:
            activity_logger.log_activity(
                user_id=user_id,
                action='password_generation',
                tool='password_generator',
                ip_address=request.remote_addr,
                status='failed',
                details='No character types selected'
            )
            return jsonify({'success': False, 'message': 'Please select at least one character type'})
        
        password = ''.join(secrets.choice(characters) for _ in range(length))
        
        # Update analytics
        analytics_engine.increment_metric('passwords_generated')
        
        activity_logger.log_activity(
            user_id=user_id,
            action='password_generation',
            tool='password_generator',
            ip_address=request.remote_addr,
            status='success',
            details=f'Length: {length}, Types: {", ".join([t for t, enabled in [("lowercase", include_lowercase), ("uppercase", include_uppercase), ("digits", include_digits), ("special", include_special)] if enabled])}'
        )
        
        return jsonify({'success': True, 'password': password})
        
    except Exception as e:
        activity_logger.log_activity(
            user_id=session.get('user_id', 'anonymous'),
            action='password_generation',
            tool='password_generator',
            ip_address=request.remote_addr,
            status='error',
            details=str(e)
        )
        return jsonify({'success': False, 'message': 'An error occurred while generating password'})

@app.route('/password-strength')
def password_strength():
    """Password strength checker page"""
    return render_template('password_strength.html')

@app.route('/api/check_password_strength', methods=['POST'])
@rate_limit(max_requests=50, window=60)  # 50 strength checks per minute
def check_password_strength():
    """API endpoint to check password strength"""
    try:
        data = request.json
        password = data.get('password', '')
        user_id = session.get('user_id', 'anonymous')
        
        if not password:
            activity_logger.log_activity(
                user_id=user_id,
                action='password_strength_check',
                tool='password_strength',
                ip_address=request.remote_addr,
                status='failed',
                details='Empty password'
            )
            return jsonify({'success': False, 'message': 'Please enter a password'})
        
        score = 0
        feedback = []
        
        # Length check
        if len(password) >= 8:
            score += 1
        else:
            feedback.append('Password should be at least 8 characters long')
        
        # Uppercase check
        if re.search(r'[A-Z]', password):
            score += 1
        else:
            feedback.append('Add uppercase letters')
        
        # Lowercase check
        if re.search(r'[a-z]', password):
            score += 1
        else:
            feedback.append('Add lowercase letters')
        
        # Digit check
        if re.search(r'\d', password):
            score += 1
        else:
            feedback.append('Add numbers')
        
        # Special character check
        if re.search(r'[!@#$%^&*()_+-=\[\]{}|;:,.<>?]', password):
            score += 1
        else:
            feedback.append('Add special characters')
        
        # Determine strength
        if score <= 2:
            strength = 'Weak'
            color = 'red'
        elif score <= 3:
            strength = 'Medium'
            color = 'orange'
        else:
            strength = 'Strong'
            color = 'green'
        
        # Update analytics
        analytics_engine.increment_metric('security_checks', 'password_checker')
        
        activity_logger.log_activity(
            user_id=user_id,
            action='password_strength_check',
            tool='password_strength',
            ip_address=request.remote_addr,
            status='success',
            details=f'Strength: {strength}, Score: {score}/5'
        )
        
        return jsonify({
            'success': True,
            'strength': strength,
            'score': score,
            'color': color,
            'feedback': feedback
        })
        
    except Exception as e:
        activity_logger.log_activity(
            user_id=session.get('user_id', 'anonymous'),
            action='password_strength_check',
            tool='password_strength',
            ip_address=request.remote_addr,
            status='error',
            details=str(e)
        )
        return jsonify({'success': False, 'message': 'An error occurred while checking password strength'})

@app.route('/ip-lookup')
def ip_lookup():
    """IP lookup page"""
    return render_template('ip_lookup.html')

@app.route('/api/lookup_ip', methods=['POST'])
def lookup_ip():
    """API endpoint to lookup IP information"""
    data = request.json
    ip_address = data.get('ip', '').strip()
    
    if not ip_address:
        return jsonify({'success': False, 'message': 'Please enter an IP address'})
    
    try:
        # Using ipapi.co for IP lookup
        response = requests.get(f'http://ipapi.co/{ip_address}/json/', timeout=10)
        if response.status_code == 200:
            ip_data = response.json()
            return jsonify({'success': True, 'data': ip_data})
        else:
            return jsonify({'success': False, 'message': 'Failed to lookup IP address'})
    except requests.exceptions.RequestException:
        return jsonify({'success': False, 'message': 'Network error occurred'})

@app.route('/encryption')
def encryption():
    """Encryption/Decryption page"""
    return render_template('encryption.html')

@app.route('/api/encrypt', methods=['POST'])
def encrypt_text():
    """API endpoint to encrypt text"""
    data = request.json
    text = data.get('text', '')
    password = data.get('password', '')
    
    if not text or not password:
        return jsonify({'success': False, 'message': 'Please enter both text and password'})
    
    try:
        # Generate key from password
        password_bytes = password.encode()
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
        
        # Encrypt the text
        f = Fernet(key)
        encrypted_text = f.encrypt(text.encode())
        
        # Combine salt and encrypted text
        result = base64.b64encode(salt + encrypted_text).decode()
        
        return jsonify({'success': True, 'result': result})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Encryption failed: {str(e)}'})

@app.route('/api/decrypt', methods=['POST'])
def decrypt_text():
    """API endpoint to decrypt text"""
    data = request.json
    encrypted_text = data.get('text', '')
    password = data.get('password', '')
    
    if not encrypted_text or not password:
        return jsonify({'success': False, 'message': 'Please enter both encrypted text and password'})
    
    try:
        # Decode the encrypted text
        encrypted_data = base64.b64decode(encrypted_text.encode())
        salt = encrypted_data[:16]
        encrypted_text_bytes = encrypted_data[16:]
        
        # Generate key from password
        password_bytes = password.encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
        
        # Decrypt the text
        f = Fernet(key)
        decrypted_text = f.decrypt(encrypted_text_bytes).decode()
        
        return jsonify({'success': True, 'result': decrypted_text})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Decryption failed: {str(e)}'})

@app.route('/hash-analyzer')
def hash_analyzer():
    """Hash & Checksum Analyzer page"""
    return render_template('hash_analyzer.html')

@app.route('/api/generate_hash', methods=['POST'])
def generate_hash():
    """API endpoint to generate hashes"""
    data = request.json
    text = data.get('text', '').strip()
    
    if not text:
        return jsonify({'success': False, 'message': 'Please enter text to hash'})
    
    try:
        text_bytes = text.encode('utf-8')
        
        hashes_result = {
            'md5': hashlib.md5(text_bytes).hexdigest(),
            'sha1': hashlib.sha1(text_bytes).hexdigest(),
            'sha256': hashlib.sha256(text_bytes).hexdigest(),
            'sha512': hashlib.sha512(text_bytes).hexdigest()
        }
        
        return jsonify({'success': True, 'hashes': hashes_result})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Hash generation failed: {str(e)}'})

@app.route('/api/verify_hash', methods=['POST'])
def verify_hash():
    """API endpoint to verify hash"""
    data = request.json
    text = data.get('text', '').strip()
    hash_value = data.get('hash', '').strip().lower()
    
    if not text or not hash_value:
        return jsonify({'success': False, 'message': 'Please enter both text and hash'})
    
    try:
        text_bytes = text.encode('utf-8')
        
        # Determine hash type by length
        hash_type = 'unknown'
        computed_hash = ''
        
        if len(hash_value) == 32:  # MD5
            hash_type = 'MD5'
            computed_hash = hashlib.md5(text_bytes).hexdigest()
        elif len(hash_value) == 40:  # SHA1
            hash_type = 'SHA1'
            computed_hash = hashlib.sha1(text_bytes).hexdigest()
        elif len(hash_value) == 64:  # SHA256
            hash_type = 'SHA256'
            computed_hash = hashlib.sha256(text_bytes).hexdigest()
        elif len(hash_value) == 128:  # SHA512
            hash_type = 'SHA512'
            computed_hash = hashlib.sha512(text_bytes).hexdigest()
        else:
            return jsonify({'success': False, 'message': 'Unknown hash format'})
        
        is_match = computed_hash.lower() == hash_value
        
        return jsonify({
            'success': True,
            'hash_type': hash_type,
            'computed_hash': computed_hash,
            'is_match': is_match
        })
    except Exception as e:
        return jsonify({'success': False, 'message': f'Hash verification failed: {str(e)}'})

@app.route('/breach-checker')
def breach_checker():
    """Data Breach Checker page"""
    return render_template('breach_checker.html')

@app.route('/api/check_email_breach', methods=['POST'])
def check_email_breach():
    """API endpoint to check email for data breaches"""
    data = request.json
    email = data.get('email', '').strip().lower()
    
    if not email:
        return jsonify({'success': False, 'message': 'Please enter an email address'})
    
    # Basic email validation
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        return jsonify({'success': False, 'message': 'Please enter a valid email address'})
    
    try:
        # Using HaveIBeenPwned API
        headers = {
            'User-Agent': 'NET-ARMOR-Security-Toolkit'
        }
        
        # URL encode the email
        encoded_email = urllib.parse.quote(email)
        url = f'https://haveibeenpwned.com/api/v3/breachedaccount/{encoded_email}'
        
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            breaches = response.json()
            return jsonify({
                'success': True,
                'breached': True,
                'breach_count': len(breaches),
                'breaches': breaches
            })
        elif response.status_code == 404:
            return jsonify({
                'success': True,
                'breached': False,
                'message': 'No breaches found for this email'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Unable to check breaches at this time'
            })
    except requests.exceptions.RequestException:
        return jsonify({
            'success': False,
            'message': 'Network error occurred while checking breaches'
        })

@app.route('/api/check_password_breach', methods=['POST'])
def check_password_breach():
    """API endpoint to check password for breaches using k-anonymity"""
    data = request.json
    password = data.get('password', '')
    
    if not password:
        return jsonify({'success': False, 'message': 'Please enter a password'})
    
    try:
        # Hash the password with SHA-1
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        
        # Use k-anonymity: send first 5 characters, get back suffixes
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]
        
        headers = {
            'User-Agent': 'NET-ARMOR-Security-Toolkit'
        }
        
        url = f'https://api.pwnedpasswords.com/range/{prefix}'
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            # Check if our suffix is in the response
            hashes = response.text.splitlines()
            breach_count = 0
            
            for hash_line in hashes:
                hash_suffix, count = hash_line.split(':')
                if hash_suffix == suffix:
                    breach_count = int(count)
                    break
            
            return jsonify({
                'success': True,
                'breached': breach_count > 0,
                'breach_count': breach_count
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Unable to check password breaches at this time'
            })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Password breach check failed: {str(e)}'
        })

@app.route('/url-scanner')
def url_scanner():
    """URL Security Scanner page"""
    return render_template('url_scanner.html')

@app.route('/api/scan_url', methods=['POST'])
def scan_url():
    """API endpoint to scan URL for security threats"""
    data = request.json
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({'success': False, 'message': 'Please enter a URL'})
    
    # Basic URL validation
    if not re.match(r'^https?://', url):
        url = 'http://' + url
    
    try:
        # Check URL accessibility and get basic info
        headers = {
            'User-Agent': 'NET-ARMOR-Security-Toolkit/1.0'
        }
        
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        
        # Basic security checks
        security_headers = {
            'Content-Security-Policy': response.headers.get('Content-Security-Policy'),
            'X-Frame-Options': response.headers.get('X-Frame-Options'),
            'X-Content-Type-Options': response.headers.get('X-Content-Type-Options'),
            'Strict-Transport-Security': response.headers.get('Strict-Transport-Security'),
            'X-XSS-Protection': response.headers.get('X-XSS-Protection')
        }
        
        security_score = 0
        max_score = 5
        
        for header, value in security_headers.items():
            if value:
                security_score += 1
        
        # Check if HTTPS
        is_https = url.startswith('https://')
        if is_https:
            security_score += 1
            max_score += 1
        
        security_percentage = (security_score / max_score) * 100
        
        return jsonify({
            'success': True,
            'url': response.url,
            'status_code': response.status_code,
            'is_https': is_https,
            'security_headers': security_headers,
            'security_score': security_score,
            'max_score': max_score,
            'security_percentage': round(security_percentage, 1)
        })
    except requests.exceptions.RequestException as e:
        return jsonify({
            'success': False,
            'message': f'Unable to scan URL: {str(e)}'
        })

@app.route('/api/validate_email', methods=['POST'])
def validate_email():
    """API endpoint to validate email address"""
    data = request.json
    email = data.get('email', '').strip().lower()
    
    if not email:
        return jsonify({'success': False, 'message': 'Please enter an email address'})
    
    # Enhanced email format validation
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        return jsonify({'success': False, 'message': 'Invalid email format'})
    
    # Additional validation checks
    if len(email) > 254:
        return jsonify({'success': False, 'message': 'Email address is too long'})
    
    if '..' in email or email.startswith('.') or email.endswith('.'):
        return jsonify({'success': False, 'message': 'Invalid email format'})
    
    # Domain validation
    try:
        domain = email.split('@')[1]
        if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain):
            return jsonify({'success': False, 'message': 'Invalid email domain'})
        
        # Check for common disposable email domains
        disposable_domains = [
            '10minutemail.com', 'tempmail.org', 'guerrillamail.com', 
            'mailinator.com', 'throwaway.email', 'temp-mail.org',
            'getnada.com', 'maildrop.cc', 'yopmail.com'
        ]
        
        if domain in disposable_domains:
            return jsonify({
                'success': True, 
                'valid': True,
                'warning': 'This appears to be a temporary/disposable email address'
            })
        
        # Check if email already exists in our system
        users = load_users()
        for user in users:
            if user.get('email', '').lower() == email:
                return jsonify({'success': False, 'message': 'Email address is already registered'})
        
        # DNS lookup to verify domain exists (optional)
        import socket
        try:
            socket.gethostbyname(domain)
            domain_exists = True
        except socket.gaierror:
            domain_exists = False
        
        return jsonify({
            'success': True, 
            'valid': True,
            'domain_exists': domain_exists,
            'message': 'Email address is valid' if domain_exists else 'Email format is valid but domain may not exist'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': 'Email validation failed'})

def init_app():
    """Initialize application data"""
    global community_posts, user_passwords, users_data
    
    if IS_PRODUCTION:
        # Initialize in-memory storage for production
        if community_posts is None:
            community_posts = []
        if user_passwords is None:
            user_passwords = []
        if users_data is None:
            users_data = []
        
        app.logger.info("Running in PRODUCTION mode - using in-memory storage")
    else:
        app.logger.info("Running in DEVELOPMENT mode - using file storage")

@app.errorhandler(500)
def internal_server_error(error):
    """Handle internal server errors"""
    app.logger.error(f"Internal Server Error: {str(error)}")
    return render_template('error.html', 
                         error="Internal Server Error", 
                         message="Something went wrong on our end. Please try again later."), 500

@app.errorhandler(404)
def not_found_error(error):
    """Handle 404 errors"""
    return render_template('error.html', 
                         error="Page Not Found", 
                         message="The page you're looking for doesn't exist."), 404

@app.route('/api/health')
def health_check():
    """Health check endpoint for monitoring"""
    try:
        # Test basic functionality
        posts = load_posts()
        users = load_users()
        
        return jsonify({
            'status': 'healthy',
            'app': 'NET ARMOR Security Toolkit',
            'version': '2.0',
            'environment': 'production' if IS_PRODUCTION else 'development',
            'storage': 'in-memory' if IS_PRODUCTION else 'file-based',
            'google_oauth': GOOGLE_OAUTH_ENABLED,
            'data': {
                'posts_count': len(posts),
                'users_count': len(users)
            }
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 500

# === ANALYTICS DASHBOARD ===
@app.route('/analytics')
@login_required
def analytics():
    """Analytics dashboard page"""
    return render_template('analytics.html')

@app.route('/api/analytics')
@login_required
def api_analytics():
    """API endpoint to get analytics data"""
    try:
        users = load_users()
        analytics_engine.metrics['total_users'] = len(users)
        recent_activities = activity_logger.get_recent_activities(10)
        formatted_activities = []
        for activity in recent_activities:
            formatted_activities.append({
                'time': activity['timestamp'][:19].replace('T', ' '),
                'user': f"User {activity['user_id']}",
                'action': activity['action'].title(),
                'tool': activity['tool'].replace('_', ' ').title(),
                'ip': activity['ip_address'],
                'status': activity['status']
            })
        return jsonify({
            'success': True,
            'metrics': analytics_engine.get_metrics(),
            'charts': analytics_engine.get_chart_data(),
            'activity': formatted_activities
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/analytics/export')
@login_required
def export_analytics():
    """Export analytics data as CSV"""
    try:
        import csv
        from io import StringIO
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['Metric', 'Value'])
        metrics = analytics_engine.get_metrics()
        for key, value in metrics.items():
            if isinstance(value, dict):
                for sub_key, sub_value in value.items():
                    writer.writerow([f"{key}_{sub_key}", sub_value])
            else:
                writer.writerow([key, value])
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=net_armor_analytics.csv'}
        )
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# === JWT AUTHENTICATION API ===
@app.route('/api/auth/token', methods=['POST'])
@rate_limit(max_requests=5, window=300)  # 5 attempts per 5 minutes
def get_auth_token():
    """Get JWT token for API access"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
            
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            activity_logger.log_activity(
                user_id=username or 'unknown',
                action='token_request',
                tool='jwt_auth',
                ip_address=request.remote_addr,
                status='failed',
                details='Missing credentials'
            )
            return jsonify({'success': False, 'error': 'Username and password required'}), 400
        
        users = load_users()
        user = next((u for u in users if u['username'] == username), None)
        
        if user and verify_password(password, user['password']):
            # Generate JWT token
            token = security_manager.generate_jwt_token({
                'user_id': user['username'],
                'username': user['username']
            })
            
            activity_logger.log_activity(
                user_id=user['username'],
                action='token_generated',
                tool='jwt_auth',
                ip_address=request.remote_addr,
                status='success'
            )
            
            return jsonify({
                'success': True,
                'token': token,
                'expires_in': 3600  # 1 hour
            })
        else:
            activity_logger.log_activity(
                user_id=username,
                action='token_request',
                tool='jwt_auth',
                ip_address=request.remote_addr,
                status='failed',
                details='Invalid credentials'
            )
            return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/auth/verify', methods=['POST'])
def verify_auth_token():
    """Verify JWT token"""
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'success': False, 'error': 'No token provided'}), 401
            
        token = auth_header.split(' ')[1]
        payload = security_manager.verify_jwt_token(token)
        
        if payload:
            return jsonify({
                'success': True,
                'user_id': payload.get('user_id'),
                'username': payload.get('username')
            })
        else:
            return jsonify({'success': False, 'error': 'Invalid token'}), 401
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# === TWO-FACTOR AUTHENTICATION ===
@app.route('/api/2fa/setup', methods=['POST'])
@login_required
def setup_2fa():
    """Setup 2FA for current user"""
    try:
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
            
        # Generate TOTP secret
        secret = security_manager.totp_manager.generate_secret()
        
        # Create QR code URI
        qr_uri = security_manager.totp_manager.get_qr_code_uri(
            user_id, 
            secret,
            issuer_name="NET ARMOR Security Toolkit"
        )
        
        # Store secret temporarily (in production, use secure storage)
        session['temp_2fa_secret'] = secret
        
        activity_logger.log_activity(
            user_id=user_id,
            action='2fa_setup_initiated',
            tool='two_factor_auth',
            ip_address=request.remote_addr,
            status='success'
        )
        
        return jsonify({
            'success': True,
            'secret': secret,
            'qr_code_uri': qr_uri,
            'backup_codes': security_manager.totp_manager.generate_backup_codes()
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/2fa/verify', methods=['POST'])
@login_required
def verify_2fa():
    """Verify 2FA token and activate 2FA for user"""
    try:
        data = request.get_json()
        token = data.get('token')
        user_id = session.get('user_id')
        secret = session.get('temp_2fa_secret')
        
        if not token or not secret:
            return jsonify({'success': False, 'error': 'Missing token or secret'}), 400
            
        # Verify the token
        if security_manager.totp_manager.verify_token(secret, token):
            # Update user with 2FA enabled
            users = load_users()
            for user in users:
                if user['username'] == user_id:
                    user['2fa_enabled'] = True
                    user['2fa_secret'] = secret
                    break
            save_users(users)
            
            # Clear temporary secret
            session.pop('temp_2fa_secret', None)
            
            activity_logger.log_activity(
                user_id=user_id,
                action='2fa_enabled',
                tool='two_factor_auth',
                ip_address=request.remote_addr,
                status='success'
            )
            
            return jsonify({'success': True, 'message': '2FA successfully enabled'})
        else:
            return jsonify({'success': False, 'error': 'Invalid token'}), 400
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/2fa/disable', methods=['POST'])
@login_required
def disable_2fa():
    """Disable 2FA for current user"""
    try:
        data = request.get_json()
        password = data.get('password')
        user_id = session.get('user_id')
        
        if not password:
            return jsonify({'success': False, 'error': 'Password required'}), 400
            
        users = load_users()
        user = next((u for u in users if u['username'] == user_id), None)
        
        if user and verify_password(password, user['password']):
            user['2fa_enabled'] = False
            user.pop('2fa_secret', None)
            save_users(users)
            
            activity_logger.log_activity(
                user_id=user_id,
                action='2fa_disabled',
                tool='two_factor_auth',
                ip_address=request.remote_addr,
                status='success'
            )
            
            return jsonify({'success': True, 'message': '2FA successfully disabled'})
        else:
            return jsonify({'success': False, 'error': 'Invalid password'}), 401
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/2fa/status')
@login_required
def get_2fa_status():
    """Get 2FA status for current user"""
    try:
        user_id = session.get('user_id')
        users = load_users()
        user = next((u for u in users if u['username'] == user_id), None)
        
        if user:
            return jsonify({
                'success': True,
                'enabled': user.get('2fa_enabled', False)
            })
        else:
            return jsonify({'success': False, 'error': 'User not found'}), 404
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# === NEW SECURITY TOOLS ===

@app.route('/domain-scanner')
@login_required
def domain_scanner():
    """Domain Security Scanner tool page"""
    return render_template('domain_scanner.html')

@app.route('/vulnerability-scanner')
@login_required  
def vulnerability_scanner():
    """Vulnerability Scanner tool page"""
    return render_template('vulnerability_scanner.html')

@app.route('/password-policy-analyzer')
@login_required
def password_policy_analyzer():
    """Password Policy Analyzer tool page"""
    return render_template('password_policy_analyzer.html')

@app.route('/api/scan_domain', methods=['POST'])
@login_required
@rate_limit(max_requests=10, window=300)  # 10 requests per 5 minutes
def scan_domain():
    """API endpoint for domain security scanning"""
    try:
        data = request.get_json()
        domain = data.get('domain', '').strip()
        
        if not domain:
            return jsonify({'success': False, 'error': 'Domain is required'}), 400
        
        # Remove protocol if present
        domain = domain.replace('http://', '').replace('https://', '').replace('www.', '')
        domain = domain.split('/')[0]  # Remove path if present
        
        # Validate domain format
        domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        if not re.match(domain_pattern, domain):
            return jsonify({'success': False, 'error': 'Invalid domain format'}), 400
        
        # Initialize scan results
        scan_results = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'ssl_info': {},
            'dns_info': {},
            'security_headers': {},
            'ports': {},
            'whois_info': {},
            'security_score': 0,
            'recommendations': []
        }
        
        # SSL/TLS Certificate Check
        try:
            import ssl
            import socket
            
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    scan_results['ssl_info'] = {
                        'enabled': True,
                        'version': ssock.version(),
                        'cipher': ssock.cipher(),
                        'issuer': dict(x[0] for x in cert['issuer']) if cert.get('issuer') else {},
                        'subject': dict(x[0] for x in cert['subject']) if cert.get('subject') else {},
                        'expires': cert.get('notAfter', 'Unknown'),
                        'serial_number': cert.get('serialNumber', 'Unknown')
                    }
                    
                    # Check if certificate is expiring soon
                    try:
                        expires_str = cert.get('notAfter')
                        if expires_str:
                            expires = datetime.strptime(expires_str, '%b %d %H:%M:%S %Y %Z')
                            days_until_expiry = (expires - datetime.now()).days
                            
                            if days_until_expiry < 30:
                                scan_results['recommendations'].append(f"SSL certificate expires in {days_until_expiry} days")
                    except Exception:
                        pass  # Ignore date parsing errors
                    
                    scan_results['security_score'] += 25
                    
        except Exception as e:
            scan_results['ssl_info'] = {'enabled': False, 'error': str(e)}
            scan_results['recommendations'].append("SSL/TLS not properly configured")
        
        # DNS Information
        try:
            import socket
            scan_results['dns_info'] = {
                'ip_address': socket.gethostbyname(domain),
                'mx_records': [],
                'txt_records': []
            }
            scan_results['security_score'] += 10
        except Exception as e:
            scan_results['dns_info'] = {'error': str(e)}
        
        # Security Headers Check
        try:
            response = requests.get(f'https://{domain}', timeout=10, allow_redirects=True)
            headers = response.headers
            
            security_headers = {
                'Strict-Transport-Security': headers.get('Strict-Transport-Security', 'Not Set'),
                'Content-Security-Policy': headers.get('Content-Security-Policy', 'Not Set'),
                'X-Frame-Options': headers.get('X-Frame-Options', 'Not Set'),
                'X-Content-Type-Options': headers.get('X-Content-Type-Options', 'Not Set'),
                'X-XSS-Protection': headers.get('X-XSS-Protection', 'Not Set'),
                'Referrer-Policy': headers.get('Referrer-Policy', 'Not Set')
            }
            
            scan_results['security_headers'] = security_headers
            
            # Score based on security headers
            header_score = 0
            for header, value in security_headers.items():
                if value != 'Not Set':
                    header_score += 5
            
            scan_results['security_score'] += min(header_score, 30)
            
            # Add recommendations for missing headers
            for header, value in security_headers.items():
                if value == 'Not Set':
                    scan_results['recommendations'].append(f"Missing security header: {header}")
                    
        except Exception as e:
            scan_results['security_headers'] = {'error': str(e)}
            scan_results['recommendations'].append("Unable to check security headers")
        
        # Port Scan (common ports only)
        try:
            import socket
            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389]
            open_ports = []
            
            for port in common_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((domain, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            
            scan_results['ports'] = {'open_ports': open_ports}
            
            # Check for risky open ports
            risky_ports = [21, 23, 25, 110, 143, 3389]
            for port in open_ports:
                if port in risky_ports:
                    scan_results['recommendations'].append(f"Potentially risky port {port} is open")
                    
        except Exception as e:
            scan_results['ports'] = {'error': str(e)}
        
        # Basic WHOIS information (simplified)
        try:
            # This is a simplified version - in production you'd use a proper WHOIS library
            scan_results['whois_info'] = {
                'status': 'Available via WHOIS lookup',
                'note': 'Full WHOIS data requires specialized library'
            }
        except Exception as e:
            scan_results['whois_info'] = {'error': str(e)}
        
        # Calculate final security score (out of 100)
        scan_results['security_score'] = min(scan_results['security_score'], 100)
        
        # Add overall recommendations based on score
        if scan_results['security_score'] < 50:
            scan_results['recommendations'].insert(0, "Domain has significant security vulnerabilities")
        elif scan_results['security_score'] < 75:
            scan_results['recommendations'].insert(0, "Domain security can be improved")
        else:
            scan_results['recommendations'].insert(0, "Domain has good security configuration")
        
        # Log the activity
        activity_logger.log_activity(
            user_id=session.get('user_id'),
            action='domain_scan',
            tool='domain_scanner',
            details={'domain': domain, 'score': scan_results['security_score']},
            ip_address=request.remote_addr,
            status='success'
        )
        
        return jsonify({'success': True, 'results': scan_results})
        
    except Exception as e:
        activity_logger.log_activity(
            user_id=session.get('user_id'),
            action='domain_scan',
            tool='domain_scanner',
            ip_address=request.remote_addr,
            status='error',
            details={'error': str(e)}
        )
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/vulnerability_scan', methods=['POST'])
@login_required
@rate_limit(max_requests=5, window=300)  # 5 requests per 5 minutes (more intensive)
def vulnerability_scan():
    """API endpoint for vulnerability scanning"""
    try:
        data = request.get_json()
        target = data.get('target', '').strip()
        scan_type = data.get('scan_type', 'basic')
        
        if not target:
            return jsonify({'success': False, 'error': 'Target is required'}), 400
        
        # Initialize scan results
        scan_results = {
            'target': target,
            'scan_type': scan_type,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': [],
            'summary': {
                'total_vulnerabilities': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            },
            'recommendations': []
        }
        
        # Basic vulnerability checks
        vulnerabilities_found = []
        
        # Check for common web vulnerabilities
        try:
            # Test for HTTP vs HTTPS
            try:
                response = requests.get(f'http://{target}', timeout=10, allow_redirects=False)
                if response.status_code != 301 and response.status_code != 302:
                    vulnerabilities_found.append({
                        'type': 'HTTP Not Redirected to HTTPS',
                        'severity': 'Medium',
                        'description': 'Site accessible via HTTP without redirect to HTTPS',
                        'recommendation': 'Implement HTTPS redirect for all HTTP requests'
                    })
            except:
                pass
            
            # Check for security headers
            try:
                response = requests.get(f'https://{target}', timeout=10)
                headers = response.headers
                
                security_checks = {
                    'X-Frame-Options': 'Clickjacking protection missing',
                    'X-Content-Type-Options': 'MIME type sniffing protection missing',
                    'X-XSS-Protection': 'XSS protection header missing',
                    'Strict-Transport-Security': 'HSTS header missing',
                    'Content-Security-Policy': 'CSP header missing'
                }
                
                for header, description in security_checks.items():
                    if header not in headers:
                        vulnerabilities_found.append({
                            'type': f'Missing {header}',
                            'severity': 'Medium' if header == 'Content-Security-Policy' else 'Low',
                            'description': description,
                            'recommendation': f'Add {header} security header'
                        })
                
                # Check for server information disclosure
                if 'Server' in headers:
                    vulnerabilities_found.append({
                        'type': 'Server Information Disclosure',
                        'severity': 'Low',
                        'description': f'Server header reveals: {headers["Server"]}',
                        'recommendation': 'Remove or obscure server version information'
                    })
                
                # Check for directory listing
                test_paths = ['/admin', '/backup', '/.git', '/.env', '/config']
                for path in test_paths:
                    try:
                        test_response = requests.get(f'https://{target}{path}', timeout=5)
                        if test_response.status_code == 200 and 'Index of' in test_response.text:
                            vulnerabilities_found.append({
                                'type': 'Directory Listing Enabled',
                                'severity': 'Medium',
                                'description': f'Directory listing enabled at {path}',
                                'recommendation': 'Disable directory listing on web server'
                            })
                    except:
                        continue
                        
            except Exception as e:
                vulnerabilities_found.append({
                    'type': 'HTTPS Connection Failed',
                    'severity': 'High',
                    'description': f'Unable to establish secure connection: {str(e)}',
                    'recommendation': 'Ensure SSL/TLS is properly configured'
                })
        
        except Exception as e:
            pass
        
        # If advanced scan requested, add more checks
        if scan_type == 'advanced':
            # SQL Injection basic test (very basic, educational purposes)
            try:
                test_payloads = ["'", '"', "1' OR '1'='1"]
                for payload in test_payloads:
                    test_url = f'https://{target}/?id={payload}'
                    try:
                        response = requests.get(test_url, timeout=5)
                        if any(error in response.text.lower() for error in ['sql error', 'mysql error', 'postgresql error']):
                            vulnerabilities_found.append({
                                'type': 'Potential SQL Injection',
                                'severity': 'Critical',
                                'description': 'Database error messages detected in response',
                                'recommendation': 'Implement proper input validation and parameterized queries'
                            })
                            break
                    except:
                        continue
            except:
                pass
        
        # Categorize vulnerabilities
        for vuln in vulnerabilities_found:
            severity = vuln['severity'].lower()
            scan_results['summary'][severity] += 1
            scan_results['summary']['total_vulnerabilities'] += 1
        
        scan_results['vulnerabilities'] = vulnerabilities_found
        
        # Generate recommendations
        if scan_results['summary']['critical'] > 0:
            scan_results['recommendations'].append("Address critical vulnerabilities immediately")
        if scan_results['summary']['high'] > 0:
            scan_results['recommendations'].append("High-severity vulnerabilities require urgent attention")
        if scan_results['summary']['total_vulnerabilities'] == 0:
            scan_results['recommendations'].append("No common vulnerabilities detected in basic scan")
        
        scan_results['recommendations'].append("Consider professional penetration testing for comprehensive security assessment")
        
        # Log the activity
        activity_logger.log_activity(
            user_id=session.get('user_id'),
            action='vulnerability_scan',
            tool='vulnerability_scanner',
            details={'target': target, 'vulnerabilities_found': scan_results['summary']['total_vulnerabilities']},
            ip_address=request.remote_addr,
            status='success'
        )
        
        return jsonify({'success': True, 'results': scan_results})
        
    except Exception as e:
        activity_logger.log_activity(
            user_id=session.get('user_id'),
            action='vulnerability_scan',
            tool='vulnerability_scanner',
            ip_address=request.remote_addr,
            status='error',
            details={'error': str(e)}
        )
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/analyze_password_policy', methods=['POST'])
@login_required
@rate_limit(max_requests=20, window=300)  # 20 requests per 5 minutes
def analyze_password_policy():
    """API endpoint for password policy analysis"""
    try:
        data = request.get_json()
        policy_text = data.get('policy_text', '').strip()
        
        if not policy_text:
            return jsonify({'success': False, 'error': 'Policy text is required'}), 400
        
        # Initialize analysis results
        analysis_results = {
            'policy_text': policy_text,
            'timestamp': datetime.now().isoformat(),
            'analysis': {
                'length_requirements': {},
                'character_requirements': {},
                'expiration_policy': {},
                'lockout_policy': {},
                'complexity_requirements': {},
                'common_patterns': []
            },
            'score': 0,
            'grade': 'F',
            'strengths': [],
            'weaknesses': [],
            'recommendations': []
        }
        
        policy_lower = policy_text.lower()
        
        # Analyze length requirements
        length_patterns = [
            (r'(?:minimum|min|at least) (\d+) character', 'minimum_length'),
            (r'(\d+) character minimum', 'minimum_length'),
            (r'(?:maximum|max|no more than) (\d+) character', 'maximum_length')
        ]
        
        for pattern, requirement_type in length_patterns:
            import re
            match = re.search(pattern, policy_lower)
            if match:
                length = int(match.group(1))
                analysis_results['analysis']['length_requirements'][requirement_type] = length
                
                if requirement_type == 'minimum_length':
                    if length >= 12:
                        analysis_results['score'] += 25
                        analysis_results['strengths'].append(f"Strong minimum length requirement ({length} characters)")
                    elif length >= 8:
                        analysis_results['score'] += 15
                        analysis_results['strengths'].append(f"Adequate minimum length requirement ({length} characters)")
                    else:
                        analysis_results['weaknesses'].append(f"Weak minimum length requirement ({length} characters)")
                        analysis_results['recommendations'].append("Increase minimum password length to at least 12 characters")
        
        # Analyze character requirements
        character_checks = {
            'uppercase': [r'upper.?case', r'capital letter', r'[A-Z]'],
            'lowercase': [r'lower.?case', r'small letter', r'[a-z]'],
            'numbers': [r'number', r'digit', r'\d', r'[0-9]'],
            'special_characters': [r'special character', r'symbol', r'[!@#$%^&*]', r'punctuation']
        }
        
        character_score = 0
        for char_type, patterns in character_checks.items():
            found = any(re.search(pattern, policy_lower) for pattern in patterns)
            analysis_results['analysis']['character_requirements'][char_type] = found
            if found:
                character_score += 5
                analysis_results['strengths'].append(f"Requires {char_type.replace('_', ' ')}")
            else:
                analysis_results['weaknesses'].append(f"Missing {char_type.replace('_', ' ')} requirement")
        
        analysis_results['score'] += character_score
        
        # Analyze expiration policy
        expiration_patterns = [
            (r'(?:expire|change|update).*?(\d+) day', 'days'),
            (r'(\d+) day.*?(?:expire|change)', 'days'),
            (r'(?:expire|change|update).*?(\d+) month', 'months'),
            (r'(\d+) month.*?(?:expire|change)', 'months')
        ]
        
        for pattern, unit in expiration_patterns:
            match = re.search(pattern, policy_lower)
            if match:
                period = int(match.group(1))
                analysis_results['analysis']['expiration_policy'] = {'period': period, 'unit': unit}
                
                if unit == 'days':
                    if period <= 30:
                        analysis_results['weaknesses'].append(f"Very frequent password changes required ({period} days)")
                        analysis_results['recommendations'].append("Consider longer password expiration periods")
                    elif period <= 90:
                        analysis_results['score'] += 10
                        analysis_results['strengths'].append(f"Reasonable password expiration ({period} days)")
                    else:
                        analysis_results['score'] += 5
                        analysis_results['strengths'].append(f"Password expiration policy in place ({period} days)")
                elif unit == 'months':
                    if period <= 6:
                        analysis_results['score'] += 10
                        analysis_results['strengths'].append(f"Reasonable password expiration ({period} months)")
                    else:
                        analysis_results['score'] += 5
                        analysis_results['strengths'].append(f"Password expiration policy in place ({period} months)")
                break
        
        # Analyze lockout policy
        lockout_patterns = [
            r'lock.*?account',
            r'account.*?lock',
            r'failed.*?attempt',
            r'incorrect.*?password',
            r'block.*?user'
        ]
        
        if any(re.search(pattern, policy_lower) for pattern in lockout_patterns):
            analysis_results['analysis']['lockout_policy']['enabled'] = True
            analysis_results['score'] += 15
            analysis_results['strengths'].append("Account lockout policy defined")
        else:
            analysis_results['analysis']['lockout_policy']['enabled'] = False
            analysis_results['weaknesses'].append("No account lockout policy mentioned")
            analysis_results['recommendations'].append("Implement account lockout after failed login attempts")
        
        # Check for complexity requirements
        complexity_patterns = {
            'no_dictionary_words': [r'dictionary word', r'common word'],
            'no_personal_info': [r'personal information', r'name', r'birthday'],
            'no_previous_passwords': [r'previous password', r'recent password', r'password history'],
            'no_keyboard_patterns': [r'keyboard pattern', r'sequential', r'qwerty']
        }
        
        for requirement, patterns in complexity_patterns.items():
            found = any(re.search(pattern, policy_lower) for pattern in patterns)
            analysis_results['analysis']['complexity_requirements'][requirement] = found
            if found:
                analysis_results['score'] += 5
                analysis_results['strengths'].append(f"Prohibits {requirement.replace('_', ' ').replace('no ', '')}")
        
        # Check for common security patterns
        security_patterns = [
            ('multi-factor authentication', 'MFA requirement'),
            ('two.factor', '2FA requirement'),
            ('single sign.on', 'SSO integration'),
            ('password manager', 'Password manager recommendation'),
            ('encryption', 'Password encryption mentioned')
        ]
        
        for pattern, description in security_patterns:
            if re.search(pattern, policy_lower):
                analysis_results['analysis']['common_patterns'].append(description)
                analysis_results['score'] += 10
                analysis_results['strengths'].append(description)
        
        # Calculate grade based on score
        if analysis_results['score'] >= 80:
            analysis_results['grade'] = 'A'
        elif analysis_results['score'] >= 70:
            analysis_results['grade'] = 'B'
        elif analysis_results['score'] >= 60:
            analysis_results['grade'] = 'C'
        elif analysis_results['score'] >= 50:
            analysis_results['grade'] = 'D'
        else:
            analysis_results['grade'] = 'F'
        
        # Add general recommendations
        if analysis_results['score'] < 70:
            analysis_results['recommendations'].extend([
                "Consider implementing multi-factor authentication",
                "Provide password manager recommendations to users",
                "Include guidance on creating strong, unique passwords",
                "Regular security awareness training for users"
            ])
        
        # Log the activity
        activity_logger.log_activity(
            user_id=session.get('user_id'),
            action='password_policy_analysis',
            tool='password_policy_analyzer',
            details={'score': analysis_results['score'], 'grade': analysis_results['grade']},
            ip_address=request.remote_addr,
            status='success'
        )
        
        return jsonify({'success': True, 'results': analysis_results})
        
    except Exception as e:
        activity_logger.log_activity(
            user_id=session.get('user_id'),
            action='password_policy_analysis',
            tool='password_policy_analyzer',
            ip_address=request.remote_addr,
            status='error',
            details={'error': str(e)}
        )
        return jsonify({'success': False, 'error': str(e)}), 500

# === END NEW SECURITY TOOLS ===

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=not IS_PRODUCTION)
