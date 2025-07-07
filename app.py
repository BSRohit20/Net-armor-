import os
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
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
def generate_password():
    """API endpoint to generate a password"""
    data = request.json
    length = int(data.get('length', 12))
    include_uppercase = data.get('uppercase', True)
    include_lowercase = data.get('lowercase', True)
    include_digits = data.get('digits', True)
    include_special = data.get('special', True)
    
    if length < 4 or length > 128:
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
        return jsonify({'success': False, 'message': 'Please select at least one character type'})
    
    password = ''.join(secrets.choice(characters) for _ in range(length))
    return jsonify({'success': True, 'password': password})

@app.route('/password-strength')
def password_strength():
    """Password strength checker page"""
    return render_template('password_strength.html')

@app.route('/api/check_password_strength', methods=['POST'])
def check_password_strength():
    """API endpoint to check password strength"""
    data = request.json
    password = data.get('password', '')
    
    if not password:
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
    
    return jsonify({
        'success': True,
        'strength': strength,
        'score': score,
        'color': color,
        'feedback': feedback
    })

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

if __name__ == '__main__':
    # Initialize the application
    init_app()
    
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('FLASK_ENV') == 'development' and not IS_PRODUCTION
    
    app.logger.info(f"Starting NET ARMOR on port {port}")
    app.logger.info(f"Production mode: {IS_PRODUCTION}")
    app.logger.info(f"Debug mode: {debug_mode}")
    app.logger.info(f"Google OAuth enabled: {GOOGLE_OAUTH_ENABLED}")
    
    try:
        app.run(debug=debug_mode, host='0.0.0.0', port=port)
    except Exception as e:
        app.logger.error(f"Failed to start application: {str(e)}")
        print(f"ERROR: Failed to start NET ARMOR - {str(e)}")
