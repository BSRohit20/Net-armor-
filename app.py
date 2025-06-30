import os
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import secrets
import string
import re
import requests
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import json
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-here-change-this-in-production')

# File to store community posts
POSTS_FILE = 'community_posts.json'
PASSWORDS_FILE = 'passwords.json'

def load_posts():
    """Load community posts from file"""
    if os.path.exists(POSTS_FILE):
        with open(POSTS_FILE, 'r') as f:
            return json.load(f)
    return []

def save_posts(posts):
    """Save community posts to file"""
    with open(POSTS_FILE, 'w') as f:
        json.dump(posts, f, indent=2)

def load_passwords():
    """Load saved passwords from file"""
    if os.path.exists(PASSWORDS_FILE):
        with open(PASSWORDS_FILE, 'r') as f:
            return json.load(f)
    return []

def save_passwords(passwords):
    """Save passwords to file"""
    with open(PASSWORDS_FILE, 'w') as f:
        json.dump(passwords, f, indent=2)

@app.route('/')
def index():
    """Main homepage"""
    return render_template('index.html')

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

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    app.run(debug=debug_mode, host='0.0.0.0', port=port)
