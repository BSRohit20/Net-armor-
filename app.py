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
import hashlib
import urllib.parse

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

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    app.run(debug=debug_mode, host='0.0.0.0', port=port)
