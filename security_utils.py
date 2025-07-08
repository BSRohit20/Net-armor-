# JWT Authentication and Advanced Security Features
import jwt
from datetime import datetime, timedelta
from functools import wraps
import secrets
import pyotp
import qrcode
from io import BytesIO
import base64

class SecurityManager:
    def __init__(self, app):
        self.app = app
        self.secret_key = app.config.get('SECRET_KEY', 'default-secret')
        
    def generate_jwt_token(self, user_id, expires_in=3600):
        """Generate JWT token for user authentication"""
        payload = {
            'user_id': user_id,
            'exp': datetime.utcnow() + timedelta(seconds=expires_in),
            'iat': datetime.utcnow(),
            'type': 'access'
        }
        return jwt.encode(payload, self.secret_key, algorithm='HS256')
    
    def generate_refresh_token(self, user_id):
        """Generate refresh token for token renewal"""
        payload = {
            'user_id': user_id,
            'exp': datetime.utcnow() + timedelta(days=30),
            'iat': datetime.utcnow(),
            'type': 'refresh'
        }
        return jwt.encode(payload, self.secret_key, algorithm='HS256')
    
    def verify_jwt_token(self, token):
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    
    def generate_2fa_secret(self):
        """Generate TOTP secret for 2FA"""
        return pyotp.random_base32()
    
    def generate_2fa_qr_code(self, user_email, secret):
        """Generate QR code for 2FA setup"""
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=user_email,
            issuer_name="NET ARMOR Security"
        )
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        
        return base64.b64encode(buffer.getvalue()).decode()
    
    def verify_2fa_token(self, secret, token):
        """Verify TOTP token"""
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=1)
    
    def generate_api_key(self):
        """Generate API key for user"""
        return secrets.token_urlsafe(32)
    
    def hash_api_key(self, api_key):
        """Hash API key for storage"""
        import hashlib
        return hashlib.sha256(api_key.encode()).hexdigest()

class ActivityLogger:
    def __init__(self):
        self.activities = []
        
    def log_activity(self, user_id, action, tool, ip_address, status='success', details=None):
        """Log user activity"""
        activity = {
            'timestamp': datetime.now().isoformat(),
            'user_id': user_id,
            'action': action,
            'tool': tool,
            'ip_address': ip_address,
            'status': status
        }
        if details:
            activity['details'] = details
            
        self.activities.append(activity)
        
        # Keep only last 1000 activities
        if len(self.activities) > 1000:
            self.activities = self.activities[-1000:]
    
    def get_recent_activities(self, limit=50):
        """Get recent activities"""
        return self.activities[-limit:]
    
    def get_user_activities(self, user_id, limit=50):
        """Get activities for specific user"""
        user_activities = [a for a in self.activities if a['user_id'] == user_id]
        return user_activities[-limit:]

class AnalyticsEngine:
    def __init__(self):
        self.metrics = {
            'total_users': 0,
            'passwords_generated': 0,
            'security_checks': 0,
            'threats_detected': 0,
            'tool_usage': {
                'password_generator': 0,
                'password_checker': 0,
                'ip_lookup': 0,
                'encryption': 0,
                'breach_checker': 0,
                'url_scanner': 0
            }
        }
    
    def increment_metric(self, metric_name, tool_name=None):
        """Increment analytics metric"""
        if metric_name in self.metrics:
            self.metrics[metric_name] += 1
        
        if tool_name and tool_name in self.metrics['tool_usage']:
            self.metrics['tool_usage'][tool_name] += 1
    
    def get_metrics(self):
        """Get current metrics"""
        return self.metrics
    
    def get_chart_data(self):
        """Get data for charts"""
        return {
            'toolUsage': list(self.metrics['tool_usage'].values()),
            'securityTrend': {
                'labels': ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
                'data': [85, 87, 92, 89, 95, 91, 88]
            },
            'geographic': [45, 25, 20, 10]  # USA, Europe, Asia, Other
        }

# Rate limiting decorator
def rate_limit(max_requests=60, window=60):
    """Rate limiting decorator"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Simple in-memory rate limiting
            # In production, use Redis
            from flask import request, jsonify
            
            client_ip = request.remote_addr
            current_time = datetime.now()
            
            # For now, just proceed - implement Redis-based rate limiting later
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# JWT required decorator
def jwt_required(f):
    """Decorator to require JWT authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from flask import request, jsonify, current_app
        
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token missing'}), 401
        
        try:
            token = token.split(' ')[1]  # Remove 'Bearer ' prefix
            security_manager = SecurityManager(current_app)
            payload = security_manager.verify_jwt_token(token)
            
            if not payload:
                return jsonify({'error': 'Invalid token'}), 401
                
            request.current_user_id = payload['user_id']
            return f(*args, **kwargs)
            
        except Exception as e:
            return jsonify({'error': 'Token invalid'}), 401
    return decorated_function
