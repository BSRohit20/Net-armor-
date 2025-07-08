import pytest
import json
import tempfile
import os
from app import app, load_users, save_users, hash_password
from security_utils import SecurityManager, ActivityLogger, AnalyticsEngine

@pytest.fixture
def client():
    """Create a test client for the app"""
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test-secret-key'
    
    with app.test_client() as client:
        with app.app_context():
            yield client

@pytest.fixture
def auth_headers():
    """Create authentication headers for testing"""
    security_manager = SecurityManager(app)
    token = security_manager.generate_jwt_token(1)
    return {'Authorization': f'Bearer {token}'}

class TestAuthentication:
    """Test authentication functionality"""
    
    def test_login_page_loads(self, client):
        """Test login page loads successfully"""
        rv = client.get('/login')
        assert rv.status_code == 200
        assert b'login' in rv.data.lower()
    
    def test_register_page_loads(self, client):
        """Test register page loads successfully"""
        rv = client.get('/register')
        assert rv.status_code == 200
        assert b'register' in rv.data.lower()
    
    def test_user_registration(self, client):
        """Test user registration functionality"""
        data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'testpassword123'
        }
        rv = client.post('/api/register', 
                        data=json.dumps(data),
                        content_type='application/json')
        
        assert rv.status_code == 200
        response_data = json.loads(rv.data)
        assert response_data['success'] == True
    
    def test_user_login(self, client):
        """Test user login functionality"""
        # First register a user
        reg_data = {
            'username': 'logintest',
            'email': 'login@example.com',
            'password': 'testpass123'
        }
        client.post('/api/register',
                   data=json.dumps(reg_data),
                   content_type='application/json')
        
        # Then try to login
        login_data = {
            'username': 'logintest',
            'password': 'testpass123'
        }
        rv = client.post('/api/login',
                        data=json.dumps(login_data),
                        content_type='application/json')
        
        assert rv.status_code == 200
        response_data = json.loads(rv.data)
        assert response_data['success'] == True
    
    def test_invalid_login(self, client):
        """Test login with invalid credentials"""
        data = {
            'username': 'nonexistent',
            'password': 'wrongpassword'
        }
        rv = client.post('/api/login',
                        data=json.dumps(data),
                        content_type='application/json')
        
        assert rv.status_code == 200
        response_data = json.loads(rv.data)
        assert response_data['success'] == False

class TestSecurityTools:
    """Test security tool functionality"""
    
    def test_password_generator(self, client):
        """Test password generator API"""
        data = {
            'length': 12,
            'uppercase': True,
            'lowercase': True,
            'digits': True,
            'special': True
        }
        rv = client.post('/api/generate_password',
                        data=json.dumps(data),
                        content_type='application/json')
        
        assert rv.status_code == 200
        response_data = json.loads(rv.data)
        assert response_data['success'] == True
        assert len(response_data['password']) == 12
    
    def test_password_strength_checker(self, client):
        """Test password strength checker API"""
        data = {'password': 'TestPassword123!'}
        rv = client.post('/api/check_password_strength',
                        data=json.dumps(data),
                        content_type='application/json')
        
        assert rv.status_code == 200
        response_data = json.loads(rv.data)
        assert response_data['success'] == True
        assert 'strength' in response_data
    
    def test_encryption_decryption(self, client):
        """Test encryption and decryption functionality"""
        # Test encryption
        encrypt_data = {
            'text': 'Secret message',
            'password': 'encryptionkey123'
        }
        rv = client.post('/api/encrypt',
                        data=json.dumps(encrypt_data),
                        content_type='application/json')
        
        assert rv.status_code == 200
        response_data = json.loads(rv.data)
        assert response_data['success'] == True
        encrypted_text = response_data['result']
        
        # Test decryption
        decrypt_data = {
            'text': encrypted_text,
            'password': 'encryptionkey123'
        }
        rv = client.post('/api/decrypt',
                        data=json.dumps(decrypt_data),
                        content_type='application/json')
        
        assert rv.status_code == 200
        response_data = json.loads(rv.data)
        assert response_data['success'] == True
        assert response_data['result'] == 'Secret message'
    
    def test_hash_generation(self, client):
        """Test hash generation functionality"""
        data = {'text': 'Hello World'}
        rv = client.post('/api/generate_hash',
                        data=json.dumps(data),
                        content_type='application/json')
        
        assert rv.status_code == 200
        response_data = json.loads(rv.data)
        assert response_data['success'] == True
        assert 'hashes' in response_data
        assert 'md5' in response_data['hashes']
        assert 'sha256' in response_data['hashes']
    
    def test_ip_lookup(self, client):
        """Test IP lookup functionality"""
        data = {'ip': '8.8.8.8'}
        rv = client.post('/api/lookup_ip',
                        data=json.dumps(data),
                        content_type='application/json')
        
        assert rv.status_code == 200
        response_data = json.loads(rv.data)
        # Note: This might fail in test environment without internet
        # In production, mock the external API call

class TestSecurityUtils:
    """Test security utilities"""
    
    def test_jwt_token_generation(self):
        """Test JWT token generation and verification"""
        security_manager = SecurityManager(app)
        
        # Generate token
        token = security_manager.generate_jwt_token(user_id=1)
        assert token is not None
        
        # Verify token
        payload = security_manager.verify_jwt_token(token)
        assert payload is not None
        assert payload['user_id'] == 1
    
    def test_2fa_secret_generation(self):
        """Test 2FA secret generation"""
        security_manager = SecurityManager(app)
        secret = security_manager.generate_2fa_secret()
        assert len(secret) == 32
    
    def test_activity_logging(self):
        """Test activity logging functionality"""
        logger = ActivityLogger()
        
        logger.log_activity(
            user_id=1,
            action='login',
            tool='authentication',
            ip_address='127.0.0.1'
        )
        
        activities = logger.get_recent_activities()
        assert len(activities) == 1
        assert activities[0]['user_id'] == 1
    
    def test_analytics_engine(self):
        """Test analytics engine functionality"""
        analytics = AnalyticsEngine()
        
        # Test metric increment
        analytics.increment_metric('passwords_generated')
        analytics.increment_metric('security_checks', 'password_generator')
        
        metrics = analytics.get_metrics()
        assert metrics['passwords_generated'] == 1
        assert metrics['tool_usage']['password_generator'] == 1

class TestDataValidation:
    """Test data validation and sanitization"""
    
    def test_email_validation(self, client):
        """Test email validation API"""
        # Valid email
        data = {'email': 'valid@example.com'}
        rv = client.post('/api/validate_email',
                        data=json.dumps(data),
                        content_type='application/json')
        
        assert rv.status_code == 200
        response_data = json.loads(rv.data)
        assert response_data['success'] == True
        
        # Invalid email
        data = {'email': 'invalid-email'}
        rv = client.post('/api/validate_email',
                        data=json.dumps(data),
                        content_type='application/json')
        
        assert rv.status_code == 200
        response_data = json.loads(rv.data)
        assert response_data['success'] == False
    
    def test_password_validation(self):
        """Test password hashing and verification"""
        password = 'testpassword123'
        hashed = hash_password(password)
        
        assert hashed != password
        assert len(hashed) == 64  # SHA-256 hex digest length

class TestErrorHandling:
    """Test error handling"""
    
    def test_404_error(self, client):
        """Test 404 error handling"""
        rv = client.get('/nonexistent-page')
        assert rv.status_code == 404
    
    def test_invalid_json_request(self, client):
        """Test handling of invalid JSON requests"""
        rv = client.post('/api/generate_password',
                        data='invalid json',
                        content_type='application/json')
        
        # Should handle gracefully without crashing

class TestPerformance:
    """Test performance-related functionality"""
    
    def test_password_generation_speed(self, client):
        """Test password generation performance"""
        import time
        
        data = {
            'length': 20,
            'uppercase': True,
            'lowercase': True,
            'digits': True,
            'special': True
        }
        
        start_time = time.time()
        for _ in range(100):
            client.post('/api/generate_password',
                       data=json.dumps(data),
                       content_type='application/json')
        end_time = time.time()
        
        # Should generate 100 passwords in less than 1 second
        assert (end_time - start_time) < 1.0

if __name__ == '__main__':
    pytest.main(['-v', __file__])
