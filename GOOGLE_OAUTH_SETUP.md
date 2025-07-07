# Google OAuth Setup Guide for NET ARMOR

## 🔧 Setting up Google OAuth

### Step 1: Create Google Cloud Project
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Enable the "Google+ API" and "Google Identity" APIs

### Step 2: Create OAuth 2.0 Credentials
1. Go to "Credentials" in the left menu
2. Click "Create Credentials" → "OAuth 2.0 Client IDs"
3. Set Application type to "Web application"
4. Add these Authorized redirect URIs:
   - `http://localhost:5000/auth/google/callback`
   - `https://your-domain.com/auth/google/callback` (for production)

### Step 3: Get Client ID and Secret
1. Copy your Client ID and Client Secret
2. Add them to your environment variables:

#### For Development (Local):
```bash
export GOOGLE_CLIENT_ID="your-google-client-id-here"
export GOOGLE_CLIENT_SECRET="your-google-client-secret-here"
```

#### For Windows (Local):
```cmd
set GOOGLE_CLIENT_ID=your-google-client-id-here
set GOOGLE_CLIENT_SECRET=your-google-client-secret-here
```

#### For Production (Railway/Heroku):
Add these as environment variables in your hosting platform:
- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`

### Step 4: Update Redirect URIs for Production
When deploying to production, update the redirect URI in:
1. Google Cloud Console OAuth settings
2. The `client_config` in app.py (line ~25)

Replace:
```python
"redirect_uris": ["http://localhost:5000/auth/google/callback"]
```

With:
```python
"redirect_uris": [
    "http://localhost:5000/auth/google/callback",
    "https://your-production-domain.com/auth/google/callback"
]
```

### Step 5: Test the Integration
1. Start your Flask app
2. Go to `/login` or `/register`
3. Click "Sign in with Google"
4. Complete the OAuth flow

## 🔒 Security Notes
- Never commit your Client ID and Secret to version control
- Use environment variables for sensitive data
- Set up proper OAuth scopes (we use: openid, email, profile)
- Validate the state parameter to prevent CSRF attacks

## 🚀 Features Added
- ✅ Google Sign-in on login page
- ✅ Google Sign-up on register page  
- ✅ Automatic user creation from Google account
- ✅ Profile picture display on dashboard
- ✅ Email and name integration
- ✅ Secure token validation
- ✅ CSRF protection with state parameter
