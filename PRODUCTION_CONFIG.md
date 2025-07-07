# Production Environment Configuration

## Required Environment Variables

### Essential Configuration
```bash
# Secret key for Flask sessions (REQUIRED)
SECRET_KEY=your-super-secret-key-here-change-this

# Port configuration (usually set automatically by platforms)
PORT=5000

# Application environment
FLASK_ENV=production
```

### Google OAuth (Optional)
```bash
# Google OAuth Client ID
GOOGLE_CLIENT_ID=your-google-client-id.googleusercontent.com

# Google OAuth Client Secret
GOOGLE_CLIENT_SECRET=your-google-client-secret

# Base URL for OAuth redirects (set this to your deployed domain)
BASE_URL=https://your-app-domain.com
```

### Platform-Specific Variables
These are usually set automatically by the deployment platform:

```bash
# Railway
RAILWAY_ENVIRONMENT=production

# Render
RENDER=true

# Heroku
DYNO=web.1
```

## Setting Environment Variables

### Railway
1. Open your Railway dashboard
2. Click on your project
3. Go to Variables tab
4. Add each variable:
   - SECRET_KEY: Generate a secure random string
   - BASE_URL: Your Railway app URL (e.g., https://net-armor-production.up.railway.app)
   - GOOGLE_CLIENT_ID: (if using Google OAuth)
   - GOOGLE_CLIENT_SECRET: (if using Google OAuth)

### Render
1. Open your Render dashboard
2. Go to your service
3. Click on Environment
4. Add environment variables:
   - SECRET_KEY: Generate a secure random string
   - BASE_URL: Your Render app URL (e.g., https://net-armor.onrender.com)
   - GOOGLE_CLIENT_ID: (if using Google OAuth)
   - GOOGLE_CLIENT_SECRET: (if using Google OAuth)

### Generating a Secret Key
Run this in Python to generate a secure secret key:
```python
import secrets
print(secrets.token_urlsafe(32))
```

## Google OAuth Setup (Optional)

If you want to enable Google OAuth login:

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Enable Google+ API
4. Create OAuth 2.0 credentials
5. Add your domain to authorized redirect URIs:
   - Local: `http://localhost:5000/auth/google/callback`
   - Production: `https://your-domain.com/auth/google/callback`
6. Set the GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables

## Troubleshooting

### Common Issues:

1. **Internal Server Error**
   - Check if SECRET_KEY is set
   - Verify BASE_URL is correct
   - Check deployment logs

2. **Google OAuth Not Working**
   - Verify GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are set
   - Check if your domain is added to Google OAuth settings
   - Ensure BASE_URL matches your deployed domain

3. **File System Issues**
   - The app now uses in-memory storage for production
   - Data will be lost on restart (this is expected for demo purposes)
   - For persistent data, consider using a database

### Checking Logs
- Railway: `railway logs`
- Render: Check the logs in your Render dashboard
- Local: Check the console output

### Testing Deployment
Visit these endpoints to test your deployment:
- `/` - Homepage
- `/login` - Login page
- `/register` - Registration page
- `/api/health` - Health check (returns app status)
